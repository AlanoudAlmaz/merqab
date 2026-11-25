"""Authentication, authorisation, rate limiting, upload validation and HTTP hardening."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

ROLES = {"investigator": 1, "reviewer": 2, "admin": 3}
PBKDF2_ITER = 260_000


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return algo == "pbkdf2_sha256" and hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def password_policy(pw: str) -> str | None:
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        return "Password must contain letters and digits."
    return None


# ------------------------------------------------------------------ tokens (HMAC-signed, stateless)
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_token(secret: str, user_id: int, role: str, ttl_min: int) -> str:
    payload = _b64(json.dumps({"uid": user_id, "role": role, "exp": int(time.time()) + ttl_min * 60,
                               "jti": secrets.token_hex(6)}).encode())
    sig = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def read_token(secret: str, token: str) -> dict | None:
    try:
        payload, sig = token.split(".")
        expected = _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload))
        return data if data.get("exp", 0) > time.time() else None
    except (ValueError, json.JSONDecodeError):
        return None


def get_db(request: Request):
    conn = request.app.state.connect()
    try:
        yield conn
    finally:
        conn.close()


def current_user(request: Request, db) -> dict | None:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    data = read_token(request.app.state.settings.secret_key, auth[7:].strip())
    if not data:
        return None
    r = db.execute("SELECT id, username, role, display_name, active FROM users WHERE id=?",
                                     (data["uid"],)).fetchone()
    if not r or not r["active"] or r["role"] != data["role"]:
        return None
    return dict(r)


def require(role: str):
    def dep(request: Request, db=Depends(get_db)) -> dict:
        user = current_user(request, db)
        if not user:
            raise HTTPException(401, "Authentication required")
        if ROLES[user["role"]] < ROLES[role]:
            raise HTTPException(403, "Insufficient role")
        return user
    return Depends(dep)


# ------------------------------------------------------------------ rate limiting (in-memory, per client)
class RateLimiter:
    MAX_KEYS = 20_000   # memory bound: stale buckets are swept, never kept forever

    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
        self._swept = time.monotonic()

    def _sweep(self, t: float, window: int) -> None:
        if len(self.hits) > self.MAX_KEYS or t - self._swept > 300:
            for k in [k for k, q in self.hits.items() if not q or q[-1] < t - max(window, 900)]:
                del self.hits[k]
            self._swept = t

    def check(self, key: str, limit: int, window: int = 60) -> None:
        t = time.monotonic()
        with self.lock:
            self._sweep(t, window)
            q = self.hits[key]
            while q and q[0] < t - window:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(429, "Too many requests — please wait a minute.")
            q.append(t)


class LoginGuard:
    """Per-account lockout on top of per-IP throttling: 5 failures in 15 min lock that username for 15 min."""
    FAILS, WINDOW = 5, 900

    def __init__(self):
        self.fails: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def _q(self, user: str) -> deque:
        q = self.fails[user.lower()[:64]]
        t = time.monotonic()
        while q and q[0] < t - self.WINDOW:
            q.popleft()
        return q

    def locked(self, user: str) -> bool:
        with self.lock:
            return len(self._q(user)) >= self.FAILS

    def failed(self, user: str) -> None:
        with self.lock:
            if len(self.fails) > 20_000:
                self.fails.clear()
            self._q(user).append(time.monotonic())

    def reset(self, user: str) -> None:
        with self.lock:
            self.fails.pop(user.lower()[:64], None)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, factor: float = 1.0):
    def dep(request: Request):
        limit = max(1, int(request.app.state.settings.rate_limit_per_min * factor))
        request.app.state.limiter.check(f"{bucket}:{client_ip(request)}", limit)
    return Depends(dep)


# ------------------------------------------------------------------ upload validation
ALLOWED = {
    "png": ("image/png", lambda b: b.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg": ("image/jpeg", lambda b: b.startswith(b"\xff\xd8\xff")),
    "jpeg": ("image/jpeg", lambda b: b.startswith(b"\xff\xd8\xff")),
    "webp": ("image/webp", lambda b: b[:4] == b"RIFF" and b[8:12] == b"WEBP"),
    "pdf": ("application/pdf", lambda b: b.startswith(b"%PDF-")),
    "txt": ("text/plain", None),
    "eml": ("message/rfc822", None),
}
_EXEC_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"#!", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")


class UploadRejected(ValueError):
    pass


def safe_filename(name: str) -> str:
    base = re.sub(r"[^\w.\-؀-ۿ ]", "_", (name or "upload").replace("\\", "/").split("/")[-1]).strip(" .")
    return (base or "upload")[:120]


def validate_upload(filename: str, data: bytes, max_bytes: int) -> tuple[str, str]:
    """Return (extension, mime) or raise UploadRejected. Content is checked, not just the name."""
    if not data:
        raise UploadRejected("Empty file.")
    if len(data) > max_bytes:
        raise UploadRejected(f"File exceeds {max_bytes // (1024 * 1024)} MB limit.")
    name = safe_filename(filename).lower()
    parts = name.split(".")
    if len(parts) < 2:
        raise UploadRejected("File type not recognised.")
    ext = parts[-1]
    if ext not in ALLOWED:
        raise UploadRejected("Unsupported file type. Allowed: PNG, JPG, WEBP, PDF, TXT, EML.")
    if any(p in ("exe", "scr", "bat", "cmd", "js", "vbs", "apk", "msi", "sh", "ps1", "jar", "html", "htm", "svg") for p in parts[1:-1]):
        raise UploadRejected("Double extensions are not accepted.")
    if data.startswith(_EXEC_MAGIC) and ext not in ("txt", "eml"):
        raise UploadRejected("File content does not match its extension.")
    mime, check = ALLOWED[ext]
    if check and not check(data[:16]):
        raise UploadRejected("File content does not match its extension.")
    if ext in ("txt", "eml"):
        if b"\x00" in data[:8192] or data.startswith(_EXEC_MAGIC[:2]):
            raise UploadRejected("Text file contains binary content.")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                data.decode("utf-16")
            except UnicodeDecodeError:
                raise UploadRejected("Text file must be UTF-8 encoded.")
    return ext, mime


# ------------------------------------------------------------------ HTTP hardening
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
       "worker-src 'self'; manifest-src 'self'")


class RequestGuard:
    """Pure-ASGI guard that runs before any body is read.

    * Host allow-list — blocks DNS-rebinding (a hostile site re-pointing its domain at 127.0.0.1 to drive this API).
    * Body-size cap — rejects oversized requests from Content-Length up front and stops chunked bodies mid-stream,
      so huge uploads are never spooled to disk.
    * Global per-IP API throttle — a backstop for endpoints without their own limit.
    """

    def __init__(self, app, allowed_hosts: list[str], max_body: int, limiter: "RateLimiter", per_min: int):
        self.app, self.hosts, self.max_body, self.limiter, self.per_min = app, {h.lower() for h in allowed_hosts}, max_body, limiter, per_min

    async def _reply(self, send, status: int, msg: str):
        body = json.dumps({"detail": msg}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"x-content-type-options", b"nosniff"), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        host = headers.get("host", "").rsplit(":", 1)[0].strip("[]").lower() if not headers.get("host", "").startswith("[") \
            else headers["host"].split("]")[0].strip("[").lower()
        # the host's own health checker may use an internal Host header; /api/health exposes nothing
        allowed = host in self.hosts or any(h.startswith(".") and host.endswith(h) for h in self.hosts)
        if "*" not in self.hosts and not allowed and scope.get("path") != "/api/health":
            return await self._reply(send, 400, "Invalid host header")
        path = scope.get("path", "")
        if path.startswith("/api/"):
            ip = (scope.get("client") or ("unknown", 0))[0]
            try:
                self.limiter.check(f"api:{ip}", self.per_min)
            except HTTPException:
                return await self._reply(send, 429, "Too many requests — please wait a minute.")
        cl = headers.get("content-length")
        if cl is not None:
            if not cl.isdigit() or int(cl) > self.max_body:
                return await self._reply(send, 413, "Request too large")
            return await self.app(scope, receive, send)
        if scope.get("method") in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        seen, started = 0, False

        async def capped():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_body:
                    raise _BodyTooLarge()
            return msg

        async def tracked(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)
        try:
            return await self.app(scope, capped, tracked)
        except _BodyTooLarge:
            if not started:
                await self._reply(send, 413, "Request too large")


class _BodyTooLarge(Exception):
    pass


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # the app itself may ask (after explicit consent) for the mic (Call Guardian), camera (QR) and location; never iframes
        resp.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=(self), payment=(), usb=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        elif not request.url.path.startswith("/assets/fonts/"):
            # app shell: always revalidate (ETag) so upgrades are picked up immediately
            resp.headers["Cache-Control"] = "no-cache"
        return resp
