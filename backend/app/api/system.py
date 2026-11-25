"""Authentication, capabilities, users and audit endpoints."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ai import RULES_VERSION
from backend.app import audit
from backend.app.db import now, rows
from backend.app.evidence import ocr_available
from backend.app.security import (current_user, get_db, hash_password, issue_token, password_policy, rate_limit, require,
                                  verify_password)

router = APIRouter(prefix="/api", tags=["system"])
_DUMMY_HASH = hash_password("timing-equaliser-0")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: Literal["investigator", "reviewer", "admin"]
    display_name: str | None = Field(default=None, max_length=80)


@router.get("/health")
def health():
    return {"status": "ok", "time": now()}


@router.get("/capabilities")
def capabilities(request: Request):
    llm = request.app.state.llm
    s = request.app.state.settings
    return {
        "rules_version": RULES_VERSION,
        "ai_language_model": {"status": "configured" if llm.available() else "not_configured", "provider": llm.name,
                              "model": getattr(llm, "model", None)},
        "ocr": {"status": "available" if (s.ocr_enabled and ocr_available()) else "unavailable", "languages": ["ara", "eng"]},
        # links are checked against the OpenPhish phishing list (and radar look-alikes) that the Live Radar keeps fresh
        "url_reputation": {"status": "available", "source": "OpenPhish community feed via Live Radar"}
        if request.app.state.radar.enabled else {"status": "not_configured", "note": "Enable the Live Radar to check links against OpenPhish."},
        "live_radar": {"status": "available" if request.app.state.radar.enabled else "unavailable",
                       "sources": ["Certificate Transparency logs", "OpenPhish community feed"]},
        "deepfake_media_analysis": {"status": "integration_ready", "note": "Requires an external audio/video forensics model."},
        "live_monitoring": {"status": "not_implemented", "note": "MERQAB analyses content you submit; it does not monitor calls, chats or transactions."},
        "store_analysis_text": s.store_analysis_text,
        "max_upload_mb": s.max_upload_mb,
    }


@router.post("/auth/login", dependencies=[rate_limit("login", 0.34)])
def login(body: LoginIn, request: Request, db=Depends(get_db)):
    guard, uname = request.app.state.login_guard, body.username.strip()
    if guard.locked(uname):
        verify_password(body.password, _DUMMY_HASH)   # same cost either way: no timing oracle
        audit.record(db, uname[:64] or "?", "auth.locked", None, {})
        raise HTTPException(429, "Too many failed attempts for this account — try again in 15 minutes.")
    r = db.execute("SELECT * FROM users WHERE username=? AND active=1", (uname,)).fetchone()
    ok = verify_password(body.password, r["pw_hash"] if r else _DUMMY_HASH)
    if not r or not ok:
        guard.failed(uname)
        audit.record(db, uname[:64] or "?", "auth.failed", None, {})
        raise HTTPException(401, "Invalid username or password")
    guard.reset(uname)
    s = request.app.state.settings
    audit.record(db, r["username"], "auth.login", None, {})
    return {"token": issue_token(s.secret_key, r["id"], r["role"], s.token_ttl_min), "expires_in": s.token_ttl_min * 60,
            "user": {"username": r["username"], "role": r["role"], "display_name": r["display_name"]}}


@router.get("/auth/me")
def me(request: Request, db=Depends(get_db)):
    u = current_user(request, db)
    if not u:
        raise HTTPException(401, "Not signed in")
    return {k: u[k] for k in ("username", "role", "display_name")}


@router.post("/users", status_code=201)
def create_user(body: UserIn, user=require("admin"), db=Depends(get_db)):
    if (msg := password_policy(body.password)):
        raise HTTPException(422, msg)
    if db.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
        raise HTTPException(409, "Username already exists")
    db.execute("INSERT INTO users (username, pw_hash, role, display_name, created_at) VALUES (?,?,?,?,?)",
               (body.username, hash_password(body.password), body.role, body.display_name, now()))
    db.commit()
    audit.record(db, user["username"], "user.create", f"user/{body.username}", {"role": body.role})
    return {"ok": True}


@router.get("/audit")
def audit_log(limit: int = 200, user=require("admin"), db=Depends(get_db)):
    return rows(db.execute("SELECT id, ts, actor, action, target, details, hash FROM audit_log ORDER BY id DESC LIMIT ?",
                           (max(1, min(limit, 1000)),)))


@router.get("/audit/verify")
def audit_verify(user=require("admin"), db=Depends(get_db)):
    return audit.verify_chain(db)
