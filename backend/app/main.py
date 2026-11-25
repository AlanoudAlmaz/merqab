"""MERQAB application factory.

Run:  uvicorn --factory backend.app.main:create_app --port 8000
"""
from __future__ import annotations

import logging
import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from ai.llm.provider import LLMProvider, provider_from_env
from backend.app import db as dbm
from backend.app.api import cases, community, prevention, radar as radar_api, system, deepfake, devices, accuracy, evidence_link
from backend.app.push import PushService, init_schema as init_push_schema
from backend.app.radar import RadarService
from backend.app.config import ROOT, Settings
from backend.app.services import radar_intel
from backend.app.security import LoginGuard, RateLimiter, RequestGuard, SecurityHeaders

mimetypes.add_type("application/manifest+json", ".webmanifest")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mirqab")
FRONTEND = ROOT / "frontend"


def _bootstrap_admin(settings: Settings) -> None:
    """First start on a fresh server: create one admin so the demo broadcast can be used.
    Password from MIRQAB_ADMIN_PASSWORD (set it yourself in the host's dashboard), otherwise a random one is
    generated and printed ONCE to the server log. Nothing happens if an admin already exists."""
    import os
    import secrets as _s
    from backend.app.security import hash_password, password_policy
    with dbm.connect(settings.db_path) as c:
        if c.execute("SELECT 1 FROM users WHERE role='admin' AND active=1").fetchone():
            return
        if not os.getenv("MIRQAB_BOOTSTRAP_ADMIN", "").strip().lower() in ("1", "true", "yes"):
            return
        user = os.getenv("MIRQAB_ADMIN_USERNAME", "admin").strip() or "admin"
        pw = os.getenv("MIRQAB_ADMIN_PASSWORD", "").strip()
        generated = not pw or password_policy(pw) is not None
        if generated:
            pw = _s.token_urlsafe(12) + "9a"
        c.execute("INSERT OR IGNORE INTO users (username, pw_hash, role, display_name, created_at) VALUES (?,?,?,?,?)",
                  (user, hash_password(pw), "admin", "MERQAB admin", dbm.now()))
        c.commit()
        if generated:
            log.warning("Created admin '%s' with a one-time generated password: %s  (change it by setting MIRQAB_ADMIN_PASSWORD)", user, pw)
        else:
            log.warning("Created admin '%s' from MIRQAB_ADMIN_PASSWORD.", user)


def create_app(settings: Settings | None = None, llm: LLMProvider | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    dbm.init(settings.db_path)

    @asynccontextmanager
    async def lifespan(a: FastAPI):
        a.state.radar.start()
        a.state.push.start(radar_intel)
        yield
        a.state.radar.shutdown()
        a.state.push.shutdown()

    app = FastAPI(title="MERQAB API", version="1.1.0", lifespan=lifespan,
                  description="AI-assisted cybercrime prevention, investigation and community protection.",
                  docs_url="/api/docs" if settings.api_docs else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if settings.api_docs else None)
    app.state.settings = settings
    app.state.connect = lambda: dbm.connect(settings.db_path)
    app.state.llm = llm or provider_from_env()
    app.state.limiter = RateLimiter()
    app.state.login_guard = LoginGuard()
    app.state.radar = RadarService(settings.db_path, settings.radar_enabled)
    with dbm.connect(settings.db_path) as c:
        init_push_schema(c)
    _bootstrap_admin(settings)
    app.state.push = PushService(settings.db_path, settings.db_path.parent, enabled=settings.push_enabled)

    log.info("LLM provider: %s (%s)", app.state.llm.name, "configured" if app.state.llm.available() else "rules only")

    app.add_middleware(SecurityHeaders)
    # largest legitimate body: a deepfake scan (25 MB) plus multipart overhead
    app.add_middleware(RequestGuard, allowed_hosts=settings.allowed_hosts, max_body=max(26, settings.max_upload_mb + 1) * 1024 * 1024,
                       limiter=app.state.limiter, per_min=settings.rate_limit_per_min * 10)
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST", "PATCH"],
                           allow_headers=["Authorization", "Content-Type"])

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Do not echo submitted content back in error messages
        errs = [{"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": "Invalid input", "errors": errs}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        log.exception("Unhandled error")
        return JSONResponse({"detail": "Internal error"}, status_code=500)

    for r in (system.router, prevention.router, cases.router, community.router, radar_api.router, deepfake.router, devices.router, accuracy.router, evidence_link.router):
        app.include_router(r)

    if FRONTEND.is_dir():
        app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
    return app

