"""Configuration from environment variables (see .env.example). No secrets live in code."""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("mirqab")
ROOT = Path(__file__).resolve().parents[2]


def _public_url_default() -> None:
    if not os.getenv("MIRQAB_PUBLIC_URL") and os.getenv("RENDER_EXTERNAL_URL"):
        os.environ["MIRQAB_PUBLIC_URL"] = os.environ["RENDER_EXTERNAL_URL"]


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no extra dependency). Existing environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    secret_key: str
    db_path: Path
    evidence_dir: Path
    max_upload_mb: int = 10
    token_ttl_min: int = 480
    cors_origins: list[str] = field(default_factory=list)
    rate_limit_per_min: int = 30
    store_analysis_text: bool = False
    ocr_enabled: bool = True
    demo_mode: bool = False
    radar_enabled: bool = False
    ephemeral_secret: bool = False
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "::1", "testserver", ".trycloudflare.com"])
    api_docs: bool = False
    push_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(ROOT / ".env")
        _public_url_default()
        secret = os.getenv("MIRQAB_SECRET_KEY", "").strip()
        ephemeral = False
        if len(secret) < 32:
            secret = secrets.token_urlsafe(48)
            ephemeral = True
            log.warning("MIRQAB_SECRET_KEY missing or too short — using an ephemeral key; sessions end on restart.")
        data = Path(os.getenv("MIRQAB_DATA_DIR", ROOT / "data"))
        return cls(
            secret_key=secret,
            db_path=Path(os.getenv("MIRQAB_DB_PATH", data / "mirqab.db")),
            evidence_dir=Path(os.getenv("MIRQAB_EVIDENCE_DIR", data / "evidence")),
            max_upload_mb=int(os.getenv("MIRQAB_MAX_UPLOAD_MB", "10")),
            token_ttl_min=int(os.getenv("MIRQAB_TOKEN_TTL_MIN", "480")),
            cors_origins=[o.strip() for o in os.getenv("MIRQAB_CORS_ORIGINS", "").split(",") if o.strip()],
            rate_limit_per_min=int(os.getenv("MIRQAB_RATE_LIMIT_PER_MIN", "30")),
            store_analysis_text=_bool("MIRQAB_STORE_ANALYSIS_TEXT", False),
            ocr_enabled=_bool("MIRQAB_OCR_ENABLED", True),
            demo_mode=_bool("MIRQAB_DEMO_MODE", False),
            radar_enabled=_bool("MIRQAB_RADAR_ENABLED", False),
            ephemeral_secret=ephemeral,
            # Render sets RENDER_EXTERNAL_HOSTNAME / RENDER_EXTERNAL_URL automatically
            allowed_hosts=["127.0.0.1", "localhost", "::1", ".trycloudflare.com"] + [h.strip() for h in (os.getenv("MIRQAB_ALLOWED_HOSTS", "") + "," + os.getenv("RENDER_EXTERNAL_HOSTNAME", "")).split(",") if h.strip()],
            api_docs=_bool("MIRQAB_API_DOCS", False),
            push_enabled=_bool("MIRQAB_PUSH_ENABLED", True),
        )
