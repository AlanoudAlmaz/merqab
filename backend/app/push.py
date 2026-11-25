"""Web Push (VAPID) for MIRGAB devices.

* Keys: MIRQAB_VAPID_PRIVATE_KEY (PEM) if set, otherwise generated once and kept in <data>/vapid_private.pem (0600).
* Devices register a real browser PushSubscription. The server keeps the subscription plus a SHA-256 hash of a
  random device token; only the holder of that token can read, change, test or delete its own registration.
* Subscription endpoints must belong to a known push service (Apple, Google, Mozilla, Microsoft) — the server never
  posts to arbitrary URLs (no SSRF).
* What is pushed is real: a test alert the user asked for, community alerts that passed two-person review, newly
  confirmed phishing campaigns from the live radar (throttled), and clearly labelled DEMO broadcasts from an admin
  to devices that opted in.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from backend.app import db as dbm

log = logging.getLogger("mirqab.push")

PUSH_HOSTS = ("web.push.apple.com", "fcm.googleapis.com", "updates.push.services.mozilla.com",
              "push.services.mozilla.com", "notify.windows.com", "android.googleapis.com")
TOPICS = ("alerts", "campaigns", "uae", "tips", "demo")
UAE_BRANDS = {"emiratespost", "emiratesnbd", "adcb", "fab", "etisalat", "du", "uaepass", "dubaipolice", "salik",
              "dewa", "adnoc", "mashreq", "rakbank", "careem", "tabby", "aramex",
              "tamm", "icp", "moi", "adpolice", "rta", "adib", "dib", "emiratesislamic", "etihad"}
CAMPAIGN_MIN_CONFIRMED = 3
CAMPAIGN_DEVICE_GAP = 6 * 3600       # at most one campaign push per device every 6 h

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, endpoint TEXT NOT NULL UNIQUE, p256dh TEXT NOT NULL, auth TEXT NOT NULL,
  lang TEXT NOT NULL DEFAULT 'en', topics TEXT NOT NULL DEFAULT '[]', demo_consent INTEGER NOT NULL DEFAULT 0,
  platform TEXT, created_at TEXT NOT NULL, last_seen TEXT NOT NULL, last_campaign_push REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_inbox (
  id INTEGER PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts TEXT NOT NULL,
  kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, url TEXT, delivered INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_inbox_device ON device_inbox(device_id, id);
CREATE TABLE IF NOT EXISTS push_seen (key TEXT PRIMARY KEY, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS push_log (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT, title TEXT, sent INTEGER, failed INTEGER, removed INTEGER
);
"""


def init_schema(conn) -> None:
    conn.executescript(SCHEMA)


def endpoint_ok(url: str) -> bool:
    try:
        u = urlparse(url)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    return u.scheme == "https" and len(url) <= 1024 and any(host == h or host.endswith("." + h) for h in PUSH_HOSTS)


def hash_token(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def new_device_token() -> str:
    return secrets.token_urlsafe(32)


class Vapid:
    def __init__(self, data_dir: Path):
        from py_vapid import Vapid02 as VapidImpl
        pem = os.getenv("MIRQAB_VAPID_PRIVATE_KEY", "").strip()
        if pem:
            self.v = VapidImpl.from_pem(pem.replace("\\n", "\n").encode())
        else:
            f = data_dir / "vapid_private.pem"
            if f.exists():
                self.v = VapidImpl.from_file(str(f))
            else:
                self.v = VapidImpl()
                self.v.generate_keys()
                data_dir.mkdir(parents=True, exist_ok=True)
                self.v.save_key(str(f))
                os.chmod(f, 0o600)
        from cryptography.hazmat.primitives import serialization
        raw = self.v.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.public_key = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.subject = os.getenv("MIRQAB_VAPID_SUBJECT", "").strip() or "mailto:security@mirqab.app"


class PushService:
    def __init__(self, db_path: Path, data_dir: Path, enabled: bool = True):
        self.db_path = db_path
        self.vapid = None
        self.error = None
        try:
            self.vapid = Vapid(data_dir)
        except Exception as e:   # missing library or broken key → push reported unavailable, app keeps working
            self.error = type(e).__name__
            log.warning("Web Push unavailable: %s", self.error)
        self.enabled = enabled and self.vapid is not None
        self.stop = threading.Event()
        self.sender = None          # injectable for tests: fn(subscription_info, payload_json) -> int status

    # ------------------------------------------------------------------ sending
    def _send_one(self, dev: dict, payload: dict) -> int:
        info = {"endpoint": dev["endpoint"], "keys": {"p256dh": dev["p256dh"], "auth": dev["auth"]}}
        data = json.dumps(payload, ensure_ascii=False)
        if self.sender:
            return self.sender(info, data)
        from pywebpush import WebPushException, webpush
        aud = "{u.scheme}://{u.netloc}".format(u=urlparse(dev["endpoint"]))
        try:
            r = webpush(info, data, vapid_private_key=self.vapid.v,
                        vapid_claims={"sub": self.vapid.subject, "aud": aud, "exp": int(time.time()) + 12 * 3600},
                        ttl=6 * 3600, headers={"Urgency": "high"}, timeout=10)
            return getattr(r, "status_code", 201)
        except WebPushException as e:
            return getattr(e.response, "status_code", 0) or 0
        except Exception as e:
            log.warning("push send failed: %s", type(e).__name__)
            return 0

    def send(self, conn, devices: list[dict], kind: str, build, actor: str | None = None) -> dict:
        """build(device) -> {"title","body","url"} in the device's language. Gone subscriptions are removed."""
        if not self.enabled:
            return {"sent": 0, "failed": len(devices), "removed": 0, "available": False}
        sent = failed = removed = 0
        title_for_log = None
        for d in devices:
            msg = build(d)
            title_for_log = title_for_log or msg["title"]
            payload = {"title": msg["title"][:120], "body": msg["body"][:300], "url": msg.get("url") or "/#/shield",
                       "kind": kind, "tag": msg.get("tag") or f"mirqab-{kind}", "ts": dbm.now()}
            status = self._send_one(d, payload)
            ok = 200 <= status < 300
            if status in (404, 410):          # subscription expired or revoked by the user
                conn.execute("DELETE FROM devices WHERE id=?", (d["id"],))
                removed += 1
                continue
            conn.execute("INSERT INTO device_inbox (device_id, ts, kind, title, body, url, delivered) VALUES (?,?,?,?,?,?,?)",
                         (d["id"], payload["ts"], kind, payload["title"], payload["body"], payload["url"], int(ok)))
            conn.execute("DELETE FROM device_inbox WHERE device_id=? AND id NOT IN (SELECT id FROM device_inbox WHERE device_id=? ORDER BY id DESC LIMIT 40)",
                         (d["id"], d["id"]))
            sent += ok
            failed += not ok
        conn.execute("INSERT INTO push_log (ts, kind, actor, title, sent, failed, removed) VALUES (?,?,?,?,?,?,?)",
                     (dbm.now(), kind, actor, title_for_log, sent, failed, removed))
        conn.commit()
        return {"sent": sent, "failed": failed, "removed": removed, "available": True}

    @staticmethod
    def devices(conn, topic: str | None = None, demo_only: bool = False) -> list[dict]:
        out = []
        for r in conn.execute("SELECT * FROM devices"):
            d = dict(r)
            d["topics"] = json.loads(d["topics"] or "[]")
            if demo_only and not d["demo_consent"]:
                continue
            if topic and topic not in d["topics"]:
                continue
            out.append(d)
        return out

    # ------------------------------------------------------------------ automatic, real-data notifications
    def notify_alert_published(self, alert: dict) -> None:
        """A community alert passed two-person review → push to devices that follow verified alerts."""
        def run():
            conn = dbm.connect(self.db_path)
            try:
                devs = self.devices(conn, "alerts")
                ar = lambda d: d["lang"] == "ar"
                self.send(conn, devs, "alert", lambda d: {
                    "title": ("تحذير موثّق: " if ar(d) else "Verified warning: ") + (alert["title_ar"] if ar(d) else alert["title_en"]),
                    "body": alert["summary_ar"] if ar(d) else alert["summary_en"], "url": "/#/community", "tag": f"alert-{alert['id']}"})
            finally:
                conn.close()
        if self.enabled:
            threading.Thread(target=run, daemon=True, name="push-alert").start()

    def campaign_scan(self, conn, intel: dict, first_run: bool = False) -> int:
        """Push newly confirmed phishing campaigns (≥3 sites listed by threat feeds). Existing ones at start-up are
        only marked as seen, so a restart never floods phones."""
        pushed = 0
        for c in intel.get("campaigns", []):
            if c.get("status") != "confirmed" or c.get("confirmed", 0) < CAMPAIGN_MIN_CONFIRMED or not c.get("brand"):
                continue
            key = f"campaign:{c['brand']}"
            if conn.execute("SELECT 1 FROM push_seen WHERE key=?", (key,)).fetchone():
                continue
            conn.execute("INSERT INTO push_seen (key, ts) VALUES (?,?)", (key, dbm.now()))
            if first_run:
                continue
            uae = c["brand"] in UAE_BRANDS
            cutoff = time.time() - CAMPAIGN_DEVICE_GAP
            devs = [d for d in self.devices(conn) if ("campaigns" in d["topics"] or (uae and "uae" in d["topics"]))
                    and d["last_campaign_push"] < cutoff]
            if not devs:
                continue
            brand = c["brand"]
            res = self.send(conn, devs, "campaign", lambda d: {
                "title": (f"حملة تصيّد نشطة تنتحل {brand}" if d["lang"] == "ar" else f"Active phishing campaign impersonating {brand}"),
                "body": (f"{c['confirmed']} موقعاً مؤكداً في قوائم التهديد. لا تفتح روابط تدّعي أنها من {brand}؛ ادخل عبر التطبيق الرسمي."
                         if d["lang"] == "ar" else
                         f"{c['confirmed']} sites confirmed by threat feeds. Don't open links claiming to be {brand}; use the official app."),
                "url": f"/#/radar/{c['id']}", "tag": f"campaign-{brand}"})
            now_ts = time.time()
            for d in devs:
                conn.execute("UPDATE devices SET last_campaign_push=? WHERE id=?", (now_ts, d["id"]))
            pushed += res["sent"]
        conn.commit()
        return pushed

    def start(self, intel_fn) -> None:
        if not self.enabled:
            return

        def loop():
            first = True
            while not self.stop.wait(30 if first else 600):
                conn = dbm.connect(self.db_path)
                try:
                    self.campaign_scan(conn, intel_fn(conn), first_run=first)
                    first = False
                except Exception as e:
                    log.warning("campaign push scan failed: %s", type(e).__name__)
                finally:
                    conn.close()
        threading.Thread(target=loop, daemon=True, name="push-campaigns").start()

    def shutdown(self) -> None:
        self.stop.set()
