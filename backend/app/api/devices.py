"""Mobile Shield API: device registration, Web Push, Live Call Guardian analysis, QR access.

A device proves who it is with the random token it received at registration (header ``X-Device-Token``).
Only a SHA-256 hash of the token is stored, and every /devices/me call is scoped to that one device — no device
can read or change another's data.
"""
from __future__ import annotations

import io
import json
import os
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ai.behavioral_analysis.tactics import TACTICS
from ai.pipeline import analyze
from backend.app import audit
from backend.app.db import now
from backend.app.push import TOPICS, endpoint_ok, hash_token, new_device_token
from backend.app.security import get_db, rate_limit, require

router = APIRouter(prefix="/api", tags=["shield"])


class SubKeys(BaseModel):
    p256dh: str = Field(min_length=20, max_length=200)
    auth: str = Field(min_length=8, max_length=64)


class Subscription(BaseModel):
    endpoint: str = Field(min_length=10, max_length=1024)
    keys: SubKeys


class DeviceIn(BaseModel):
    subscription: Subscription
    lang: Literal["ar", "en", "ur", "hi", "tl", "zh", "fr", "es", "ru"] = "en"
    topics: list[Literal["alerts", "campaigns", "uae", "tips", "demo"]] = ["alerts", "campaigns"]
    demo_consent: bool = False
    platform: Literal["ios", "android", "desktop", "other"] = "other"


class PrefsIn(BaseModel):
    lang: Literal["ar", "en", "ur", "hi", "tl", "zh", "fr", "es", "ru"] | None = None
    topics: list[Literal["alerts", "campaigns", "uae", "tips", "demo"]] | None = None
    demo_consent: bool | None = None


class DemoIn(BaseModel):
    title_en: str = Field(min_length=3, max_length=80)
    title_ar: str = Field(min_length=3, max_length=80)
    body_en: str = Field(min_length=3, max_length=220)
    body_ar: str = Field(min_length=3, max_length=220)


class GuardIn(BaseModel):
    transcript: str = Field(min_length=1, max_length=8000)
    lang: Literal["ar", "en"] = "ar"


def _base(request: Request) -> str:
    """Public address as the visitor sees it (behind a tunnel or proxy the scheme comes from X-Forwarded-Proto)."""
    env = os.getenv("MIRQAB_PUBLIC_URL", "").strip().rstrip("/")
    if env:
        return env
    host = request.headers.get("host", request.url.netloc)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    if host.endswith(".trycloudflare.com"):
        proto = "https"
    return f"{proto}://{host}"


def _push(request: Request):
    return request.app.state.push


def _device(db, token: str | None) -> dict:
    if not token or len(token) > 100:
        raise HTTPException(401, "Device not registered")
    r = db.execute("SELECT * FROM devices WHERE token_hash=?", (hash_token(token),)).fetchone()
    if not r:
        raise HTTPException(401, "Device not registered")
    d = dict(r)
    d["topics"] = json.loads(d["topics"])
    return d


def _public(d: dict) -> dict:
    return {"id": d["id"][:8], "lang": d["lang"], "topics": d["topics"], "demo_consent": bool(d["demo_consent"]),
            "platform": d["platform"], "registered_at": d["created_at"], "last_seen": d["last_seen"]}


@router.get("/push/config")
def push_config(request: Request):
    p = _push(request)
    return {"available": p.enabled, "public_key": p.vapid.public_key if p.enabled else None, "topics": list(TOPICS)}


@router.post("/devices", status_code=201, dependencies=[rate_limit("device_register", 0.34)])
def register(body: DeviceIn, request: Request, db=Depends(get_db)):
    if not _push(request).enabled:
        raise HTTPException(503, "Push notifications are not available on this server")
    if not endpoint_ok(body.subscription.endpoint):
        raise HTTPException(422, "Unknown push service")
    tok = new_device_token()
    topics = sorted(set(body.topics) | ({"demo"} if body.demo_consent else set()) - ({"demo"} if not body.demo_consent else set()))
    old = db.execute("SELECT id FROM devices WHERE endpoint=?", (body.subscription.endpoint,)).fetchone()
    dev_id = old["id"] if old else os.urandom(12).hex()
    if old:   # same browser re-registering: rotate the token, keep the history
        db.execute("""UPDATE devices SET token_hash=?, p256dh=?, auth=?, lang=?, topics=?, demo_consent=?, platform=?, last_seen=?
                      WHERE id=?""", (hash_token(tok), body.subscription.keys.p256dh, body.subscription.keys.auth, body.lang,
                                      json.dumps(topics), int(body.demo_consent), body.platform, now(), dev_id))
    else:
        if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] >= 50_000:
            raise HTTPException(503, "Device capacity reached")
        db.execute("""INSERT INTO devices (id, token_hash, endpoint, p256dh, auth, lang, topics, demo_consent, platform, created_at, last_seen)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                   (dev_id, hash_token(tok), body.subscription.endpoint, body.subscription.keys.p256dh, body.subscription.keys.auth,
                    body.lang, json.dumps(topics), int(body.demo_consent), body.platform, now(), now()))
    db.commit()
    d = _device(db, tok)
    return {"device_token": tok, "device": _public(d)}


@router.get("/devices/me")
def me(db=Depends(get_db), x_device_token: str | None = Header(None)):
    d = _device(db, x_device_token)
    db.execute("UPDATE devices SET last_seen=? WHERE id=?", (now(), d["id"]))
    db.commit()
    inbox = [dict(r) for r in db.execute(
        "SELECT ts, kind, title, body, url, delivered FROM device_inbox WHERE device_id=? ORDER BY id DESC LIMIT 40", (d["id"],))]
    return {"device": _public(d), "inbox": inbox}


@router.patch("/devices/me")
def prefs(body: PrefsIn, db=Depends(get_db), x_device_token: str | None = Header(None)):
    d = _device(db, x_device_token)
    topics = set(body.topics if body.topics is not None else d["topics"])
    consent = d["demo_consent"] if body.demo_consent is None else int(body.demo_consent)
    topics = (topics | {"demo"}) if consent else (topics - {"demo"})
    db.execute("UPDATE devices SET lang=?, topics=?, demo_consent=?, last_seen=? WHERE id=?",
               (body.lang or d["lang"], json.dumps(sorted(topics)), consent, now(), d["id"]))
    db.commit()
    return {"device": _public(_device(db, x_device_token))}


@router.delete("/devices/me")
def disconnect(db=Depends(get_db), x_device_token: str | None = Header(None)):
    d = _device(db, x_device_token)
    db.execute("DELETE FROM device_inbox WHERE device_id=?", (d["id"],))
    db.execute("DELETE FROM devices WHERE id=?", (d["id"],))
    db.commit()
    return {"ok": True, "deleted": True}


@router.post("/devices/me/test", dependencies=[rate_limit("push_test", 0.2)])
def test_alert(request: Request, db=Depends(get_db), x_device_token: str | None = Header(None)):
    d = _device(db, x_device_token)
    ar = d["lang"] == "ar"
    res = _push(request).send(db, [d], "test", lambda _: {
        "title": "مرقاب: تنبيه أمني تجريبي" if ar else "MIRGAB: test security alert",
        "body": ("هذا تنبيه تجريبي طلبته من جهازك. الإشعارات تعمل — ستصلك تحذيرات حقيقية بنفس الطريقة."
                 if ar else "This is a test you requested. Notifications work — real warnings will arrive the same way."),
        "url": "/#/shield", "tag": "mirqab-test"})
    if not res["sent"]:
        raise HTTPException(502, "The push service did not accept the notification — open MIRGAB and re-enable protection.")
    return res


@router.post("/push/demo", dependencies=[rate_limit("push_demo", 0.2)])
def demo_broadcast(body: DemoIn, request: Request, user=require("admin"), db=Depends(get_db)):
    """Clearly labelled demonstration alert, only to devices whose owner opted in to demo alerts."""
    devs = _push(request).devices(db, demo_only=True)
    res = _push(request).send(db, devs, "demo", lambda d: {
        "title": ("[تجريبي] " + body.title_ar) if d["lang"] == "ar" else ("[DEMO] " + body.title_en),
        "body": (body.body_ar + " — تنبيه عرض توضيحي، ليس تهديداً حقيقياً.") if d["lang"] == "ar"
        else (body.body_en + " — Demonstration alert, not a real threat."),
        "url": "/#/shield", "tag": "mirqab-demo"}, actor=user["username"])
    audit.record(db, user["username"], "push.demo", None, {"devices": len(devs), "sent": res["sent"]})
    return {**res, "devices": len(devs)}


@router.get("/push/stats")
def push_stats(user=require("admin"), db=Depends(get_db)):
    total = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    demo = db.execute("SELECT COUNT(*) FROM devices WHERE demo_consent=1").fetchone()[0]
    log = [dict(r) for r in db.execute("SELECT ts, kind, actor, title, sent, failed, removed FROM push_log ORDER BY id DESC LIMIT 20")]
    return {"devices": total, "demo_consent": demo, "log": log}


# ---------------------------------------------------------------- Live Call Guardian
@router.post("/guardian/analyze", dependencies=[rate_limit("guardian", 2)])
def guardian(body: GuardIn, request: Request, db=Depends(get_db)):
    """Rolling analysis of a live transcript. Nothing is stored: no audio ever reaches the server, and the transcript
    is analysed in memory only."""
    text = body.transcript.strip()[-6000:]
    r = analyze("conversation", text, request.app.state.llm, None)
    quotes = {}
    for o in r.get("observed", []):
        quotes.setdefault(o["tactic"], o["quote"])
    tactics = [{"key": k, "en": TACTICS[k].label_en, "ar": TACTICS[k].label_ar, "quote": quotes.get(k)}
               for k in dict.fromkeys(b["key"] for b in r["risk"]["breakdown"] if b["source"] == "rule") if k in TACTICS]
    return {"risk": {k: r["risk"][k] for k in ("score", "level", "confidence")},
            "tactics": tactics,
            "patterns": [{"key": p["key"], "en": p["name_en"], "ar": p["name_ar"]} for p in r["patterns"][:2]],
            "intervention": r.get("intervention"), "llm": r["engine"]["llm"]["status"], "stored": False}


AUDIO_MAGIC = (b"ftyp", b"\x1aE\xdf\xa3", b"OggS", b"RIFF", b"ID3")


@router.post("/guardian/transcribe", dependencies=[rate_limit("guardian_stt", 1)])
async def transcribe(audio: UploadFile = File(...), lang: str = Form("ar")):
    """Speech-to-text for phones without a browser speech engine. The 5-second chunk is sent to OpenAI and dropped;
    nothing is written to disk."""
    import httpx
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key:
        raise HTTPException(503, "Server speech-to-text is not configured")
    data = await audio.read(2 * 1024 * 1024 + 1)
    if not data or len(data) > 2 * 1024 * 1024 or not any(m in data[:16] for m in AUDIO_MAGIC):
        raise HTTPException(415, "Unsupported audio")
    name = "chunk.webm" if data[:4] == b"\x1aE\xdf\xa3" else "chunk.ogg" if data[:4] == b"OggS" else "chunk.m4a"
    try:
        r = httpx.post("https://api.openai.com/v1/audio/transcriptions", timeout=30, headers={"authorization": f"Bearer {key}"},
                       data={"model": os.getenv("MIRQAB_OPENAI_STT_MODEL", "gpt-4o-mini-transcribe"), "language": "ar" if lang == "ar" else "en"},
                       files={"file": (name, data)})
    except httpx.HTTPError:
        raise HTTPException(502, "Speech service unreachable") from None
    if r.status_code != 200:
        raise HTTPException(502, f"Speech service error ({r.status_code})")
    return {"text": (r.json().get("text") or "")[:2000], "stored": False}


# ---------------------------------------------------------------- QR access
@router.get("/qr.svg")
def qr(request: Request, path: str = "/"):
    import qrcode
    import qrcode.image.svg
    base = _base(request)
    if not path.startswith("/") or len(path) > 100 or "//" in path:
        raise HTTPException(422, "Invalid path")
    img = qrcode.make(base + path, image_factory=qrcode.image.svg.SvgPathImage, box_size=12, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-cache"})


PREVIEW_MESSAGE = ("مرقاب | MIRGAB\n"
                   "عند إطلاق المنصة، امسح هذا الرمز لتثبيت مرقاب على شاشتك الرئيسية وتفعيل التنبيهات الفورية.\n"
                   "Once MIRGAB is live, scan this code to add it to your home screen and turn on instant alerts.")


@router.get("/qr/preview.svg")
def qr_preview():
    """Placeholder QR for a local (non-public) copy: scanning it shows a short message from MIRGAB, not a link.
    High error correction so the MIRGAB logo can sit in the centre."""
    import qrcode
    import qrcode.image.svg
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=12, border=2,
                      image_factory=qrcode.image.svg.SvgPathImage)
    q.add_data(PREVIEW_MESSAGE.encode("utf-8"))
    buf = io.BytesIO()
    q.make_image().save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})


@router.get("/shield/info")
def shield_info(request: Request):
    base = _base(request)
    return {"url": base, "https": base.startswith("https://"), "push": _push(request).enabled,
            "ai_layer": request.app.state.llm.available(), "stt_server": bool(os.getenv("OPENAI_API_KEY", "").strip())}
