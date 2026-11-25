"""Deepfake / AI-media scan for the Check tab. Files are analysed in memory and never stored."""
from __future__ import annotations

import hashlib
from collections import OrderedDict

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from ai.deepfake import provenance, vision_review
from backend.app.security import rate_limit

router = APIRouter(prefix="/api")
_REVIEWS: "OrderedDict[str, dict]" = OrderedDict()   # same file → same paid AI review (hash only, never the file)
MAX_MB = 25
# extension -> (kind, mime, magic check)
MEDIA = {
    "jpg": ("image", "image/jpeg", lambda b: b[:3] == b"\xff\xd8\xff"), "jpeg": ("image", "image/jpeg", lambda b: b[:3] == b"\xff\xd8\xff"),
    "png": ("image", "image/png", lambda b: b[:8] == b"\x89PNG\r\n\x1a\n"),
    "webp": ("image", "image/webp", lambda b: b[:4] == b"RIFF" and b[8:12] == b"WEBP"),
    "mp3": ("audio", "audio/mpeg", lambda b: b[:3] == b"ID3" or b[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")),
    "wav": ("audio", "audio/wav", lambda b: b[:4] == b"RIFF" and b[8:12] == b"WAVE"),
    "m4a": ("audio", "audio/mp4", lambda b: b[4:8] == b"ftyp"),
    "ogg": ("audio", "audio/ogg", lambda b: b[:4] == b"OggS"), "opus": ("audio", "audio/ogg", lambda b: b[:4] == b"OggS"),
    "mp4": ("video", "video/mp4", lambda b: b[4:8] == b"ftyp"), "mov": ("video", "video/quicktime", lambda b: b[4:8] in (b"ftyp", b"moov", b"wide", b"mdat")),
}


@router.get("/deepfake/status")
def status():
    import os
    return {"provenance": "available", "ai_review": "available" if os.getenv("OPENAI_API_KEY", "").strip() else "not_configured",
            "max_mb": MAX_MB, "types": sorted(MEDIA)}


@router.post("/deepfake/scan", dependencies=[rate_limit("deepfake", 0.5)])
async def scan(request: Request, file: UploadFile = File(...)):
    name = (file.filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext not in MEDIA:
        raise HTTPException(415, "Unsupported file type")
    data = await file.read(MAX_MB * 1024 * 1024 + 1)
    if len(data) > MAX_MB * 1024 * 1024:
        raise HTTPException(413, f"File larger than {MAX_MB} MB")
    kind, mime, ok = MEDIA[ext]
    if not data or not ok(data):
        raise HTTPException(415, "File content does not match its type")
    prov = provenance(data, kind)
    if kind == "image" and len(data) <= 20 * 1024 * 1024:
        digest = hashlib.sha256(data).hexdigest()
        review = _REVIEWS.get(digest) or vision_review(data, mime)
        if review.get("status") == "used":
            _REVIEWS[digest] = review
            _REVIEWS.move_to_end(digest)
            while len(_REVIEWS) > 256:
                _REVIEWS.popitem(last=False)
    else:
        review = {"status": "not_applicable" if kind != "image" else "too_large"}
    if review.get("status") == "not_configured" and kind != "image":
        review = {"status": "not_applicable"}
    level = ("high" if prov["verdict"] in ("declared_ai", "ai_markers") or review.get("assessment") == "likely_ai"
             else "medium" if review.get("assessment") == "possibly_ai" else "unknown")
    return {"kind": kind, "bytes": len(data), "level": level, "provenance": prov, "ai_review": review, "stored": False,
            "limits_en": "No tool can prove a file is real. Treat any unexpected call, voice note or video asking for money or codes as a scam until you verify it through a number you already know.",
            "limits_ar": "لا توجد أداة تستطيع إثبات أن الملف حقيقي. تعامل مع أي مكالمة أو رسالة صوتية أو فيديو غير متوقع يطلب مالاً أو رموزاً على أنه احتيال حتى تتحقق منه عبر رقم تعرفه مسبقاً."}
