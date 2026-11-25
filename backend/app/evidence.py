"""Evidence storage and processing.

Originals are written once to content-addressed, read-only files and never modified. All text
extraction (OCR, PDF, e-mail parsing) works on in-memory copies. Integrity is verified by
recomputing SHA-256 over the stored bytes.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import stat
from functools import lru_cache
from pathlib import Path

from ai.investigation.email_parser import parse_eml

log = logging.getLogger("mirqab.evidence")
MAX_OCR_PIXELS = 40_000_000
MAX_PDF_PAGES = 30


def store(evidence_dir: Path, data: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    d = evidence_dir / digest[:2]
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{digest}.bin"
    if not p.exists():
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IRGRP)
        tmp.replace(p)
    return digest, str(p.relative_to(evidence_dir))


def verify(evidence_dir: Path, rel_path: str, expected: str) -> dict:
    p = (evidence_dir / rel_path).resolve()
    if not str(p).startswith(str(evidence_dir.resolve())) or not p.is_file():
        return {"intact": False, "reason": "missing"}
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    return {"intact": actual == expected, "expected_sha256": expected, "actual_sha256": actual}


@lru_cache(maxsize=1)
def ocr_available() -> bool:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def ocr_image(data: bytes) -> tuple[str | None, str]:
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_OCR_PIXELS
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
    except Exception:
        return None, "Image could not be decoded."
    if not ocr_available():
        return None, "OCR engine not installed — add a text transcription of the screenshot."
    import pytesseract
    try:
        g = img.convert("L")
        if g.width < 1200:
            g = g.resize((g.width * 2, g.height * 2))
        text = pytesseract.image_to_string(g, lang="ara+eng", timeout=25)
    except Exception as exc:
        log.warning("OCR failed: %s", type(exc).__name__)
        return None, "OCR failed on this image."
    text = re.sub(r"[ \t]+", " ", text).strip()
    return (text or None), ("Text extracted by OCR — may contain recognition errors." if text else "No readable text found.")


def image_metadata(data: bytes) -> dict:
    from PIL import ExifTags, Image
    Image.MAX_IMAGE_PIXELS = MAX_OCR_PIXELS
    meta: dict = {}
    try:
        img = Image.open(io.BytesIO(data))
        meta.update({"width": img.width, "height": img.height, "format": img.format})
        exif = img.getexif()
        tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()} if exif else {}
        sub = exif.get_ifd(0x8769) if exif else {}
        dto = sub.get(36867) or tags.get("DateTime")
        if dto:
            t = str(dto).strip()
            if re.match(r"\d{4}:\d{2}:\d{2} \d{2}:\d{2}", t):
                meta["event_time"] = t[:10].replace(":", "-") + "T" + t[11:16]
                meta["event_time_label"] = "Image EXIF date"
        if tags.get("Software"):
            meta["software"] = str(tags["Software"])[:80]
        meta["exif_present"] = bool(tags)
    except Exception:
        meta["decode_error"] = True
    return meta


def pdf_text(data: bytes) -> tuple[str | None, str, dict]:
    meta = {"active_content": bool(re.search(rb"/(JavaScript|JS|Launch|EmbeddedFile|OpenAction|AA)\b", data))}
    try:
        from pypdf import PdfReader
    except ImportError:
        return None, "PDF text extraction library not installed.", meta
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return None, "Encrypted PDF — stored but not processed.", meta
        meta["pages"] = len(reader.pages)
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:MAX_PDF_PAGES]).strip()
        info = reader.metadata or {}
        cd = str(info.get("/CreationDate", ""))
        m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})", cd)
        if m:
            meta["event_time"] = f"{m[1]}-{m[2]}-{m[3]}T{m[4]}:{m[5]}"
            meta["event_time_label"] = "PDF creation date (metadata)"
    except Exception:
        return None, "PDF could not be parsed — stored but not processed.", meta
    note = "Text extracted from PDF."
    if meta["active_content"]:
        note += " Warning: the PDF contains active content (scripts/actions); it is never opened or rendered."
    return (text or None), note, meta


def extract(ext: str, data: bytes, ocr_enabled: bool) -> dict:
    """Return {text, note, metadata, header_signals}. Never raises for malformed content."""
    if ext == "txt":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-16", "replace")
        return {"text": text.lstrip("﻿"), "note": "Plain text.", "metadata": {}, "header_signals": []}
    if ext == "eml":
        try:
            e = parse_eml(data)
        except Exception:
            return {"text": None, "note": "E-mail could not be parsed.", "metadata": {}, "header_signals": []}
        return {"text": e["text"], "note": "E-mail parsed (headers and body).", "header_signals": e["header_signals"],
                "metadata": {"headers": e["headers"], "attachments": e["attachments"], "event_time": e["event_time"],
                             "event_time_label": e["event_time_label"]}}
    if ext == "pdf":
        text, note, meta = pdf_text(data)
        return {"text": text, "note": note, "metadata": meta, "header_signals": []}
    meta = image_metadata(data)
    if ocr_enabled:
        text, note = ocr_image(data)
    else:
        text, note = None, "OCR disabled by configuration."
    return {"text": text, "note": note, "metadata": meta, "header_signals": []}
