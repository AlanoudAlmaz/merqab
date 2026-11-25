"""Parse .eml evidence: headers, body text and header-level phishing indicators."""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from ai.behavioral_analysis.url_analyzer import brand_data, registrable_domain


def _domain(addr: str) -> str:
    return registrable_domain(addr.rsplit("@", 1)[-1].lower()) if "@" in addr else ""


def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    hdr = {k: str(msg.get(k, "")) for k in ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID")}
    auth = str(msg.get("Authentication-Results", ""))
    body_parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except (LookupError, ValueError):
                content = part.get_payload(decode=True).decode("utf-8", "replace")
            if ctype == "text/html":
                content = re.sub(r"(?is)<(script|style).*?</\1>", " ", content)
                content = re.sub(r'(?i)href="([^"]+)"', r" \1 ", content)
                content = re.sub(r"<[^>]+>", " ", content)
            body_parts.append(content)
    attachments = [p.get_filename() for p in msg.walk() if p.get_content_disposition() == "attachment"]
    body = re.sub(r"[ \t]+", " ", "\n".join(body_parts)).strip()

    from_name, from_addr = (getaddresses([hdr["From"]]) or [("", "")])[0]
    _, reply_addr = (getaddresses([hdr["Reply-To"]]) or [("", "")])[0]
    signals = []
    fd, rd = _domain(from_addr), _domain(reply_addr)
    if reply_addr and fd and rd and fd != rd:
        signals.append({"key": "reply_to_mismatch", "en": f"Replies go to a different domain ({rd}) than the sender ({fd}).",
                        "ar": f"الردود تذهب إلى نطاق مختلف ({rd}) عن نطاق المرسل ({fd})."})
    brands = brand_data()["brands"]
    for b, v in brands.items():
        if any(n.lower() in from_name.lower() for n in v["names"] if len(n) >= 4) and fd and fd not in v["domains"]:
            signals.append({"key": "display_name_spoof", "en": f"Sender name mentions '{b}' but the address is from {fd}.",
                            "ar": f"اسم المرسل يذكر '{b}' لكن العنوان من {fd}."})
            break
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none)", auth, re.I):
            signals.append({"key": f"{mech}_fail", "en": f"{mech.upper()} check did not pass.", "ar": f"فحص {mech.upper()} لم ينجح."})
    for a in attachments:
        if a and re.search(r"\.(exe|scr|js|vbs|bat|cmd|iso|lnk|hta|apk|html?)$", a, re.I):
            signals.append({"key": "risky_attachment", "en": f"Risky attachment type: {a}", "ar": f"مرفق من نوع خطِر: {a}"})
    event_time = None
    try:
        if hdr["Date"]:
            dt = parsedate_to_datetime(hdr["Date"])
            event_time = dt.strftime("%Y-%m-%dT%H:%M")  # local time as stated in the header
    except (TypeError, ValueError):
        pass
    text = f"Subject: {hdr['Subject']}\nFrom: {hdr['From']}\n\n{body}"
    return {"text": text, "headers": hdr, "attachments": attachments, "header_signals": signals,
            "event_time": event_time, "event_time_label": "E-mail Date header"}
