"""Extraction of observable indicators (IOCs) from evidence text.

Values are normalised so the same phone number / domain / account written differently in two
pieces of evidence still correlates. Card numbers are never stored in full.
"""
from __future__ import annotations

import re

from ai.behavioral_analysis.url_analyzer import analyze_url, extract_urls
from ai.text import normalize

# Phone numbers must look like phone numbers (international "+"/"00" or a local leading 0) and must not be
# part of a URL, ID or timestamp — e.g. "/users/36707123404" or "entry_index": 1234567890 are not phones.
PHONE_RE = re.compile(r"(?<![\w+/=.:#%&?-])(?:\+|00|0)\d[\d\s\-().]{7,17}\d(?![\w/])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
AMOUNT_RE = re.compile(r"(?i)(?:(aed|usd|sar|dhs?|eur|gbp|egp|kwd|qar|omr|bhd|\$|€|£|درهم|ريال|دولار)\s?(\d[\d,]*(?:\.\d+)?)|(\d[\d,]*(?:\.\d+)?)\s?(aed|usd|sar|dhs?|eur|gbp|درهم|ريال|دولار))")

_CUR = {"dh": "AED", "dhs": "AED", "درهم": "AED", "ريال": "SAR", "دولار": "USD", "$": "USD", "€": "EUR", "£": "GBP"}


def _luhn(num: str) -> bool:
    total, alt = 0, False
    for d in reversed(num):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def extract_indicators(text: str) -> list[dict]:
    """Return [{type, value (normalised), display}] — de-duplicated."""
    text = normalize(text).original  # keep original; normalise digits below
    digits_text = "".join(str(int(c)) if c.isdigit() and not c.isascii() else c for c in text)
    out: dict[tuple, dict] = {}

    def add(t, value, display):
        out.setdefault((t, value), {"type": t, "value": value, "display": display})

    for u in extract_urls(digits_text):
        rep = analyze_url(u)
        if rep.host:
            add("domain", rep.registrable_domain, rep.registrable_domain.replace(".", "[.]"))
            add("url", rep.url.lower().rstrip("/"), rep.defanged)
    emails = set()
    for m in EMAIL_RE.finditer(digits_text):
        e = m.group(0).lower()
        emails.add(e)
        add("email", e, e.replace("@", "[@]"))
    for m in IBAN_RE.finditer(digits_text.upper()):
        v = m.group(0).replace(" ", "")
        if 15 <= len(v) <= 34:
            add("bank_account", v, v[:4] + "…" + v[-4:])
    for rx, name in ((ETH_RE, "wallet"), (BTC_RE, "wallet"), (TRON_RE, "wallet")):
        for m in rx.finditer(digits_text):
            add(name, m.group(0), m.group(0)[:6] + "…" + m.group(0)[-4:])
    card_spans = []
    for m in CARD_RE.finditer(digits_text):
        d = re.sub(r"\D", "", m.group(0))
        if 13 <= len(d) <= 19 and _luhn(d):
            card_spans.append(m.span())
            add("card", "card:" + d[-4:], "•••• " + d[-4:])  # never keep full PAN
    for m in PHONE_RE.finditer(digits_text):
        if any(s <= m.start() < e for s, e in card_spans):
            continue
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        if len(d) < 9 or len(d) > 15 or re.fullmatch(r"(19|20)\d{6,}", d):
            continue  # too short / looks like a date
        if raw.startswith("00"):
            d = d[2:]
        if d.startswith("0") and len(d) == 10:  # local UAE-style 05XXXXXXXX -> 9715XXXXXXXX
            d = "971" + d[1:]
        add("phone", "+" + d, "+" + d[:5] + "…" + d[-2:])
    for m in AMOUNT_RE.finditer(digits_text):
        cur = (m.group(1) or m.group(4) or "").lower()
        num = (m.group(2) or m.group(3) or "").replace(",", "")
        cur = _CUR.get(cur, cur.upper())
        add("amount", f"{cur} {num}", f"{cur} {num}")
    return list(out.values())


# Indicator types that link evidence strongly (shared infrastructure / money destination)
STRONG_TYPES = {"domain", "url", "email", "phone", "bank_account", "wallet", "card"}
