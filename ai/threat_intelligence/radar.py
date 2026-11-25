"""Live Threat Radar detection logic (pure functions, unit-tested).

Two kinds of real, external input:
  * Certificate Transparency: every new HTTPS certificate is published in public CT logs within
    seconds. A newly certified domain that imitates a protected brand is often a phishing site being
    set up *before* any victim receives the link.
  * Public phishing feeds (OpenPhish community feed): URLs already confirmed as phishing by a third party.

Detection on CT data is deliberately strict (brand token in the *registered* name **and** a lure
word or risky TLD), because live certificate traffic is dominated by legitimate infrastructure.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ai.behavioral_analysis.url_analyzer import _LEET, _skeleton, analyze_url, brand_data, registrable_domain


def _brand_names() -> dict[str, list[str]]:
    out = {}
    for b, v in brand_data()["brands"].items():
        names = {n.replace(" ", "").lower() for n in v["names"] if n.isascii()}
        if len(b) >= 5:
            names.add(b)
        out[b] = sorted(n for n in names if len(n) >= 3)
    return out


def _same_length_typo(token: str, name: str) -> bool:
    """One substituted character (after leet folding), names of 6+ letters only."""
    if len(name) < 6 or len(token) != len(name) or token == name:
        return False
    return sum(a != b for a, b in zip(token.translate(_LEET), name)) == 1


def _embedded(name: str, tokens: list[str], lures: set[str]) -> bool:
    """Brand glued to other text ("netflixir", "paypalsecure"): accept only if the rest is short,
    numeric or a lure word — "forticloud" must not count as "icloud"."""
    for t in tokens:
        if name in t and t != name:
            rest = t.replace(name, "", 1)
            if len(rest) <= 2 or rest.isdigit() or rest in lures:
                return True
    return False


def classify_domain(host: str) -> dict | None:
    """Return a radar finding for a newly seen domain, or None if it does not look like brand abuse."""
    host = host.lower().strip(".")
    if not host or "." not in host:
        return None
    data = brand_data()
    reg = registrable_domain(host)
    official = {d for v in data["brands"].values() for d in v["domains"]}
    if reg in official or reg in data.get("legit_related", []) or any(host.endswith("." + d) or host == d for d in official):
        return None
    skel = _skeleton(host)
    reg_label = _skeleton(reg).split(".")[0]
    reg_tokens = [t for t in re.split(r"[-_]", reg_label) if t]
    sub = skel[: -len(reg)].strip(".") if skel.endswith(reg) else ""
    sub_tokens = [t for t in re.split(r"[.\-_]", sub) if t]
    lures = set(data.get("radar_lure_words", []))
    tld = host.rsplit(".", 1)[-1]
    risky_tld = tld in data["suspicious_tlds"]
    shared = reg in data.get("shared_hosting", [])

    brand, how = None, None
    for b, names in _brand_names().items():
        for n in names:
            if any(t != n and t.translate(_LEET) == n for t in reg_tokens):
                brand, how = b, "typosquat"
            elif any(t == n for t in reg_tokens) or (len(n) >= 6 and _embedded(n, reg_tokens, lures)):
                brand, how = b, "registered_name"
            elif any(_same_length_typo(t, n) for t in reg_tokens):
                brand, how = b, "lookalike_word"
            elif any(t == n for t in sub_tokens) and (shared or risky_tld or any(t in lures for t in reg_tokens)):
                brand, how = b, "subdomain"
            if brand:
                break
        if brand:
            break
    if not brand:
        return None
    all_tokens = set(reg_tokens) | set(sub_tokens) | {reg_label}
    lure_hits = sorted({w for w in lures if any(w == t or (len(w) >= 5 and w in t) for t in all_tokens)})
    idn = "xn--" in host
    if how in ("registered_name", "lookalike_word") and not (lure_hits or risky_tld or idn):
        # brand-owned infrastructure ("<brand>-cdn.com") or ordinary words one letter away from a brand
        # ("takara" vs "tamara", "career" vs "careem") — found as false alarms on real CT data
        return None
    if how == "lookalike_word":
        how = "typosquat"
    rep = analyze_url("https://" + host)
    reasons = []
    if how == "typosquat":
        reasons.append({"en": f"Misspelling of '{brand}'", "ar": f"تهجئة محرّفة لـ '{brand}'"})
    elif how == "subdomain":
        reasons.append({"en": f"Puts '{brand}' in a sub-domain of an unrelated site", "ar": f"يضع '{brand}' في نطاق فرعي لموقع غير مرتبط"})
    else:
        reasons.append({"en": f"Registered name contains '{brand}' but it is not an official {brand} domain",
                        "ar": f"الاسم المسجّل يحتوي '{brand}' لكنه ليس نطاقاً رسمياً لـ {brand}"})
    if lure_hits:
        reasons.append({"en": "Lure words: " + ", ".join(lure_hits), "ar": "كلمات استدراج: " + "، ".join(lure_hits)})
    if risky_tld:
        reasons.append({"en": f"Frequently abused ending .{tld}", "ar": f"امتداد يُساء استخدامه كثيراً ‎.{tld}"})
    if idn:
        reasons.append({"en": "Uses look-alike international characters", "ar": "يستخدم حروفاً دولية متشابهة"})
    score = min(100, 45 + 15 * bool(lure_hits) + 10 * risky_tld + 20 * idn + 10 * (how == "typosquat") + rep.score // 4)
    return {"host": host, "registrable_domain": reg, "brand": brand, "method": how, "score": score,
            "level": "critical" if score >= 70 else "high", "reasons": reasons}


def brand_in_url(url: str) -> str | None:
    """Brand named anywhere in a confirmed phishing URL (host or path tokens), e.g. '/netflix-clone'."""
    toks = set(re.split(r"[^a-z0-9]+", url.lower()))
    for b, names in _brand_names().items():
        if any(n in toks for n in names if len(n) >= 4):
            return b
    return None


def parse_feed_line(line: str) -> dict | None:
    """OpenPhish feed: one confirmed phishing URL per line."""
    line = line.strip()
    if not line or line.startswith("#") or not re.match(r"^https?://", line, re.I):
        return None
    host = (urlsplit(line).hostname or "").lower()
    if not host or "." not in host:
        return None
    brand = None
    c = classify_domain(host)
    if c:
        brand = c["brand"]
    else:
        rep = analyze_url(line)
        brand = rep.impersonated_brand or brand_in_url(line)
    return {"url": line[:500], "host": host, "registrable_domain": registrable_domain(host), "brand": brand}
