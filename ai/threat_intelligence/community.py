"""Privacy-preserving community threat intelligence.

* ``anonymize`` removes personal data from any text that could be published.
* ``build_alert_draft`` turns a case's validated tactics into a bilingual public warning draft.
* ``residual_pii`` is a publishing gate: alerts containing personal data cannot be published.
"""
from __future__ import annotations

import re

from ai.behavioral_analysis.analyzer import pattern_by_key
from ai.behavioral_analysis.tactics import TACTICS
from ai.investigation.indicators import CARD_RE, EMAIL_RE, ETH_RE, IBAN_RE, PHONE_RE, TRON_RE, BTC_RE

_NAME_AFTER = re.compile(r"(?i)\b(dear|hi|hello|mr\.?|mrs\.?|ms\.?|miss|sir|madam)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)")
_NAME_AFTER_AR = re.compile(r"(عزيزي|عزيزتي|السيد|السيده|السيدة|الاخ|الأخ|الاخت|الأخت|اخي|أخي)\s+([ء-ي]{2,}(?:\s[ء-ي]{2,})?)")
_ID_RE = re.compile(r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b")  # Emirates ID format


def anonymize(text: str) -> str:
    t = _ID_RE.sub("[ID]", text)
    t = EMAIL_RE.sub("[EMAIL]", t)
    t = IBAN_RE.sub("[ACCOUNT]", t)
    for rx in (ETH_RE, TRON_RE, BTC_RE):
        t = rx.sub("[WALLET]", t)
    t = CARD_RE.sub(lambda m: "[CARD]" if len(re.sub(r"\D", "", m.group(0))) >= 13 else m.group(0), t)
    t = PHONE_RE.sub(lambda m: "[PHONE]" if len(re.sub(r"\D", "", m.group(0))) >= 9 else m.group(0), t)
    t = re.sub(r"(?i)https?://[^\s]+", lambda m: _keep_host(m.group(0)), t)
    t = _NAME_AFTER.sub(lambda m: f"{m.group(1)} [NAME]", t)
    t = _NAME_AFTER_AR.sub(lambda m: f"{m.group(1)} [الاسم]", t)
    t = re.sub(r"\b\d{6,}\b", "[NUMBER]", t)  # codes, references
    return t


def _keep_host(url: str) -> str:
    m = re.match(r"(?i)(https?://[^/\s?#]+)", url)
    return (m.group(1) if m else url).replace("http", "hxxp", 1).replace(".", "[.]") + "/…"


def residual_pii(text: str) -> list[str]:
    found = []
    if EMAIL_RE.search(text):
        found.append("email")
    if IBAN_RE.search(text.upper()):
        found.append("bank_account")
    if any(len(re.sub(r"\D", "", m.group(0))) >= 9 for m in PHONE_RE.finditer(text)):
        found.append("phone")
    if _ID_RE.search(text):
        found.append("national_id")
    if _NAME_AFTER.search(text) and "[NAME]" not in text:
        found.append("possible_name")
    return found


_SIGN_TEXT = {k: (t.label_en, t.label_ar) for k, t in TACTICS.items()}


def build_alert_draft(pattern_key: str | None, tactics: list[str], domains: list[str]) -> dict:
    p = pattern_by_key(pattern_key) if pattern_key else None
    from ai.risk_assessment.intervention import ACTIONS
    name_en = p.name_en if p else "Suspicious messages"
    name_ar = p.name_ar if p else "رسائل مشبوهة"
    ordered = sorted(set(tactics), key=lambda k: -TACTICS[k].weight)[:5]
    signs = [{"en": TACTICS[k].label_en, "ar": TACTICS[k].label_ar, "why_en": TACTICS[k].explain_en,
              "why_ar": TACTICS[k].explain_ar} for k in ordered]
    action_keys = []
    for t, a in (("credential_request", "share_credentials"), ("payment_instruction", "transfer_money"),
                 ("remote_access", "install_remote_access"), ("personal_data_request", "share_personal_data"),
                 ("link_prompt", "open_link"), ("identity_claim", "verify_identity"), ("emotional_emergency", "verify_identity")):
        if t in tactics and a not in action_keys:
            action_keys.append(a)
    if p and p.likely_next not in action_keys:
        action_keys.append(p.likely_next)
    actions = [{"en": ACTIONS[k]["en"], "ar": ACTIONS[k]["ar"]} for k in action_keys[:4]]
    return {
        "pattern_key": pattern_key,
        "title_en": f"Warning: {name_en}",
        "title_ar": f"تحذير: {name_ar}",
        "summary_en": "Validated reports describe messages using the tactics below. If you receive something similar, stop and verify through official channels.",
        "summary_ar": "تصف بلاغات تم التحقق منها رسائل تستخدم الأساليب التالية. إذا وصلتك رسالة مشابهة، توقف وتحقق عبر القنوات الرسمية.",
        "signs": signs,
        "actions": actions,
        "indicators": [{"type": "domain", "value": d} for d in domains[:10]],
    }
