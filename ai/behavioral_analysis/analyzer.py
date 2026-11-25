"""Deterministic behavioural analysis of a single text.

Produces *observed evidence* (exact quotes with character offsets) for every tactic detected.
Nothing here is inferred: a hit is only created when the pattern literally matches the text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ai.behavioral_analysis.tactics import TACTICS, is_negated
from ai.behavioral_analysis.url_analyzer import brand_data, extract_urls
from ai.text import normalize, snippet, normalize_pattern

MAX_HITS_PER_TACTIC = 3


@dataclass
class Hit:
    tactic: str
    quote: str          # exact substring of the original text
    start: int
    end: int
    context: str
    message_index: int | None = None

    def to_dict(self) -> dict:
        d = {"tactic": self.tactic, "quote": self.quote, "span": [self.start, self.end], "context": self.context}
        if self.message_index is not None:
            d["message_index"] = self.message_index
        return d


@dataclass
class TextAnalysis:
    text: str
    hits: list[Hit] = field(default_factory=list)
    negated: list[Hit] = field(default_factory=list)  # protective phrasing, e.g. "never share your OTP"
    urls: list[str] = field(default_factory=list)
    brands_mentioned: list[str] = field(default_factory=list)

    @property
    def tactics(self) -> set[str]:
        return {h.tactic for h in self.hits}


_BRAND_RES: list[tuple[str, re.Pattern]] | None = None


def _brand_res() -> list[tuple[str, re.Pattern]]:
    global _BRAND_RES
    if _BRAND_RES is None:
        out = []
        for brand, v in brand_data()["brands"].items():
            alts = "|".join(re.escape(normalize_pattern(n.lower())) for n in v["names"])
            out.append((brand, re.compile(rf"(?<![\w])({alts})(?![\w])", re.IGNORECASE)))
        _BRAND_RES = out
    return _BRAND_RES


def analyze_text(text: str, message_index: int | None = None) -> TextAnalysis:
    nt = normalize(text)
    res = TextAnalysis(text=text)
    for tactic in TACTICS.values():
        count = 0
        for rx in tactic.compiled:
            for m in rx.finditer(nt.norm):
                s, e = nt.span_to_original(m.start(), m.end())
                hit = Hit(tactic.key, text[s:e], s, e, snippet(text, s, e), message_index)
                if tactic.negatable and is_negated(nt.norm, m.start()):
                    res.negated.append(hit)
                    continue
                if any(h.tactic == tactic.key and not (e <= h.start or s >= h.end) for h in res.hits):
                    continue  # overlapping duplicate
                res.hits.append(hit)
                count += 1
                if count >= MAX_HITS_PER_TACTIC:
                    break
            if count >= MAX_HITS_PER_TACTIC:
                break
    res.urls = extract_urls(text)
    for brand, rx in _brand_res():
        if rx.search(nt.norm):
            res.brands_mentioned.append(brand)
    res.hits.sort(key=lambda h: h.start)
    return res


# --------------------------------------------------------------------------------------------
# Known fraud patterns (used for *inferences*, never presented as facts)
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class FraudPattern:
    key: str
    name_en: str
    name_ar: str
    all_of: tuple[str, ...]
    any_of: tuple[str, ...] = ()
    hint_words: tuple[str, ...] = ()
    likely_next: str = "transfer_money"  # predicted next harmful step if not already requested


FRAUD_PATTERNS: tuple[FraudPattern, ...] = (
    FraudPattern("bank_impersonation", "Bank / authority impersonation", "انتحال صفة بنك أو جهة رسمية",
                 ("authority_impersonation",), ("credential_request", "personal_data_request", "threat_fear", "payment_instruction"),
                 likely_next="share_credentials"),
    FraudPattern("family_emergency", "Family emergency ('Hi Mum') scam", "احتيال الطوارئ العائلية ('مرحبا ماما')",
                 ("emotional_emergency",), ("payment_instruction", "channel_shift", "identity_claim", "secrecy"),
                 likely_next="transfer_money"),
    FraudPattern("prize_lottery", "Prize / refund lure", "طُعم الجوائز أو الاسترداد",
                 ("reward_lure",), ("payment_instruction", "personal_data_request", "link_prompt", "credential_request"),
                 hint_words=("won", "prize", "congratulations", "winner", "lottery", "ربحت", "فزت", "جائزه", "مبروك"),
                 likely_next="share_personal_data"),
    FraudPattern("parcel_fee", "Fake delivery / customs fee", "رسوم توصيل أو جمارك وهمية",
                 ("payment_instruction",), ("authority_impersonation", "link_prompt", "urgency"),
                 hint_words=("parcel", "package", "shipment", "delivery", "customs", "courier", "شحنه", "طرد", "التوصيل", "الجمارك"),
                 likely_next="open_link"),
    FraudPattern("investment_crypto", "Investment / crypto fraud", "احتيال استثماري / عملات رقمية",
                 ("reward_lure",), ("payment_instruction",),
                 hint_words=("invest", "profit", "return", "crypto", "usdt", "bitcoin", "trading", "استثمار", "ارباح", "تداول"),
                 likely_next="transfer_money"),
    FraudPattern("job_task", "Task-based job scam", "احتيال الوظائف بالمهام",
                 ("job_task_scam",), ("payment_instruction", "channel_shift", "reward_lure"),
                 likely_next="transfer_money"),
    FraudPattern("tech_support", "Tech-support / remote-access scam", "احتيال الدعم الفني / التحكم عن بعد",
                 ("remote_access",), ("authority_impersonation", "threat_fear", "urgency"),
                 likely_next="install_remote_access"),
    FraudPattern("executive_impersonation", "Executive / business email compromise", "انتحال صفة مدير / اختراق البريد التجاري",
                 ("identity_claim", "payment_instruction"), ("urgency", "secrecy"),
                 hint_words=("ceo", "director", "invoice", "supplier", "المدير", "فاتوره", "المورد"),
                 likely_next="transfer_money"),
    FraudPattern("account_phishing", "Account-suspension phishing", "تصيّد بحجة إيقاف الحساب",
                 ("threat_fear",), ("link_prompt", "credential_request", "personal_data_request"),
                 likely_next="open_link"),
)


def match_patterns(tactics: set[str], text: str, has_url: bool) -> list[dict]:
    norm = normalize(text).norm
    out = []
    for p in FRAUD_PATTERNS:
        if not all(t in tactics for t in p.all_of):
            continue
        support = [t for t in p.any_of if t in tactics]
        hints = [w for w in p.hint_words if normalize_pattern(w) in norm]
        if p.any_of and not support and not hints:
            continue
        if p.hint_words and not hints and p.key in ("parcel_fee", "investment_crypto", "executive_impersonation"):
            continue
        strength = len(p.all_of) + len(support) + (1 if hints else 0) + (1 if has_url and p.likely_next == "open_link" else 0)
        out.append({"key": p.key, "name_en": p.name_en, "name_ar": p.name_ar, "strength": strength,
                    "supporting_tactics": list(p.all_of) + support, "likely_next": p.likely_next})
    out.sort(key=lambda d: -d["strength"])
    return out


def pattern_by_key(key: str) -> FraudPattern | None:
    return next((p for p in FRAUD_PATTERNS if p.key == key), None)
