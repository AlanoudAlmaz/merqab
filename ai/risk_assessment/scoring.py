"""Explainable risk scoring.

score = Σ tactic weights + Σ contextual-inconsistency bonuses + link risk + community match,
capped at 100. Every point added is traceable to an indicator listed in the result.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ai.behavioral_analysis.tactics import TACTICS

LEVELS = ("low", "medium", "high", "critical")


def level_for(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"


@dataclass
class Combination:
    key: str
    bonus: int
    en: str
    ar: str
    tactics: tuple[str, ...]


@dataclass
class RiskResult:
    score: int
    level: str
    confidence: str
    breakdown: list[dict] = field(default_factory=list)
    combinations: list[Combination] = field(default_factory=list)
    uncertainty: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "level": self.level, "confidence": self.confidence,
                "breakdown": self.breakdown,
                "inconsistencies": [c.__dict__ for c in self.combinations],
                "uncertainty": self.uncertainty}


def _combinations(tactics: set[str], brand_mismatch: list[dict]) -> list[Combination]:
    out: list[Combination] = []
    ext = tactics & {"credential_request", "payment_instruction", "remote_access", "personal_data_request"}
    if "authority_impersonation" in tactics and "credential_request" in tactics:
        out.append(Combination("authority_asks_code", 20,
                               "Claims to be an institution but asks for a code or password — real institutions never do this.",
                               "يدّعي أنه جهة رسمية لكنه يطلب رمزاً أو كلمة مرور — الجهات الحقيقية لا تفعل ذلك أبداً.",
                               ("authority_impersonation", "credential_request")))
    if "authority_impersonation" in tactics and "payment_instruction" in tactics:
        out.append(Combination("authority_asks_payment", 12,
                               "An 'official' party asking for payment through a message is inconsistent with how institutions operate.",
                               "طلب الدفع عبر رسالة من جهة 'رسمية' لا يتوافق مع طريقة عمل المؤسسات.",
                               ("authority_impersonation", "payment_instruction")))
    if tactics & {"urgency", "threat_fear"} and ext:
        out.append(Combination("pressure_to_act", 10,
                               "Pressure is combined with a request to act — a core manipulation pattern.",
                               "الضغط مقترن بطلب تنفيذ إجراء — نمط تلاعب أساسي.",
                               tuple(sorted((tactics & {"urgency", "threat_fear"}) | ext))))
    if "emotional_emergency" in tactics and "payment_instruction" in tactics:
        out.append(Combination("emergency_money", 12,
                               "An emotional emergency is used to justify a money request.",
                               "تُستخدم حالة طارئة عاطفية لتبرير طلب المال.",
                               ("emotional_emergency", "payment_instruction")))
    if "secrecy" in tactics and tactics & {"payment_instruction", "credential_request", "remote_access"}:
        out.append(Combination("secret_request", 10,
                               "You are asked to keep a financial or security request secret.",
                               "يُطلب منك إبقاء طلب مالي أو أمني سراً.",
                               ("secrecy",)))
    if "identity_claim" in tactics and "payment_instruction" in tactics:
        out.append(Combination("unverified_identity_payment", 10,
                               "Money is requested on the basis of an identity that has not been verified.",
                               "يُطلب المال بناءً على هوية لم يتم التحقق منها.",
                               ("identity_claim", "payment_instruction")))
    if tactics & {"job_task_scam", "reward_lure"} and "payment_instruction" in tactics:
        out.append(Combination("upfront_payment", 12,
                               "You are asked to pay first in order to receive money, a prize or a job — legitimate offers do not work this way.",
                               "يُطلب منك الدفع أولاً لتحصل على مال أو جائزة أو وظيفة — العروض المشروعة لا تعمل بهذه الطريقة.",
                               tuple(sorted(tactics & {"job_task_scam", "reward_lure", "payment_instruction"}))))
    if "analyzer_evasion" in tactics and len(tactics) > 1:
        out.append(Combination("evasion_with_lure", 15,
                               "The text tries to influence automated checks while also making a request — legitimate senders have no reason to do this.",
                               "النص يحاول التأثير على الفحص الآلي ويقدّم طلباً في الوقت نفسه — لا سبب لدى المرسل الحقيقي لفعل ذلك.",
                               ("analyzer_evasion",)))
    for bm in brand_mismatch:
        out.append(Combination("brand_link_mismatch", 18,
                               f"The message mentions '{bm['brand']}' but the link goes to '{bm['domain']}', which is not an official {bm['brand']} domain.",
                               f"الرسالة تذكر '{bm['brand']}' لكن الرابط يذهب إلى '{bm['domain']}' وهو ليس نطاقاً رسمياً لـ {bm['brand']}.",
                               ()))
    return out


def score(tactics: set[str], url_reports: list[dict], brand_mismatch: list[dict], community_matches: list[dict],
          text_length: int, protective_phrases: int, llm_extra: list[str] | None = None,
          llm_status: str = "not_configured", pattern: dict | None = None, radar: list[dict] | None = None) -> RiskResult:
    breakdown: list[dict] = []
    total = 0
    for t in sorted(tactics, key=lambda k: -TACTICS[k].weight):
        total += TACTICS[t].weight
        breakdown.append({"source": "rule", "key": t, "points": TACTICS[t].weight})
    for t in llm_extra or []:
        pts = TACTICS[t].weight // 2  # grounded AI-only findings count half
        total += pts
        breakdown.append({"source": "ai_inference", "key": t, "points": pts})
    combos = _combinations(tactics | set(llm_extra or []), brand_mismatch)
    for c in combos:
        total += c.bonus
        breakdown.append({"source": "inconsistency", "key": c.key, "points": c.bonus})
    if pattern and len(pattern["supporting_tactics"]) >= 2:
        total += 15
        breakdown.append({"source": "pattern", "key": pattern["key"], "points": 15})
    if url_reports:
        worst = max(r["score"] for r in url_reports)
        pts = round(worst * 0.6) if (tactics or llm_extra) else worst
        if pts:
            total += pts
            breakdown.append({"source": "link", "key": "url_risk", "points": pts})
    if community_matches:
        total += 15
        breakdown.append({"source": "community", "key": "validated_alert_match", "points": 15})
    for m in radar or []:
        # confirmed feed listing > suspected new look-alike > predicted from campaign naming DNA
        # a site that has dropped off the feed was malicious, but is no longer confirmed as live
        pts = (40 if m.get("active", True) else 25) if m.get("confirmed") else 10 if m.get("predicted") else 20
        total += pts
        breakdown.append({"source": "radar_predicted" if m.get("predicted") else "radar", "key": m["host"], "points": pts})
    total = min(100, total)
    lvl = level_for(total)

    n_signals = len(tactics) + len(llm_extra or []) + (1 if any(r["score"] >= 20 for r in url_reports) else 0) + len(community_matches) + len(radar or [])
    unc: list[dict] = []
    if text_length < 25 and not url_reports:
        conf = "low"
        unc.append({"en": "Very little text was provided, so the assessment is limited.",
                    "ar": "النص المقدم قصير جداً، لذا التقييم محدود."})
    elif n_signals == 0:
        conf = "medium"
        unc.append({"en": "No known scam indicators were found. This does not prove the message is safe — new scams may not match known patterns.",
                    "ar": "لم يتم العثور على مؤشرات احتيال معروفة. هذا لا يثبت أن الرسالة آمنة — قد لا تطابق الأساليب الجديدة الأنماط المعروفة."})
    elif n_signals >= 3 or total >= 70:
        conf = "high"
    elif n_signals == 2:
        conf = "medium"
    else:
        conf = "low" if total < 45 else "medium"
        unc.append({"en": "Only one indicator was found; context you know (who sent it, whether you expected it) matters.",
                    "ar": "تم العثور على مؤشر واحد فقط؛ السياق الذي تعرفه (من أرسلها، وهل كنت تتوقعها) مهم."})
    if any(not m.get("confirmed") for m in radar or []):
        unc.append({"en": "A link matches a look-alike site MIRGAB detected on its own (not yet confirmed by a phishing list) — treat it as suspicious, not as proven.",
                    "ar": "رابط يطابق موقعاً مقلّداً رصده مرقاب بنفسه (غير مؤكَّد في قوائم التصيّد بعد) — تعامل معه كمشبوه لا كمثبَت."})
    if protective_phrases and lvl in ("low", "medium"):
        unc.append({"en": "The text contains protective wording (e.g. 'never share this code'), which is typical of genuine notifications.",
                    "ar": "يحتوي النص على عبارات حماية (مثل 'لا تشارك هذا الرمز')، وهي معتادة في الإشعارات الحقيقية."})
    if llm_status in ("not_configured", "failed", "disabled"):
        unc.append({"en": "Result produced by the deterministic rule engine only (AI language model not used).",
                    "ar": "النتيجة صادرة عن محرك القواعد فقط (لم يُستخدم نموذج الذكاء الاصطناعي اللغوي)."})
    return RiskResult(total, lvl, conf, breakdown, combos, unc)
