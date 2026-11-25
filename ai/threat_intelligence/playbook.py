"""Family Shield content: how a scam unfolds, practice messages and audience advice.

Stages and tactics come straight from the behavioural engine's taxonomy (``TACTICS``), so the page
teaches exactly what MIRGAB detects. Practice messages are short training examples written for this
page (labelled as such in the UI); their highlighted phrases are produced by the real engine at request
time, never hand-annotated.
"""
from __future__ import annotations

from ai.behavioral_analysis.tactics import STAGE_ORDER, TACTICS

STAGES = {
    "contact": {
        "label_en": "First contact", "label_ar": "أول تواصل",
        "goal_en": "Reach you on a channel where they control the conversation.",
        "goal_ar": "الوصول إليك عبر قناة يتحكم فيها بالمحادثة.",
        "stop_en": "Unknown number or new account? Don't move the chat elsewhere. Contact the person or company on a number you already know.",
        "stop_ar": "رقم غريب أو حساب جديد؟ لا تنتقل لقناة أخرى، وتواصل مع الشخص أو الجهة على رقم تعرفه مسبقاً.",
    },
    "pretext": {
        "label_en": "The story", "label_ar": "القصة",
        "goal_en": "Borrow trust: a bank, a government entity, a prize, a job, or a relative in trouble.",
        "goal_ar": "استعارة الثقة: بنك، جهة حكومية، جائزة، وظيفة، أو قريب في ورطة.",
        "stop_en": "Check the story independently: the official app or website, or a call to the relative.",
        "stop_ar": "تحقق من القصة بنفسك: التطبيق أو الموقع الرسمي، أو اتصال بالقريب.",
    },
    "pressure": {
        "label_en": "Pressure", "label_ar": "الضغط",
        "goal_en": "Stop you from thinking or asking anyone: urgency, fear, secrecy.",
        "goal_ar": "منعك من التفكير أو سؤال أحد: استعجال، تخويف، سرّية.",
        "stop_en": "Pressure is the signal. Pause, and tell someone you trust — real organisations can wait.",
        "stop_ar": "الضغط هو العلامة. توقّف وأخبر شخصاً تثق به، فالجهات الحقيقية تنتظر.",
    },
    "extraction": {
        "label_en": "The ask", "label_ar": "الطلب",
        "goal_en": "The harmful action: a code, a transfer, remote access, your ID or a link to log in.",
        "goal_ar": "الفعل الضار: رمز، تحويل، وصول عن بُعد، هويتك، أو رابط لتسجيل الدخول.",
        "stop_en": "Never share a code, PIN or password, never install apps for a caller, and never pay to receive money.",
        "stop_ar": "لا تشارك أي رمز أو رقم سري، ولا تثبّت تطبيقاً لمتصل، ولا تدفع لتستلم مالاً.",
    },
}

# Which tactics matter most to each audience (advice ordering only; alerts and radar data are added live).
AUDIENCE_TACTICS = {
    "everyone": ["credential_request", "urgency", "link_prompt", "authority_impersonation"],
    "seniors": ["emotional_emergency", "credential_request", "authority_impersonation", "remote_access"],
    "students": ["job_task_scam", "reward_lure", "link_prompt", "personal_data_request"],
    "families": ["emotional_emergency", "secrecy", "channel_shift", "payment_instruction"],
    "businesses": ["authority_impersonation", "payment_instruction", "urgency", "remote_access"],
}

# Training examples written for this page. truth = what the example was written to be.
PRACTICE = [
    {"id": "p1", "lang": "ar", "truth": "scam",
     "text": "عزيزي العميل، تم إيقاف بطاقتك مؤقتاً. لإعادة التفعيل أرسل رمز التحقق الذي وصلك خلال 10 دقائق وإلا سيتم إلغاء الحساب."},
    {"id": "p2", "lang": "en", "truth": "scam",
     "text": "Hi mum, I dropped my phone and this is my new number. Can you send AED 2,000 now for a repair? Please don't tell dad yet."},
    {"id": "p3", "lang": "ar", "truth": "safe",
     "text": "تم خصم 32.50 درهم من بطاقتك المنتهية بـ 4421 لدى كريم. إذا لم تقم بهذه العملية اتصل بالرقم الموجود خلف بطاقتك."},
    {"id": "p4", "lang": "en", "truth": "scam",
     "text": "Congratulations! You have been selected for a part-time job: earn AED 900 a day by liking videos. Pay the AED 150 registration fee to start today."},
    {"id": "p5", "lang": "en", "truth": "safe",
     "text": "Your appointment at the clinic is confirmed for Sunday at 10:30. Reply 1 to confirm or call reception to reschedule."},
    {"id": "p6", "lang": "ar", "truth": "scam",
     "text": "معك الدعم الفني للبنك، رصدنا عملية مشبوهة على حسابك. ثبّت تطبيق AnyDesk الآن حتى نحمي أموالك ولا تخبر أحداً بهذه المكالمة."},
]


def tactic_view(key: str) -> dict:
    t = TACTICS[key]
    return {"key": key, "label_en": t.label_en, "label_ar": t.label_ar, "explain_en": t.explain_en, "explain_ar": t.explain_ar}


def stages() -> list[dict]:
    out = []
    for s in STAGE_ORDER:
        keys = [k for k, t in TACTICS.items() if t.stage == s]
        out.append({"key": s, **STAGES[s], "tactics": [tactic_view(k) for k in keys]})
    return out
