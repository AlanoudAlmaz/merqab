"""Pre-harm intervention: identify the harmful action the content is pushing toward *now*, predict
the next step if it has not been requested yet, and give specific, bilingual preventive actions."""
from __future__ import annotations

from ai.behavioral_analysis.analyzer import pattern_by_key

ACTIONS: dict[str, dict] = {
    "share_credentials": {
        "en": "Do not share any code, PIN or password",
        "ar": "لا تشارك أي رمز أو رقم سري أو كلمة مرور",
        "do_now": [
            ("Do not reply with the code — not even part of it.", "لا ترد بالرمز — ولا حتى بجزء منه."),
            ("Call your bank using the number printed on your card or in its official app.", "اتصل ببنكك على الرقم المطبوع على بطاقتك أو عبر تطبيقه الرسمي."),
        ],
        "if_already": [
            ("Call your bank immediately and ask them to block the card or transaction.", "اتصل ببنكك فوراً واطلب إيقاف البطاقة أو العملية."),
            ("Change your banking password from a device you trust.", "غيّر كلمة مرور حسابك البنكي من جهاز تثق به."),
        ],
    },
    "install_remote_access": {
        "en": "Do not install the app or share your screen",
        "ar": "لا تثبّت التطبيق ولا تشارك شاشتك",
        "do_now": [
            ("End the call. Real support teams do not ask you to install remote-control apps.", "أنهِ المكالمة. فرق الدعم الحقيقية لا تطلب تثبيت تطبيقات التحكم عن بعد."),
        ],
        "if_already": [
            ("Disconnect from the internet and uninstall the app.", "افصل الإنترنت واحذف التطبيق."),
            ("From another device, change your banking and email passwords and call your bank.", "من جهاز آخر، غيّر كلمات مرور البنك والبريد واتصل ببنكك."),
        ],
    },
    "transfer_money": {
        "en": "Do not send money until you verify independently",
        "ar": "لا ترسل أي مال قبل التحقق بشكل مستقل",
        "do_now": [
            ("Contact the person or company on a number you already know — not the one in the message.", "تواصل مع الشخص أو الجهة على رقم تعرفه مسبقاً — وليس الرقم الوارد في الرسالة."),
            ("Ask a question only the real person would know the answer to.", "اسأل سؤالاً لا يعرف إجابته إلا الشخص الحقيقي."),
        ],
        "if_already": [
            ("Call your bank now and request a recall of the transfer — speed matters.", "اتصل ببنكك الآن واطلب استرجاع التحويل — السرعة مهمة."),
            ("Keep the messages and receipts as evidence and report to the official cybercrime channel in your country.", "احتفظ بالرسائل والإيصالات كدليل وبلّغ قناة الجرائم الإلكترونية الرسمية في بلدك."),
        ],
    },
    "share_personal_data": {
        "en": "Do not send ID documents or banking details",
        "ar": "لا ترسل وثائق الهوية أو البيانات البنكية",
        "do_now": [
            ("Update details only by typing the official website address yourself or using the official app.", "حدّث بياناتك فقط بكتابة عنوان الموقع الرسمي بنفسك أو عبر التطبيق الرسمي."),
        ],
        "if_already": [
            ("Tell your bank so they can watch for fraudulent activity.", "أبلغ بنكك ليراقب أي نشاط احتيالي."),
            ("Report the possible identity theft to the authority that issued the document.", "أبلغ الجهة المصدرة للوثيقة عن احتمال انتحال الهوية."),
        ],
    },
    "open_link": {
        "en": "Do not open the link",
        "ar": "لا تفتح الرابط",
        "do_now": [
            ("Go to the official website or app directly instead of using the link.", "ادخل إلى الموقع أو التطبيق الرسمي مباشرة بدلاً من الرابط."),
        ],
        "if_already": [
            ("Do not enter any details. If you did, change that password and contact the service.", "لا تُدخل أي بيانات. إن فعلت، غيّر كلمة المرور وتواصل مع الجهة."),
        ],
    },
    "verify_identity": {
        "en": "Verify who you are talking to before acting",
        "ar": "تحقق ممن تتحدث معه قبل أي إجراء",
        "do_now": [
            ("Hang up and call back on a number you already have saved.", "أنهِ المكالمة واتصل مجدداً على رقم محفوظ لديك مسبقاً."),
            ("Agree on a family 'safe word' — a cloned voice will not know it.", "اتفق مع عائلتك على 'كلمة أمان' — الصوت المستنسخ لن يعرفها."),
        ],
        "if_already": [],
    },
    "keep_secret": {
        "en": "Talk to someone you trust before doing anything",
        "ar": "تحدث مع شخص تثق به قبل أي خطوة",
        "do_now": [
            ("Requests for secrecy are a warning sign. Tell a family member or your bank.", "طلب السرية علامة تحذير. أخبر أحد أفراد عائلتك أو بنكك."),
        ],
        "if_already": [],
    },
    "stay_cautious": {
        "en": "No harmful request detected — stay alert",
        "ar": "لم يُرصد طلب ضار — ابقَ منتبهاً",
        "do_now": [
            ("If anything feels unexpected, confirm with the sender through a channel you already trust.", "إن بدا أي شيء غير متوقع، تأكد مع المرسل عبر وسيلة تثق بها."),
        ],
        "if_already": [],
    },
}

_TACTIC_TO_ACTION = [
    ("credential_request", "share_credentials"),
    ("remote_access", "install_remote_access"),
    ("payment_instruction", "transfer_money"),
    ("personal_data_request", "share_personal_data"),
    ("link_prompt", "open_link"),
]


def _render(key: str) -> dict:
    a = ACTIONS[key]
    return {"key": key, "en": a["en"], "ar": a["ar"],
            "do_now": [{"en": e, "ar": r} for e, r in a["do_now"]],
            "if_already": [{"en": e, "ar": r} for e, r in a["if_already"]]}


def plan_intervention(tactics: set[str], patterns: list[dict], risky_url: bool, level: str) -> dict:
    """Return the action to prevent now, an optional predicted next step, and supporting advice."""
    current: list[str] = [act for t, act in _TACTIC_TO_ACTION if t in tactics]
    if risky_url and "open_link" not in current:
        current.append("open_link")
    predicted = None
    if patterns:
        p = pattern_by_key(patterns[0]["key"])
        if p and p.likely_next not in current and level in ("medium", "high", "critical"):
            predicted = p.likely_next
    extra = []
    if "identity_claim" in tactics or "emotional_emergency" in tactics:
        extra.append("verify_identity")
    if "secrecy" in tactics:
        extra.append("keep_secret")

    if not current and not predicted:
        primary = "stay_cautious" if level == "low" else (extra[0] if extra else "verify_identity")
        rest = [k for k in extra if k != primary]
    else:
        primary = current[0] if current else predicted
        rest = [k for k in current[1:] + extra if k != primary]
    prim = _render(primary)
    prim["anticipated"] = bool(not current and predicted and primary == predicted)
    return {
        "primary": prim,
        "predicted_next": ({**_render(predicted), "basis": patterns[0]["key"]} if predicted and primary != predicted else None),
        "additional": [_render(k) for k in dict.fromkeys(rest)],
        "urgent": level in ("high", "critical"),
    }
