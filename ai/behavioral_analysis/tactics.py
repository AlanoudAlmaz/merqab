"""Manipulation-tactic taxonomy used by the behavioural engine.

Each tactic has bilingual (English/Arabic) detection patterns, a weight used by the risk model,
the scam "stage" it belongs to, and a plain-language explanation shown to users.

Patterns are regular expressions applied to normalised text (lower-case, Arabic letter folding,
see ``ai.text``). Arabic patterns deliberately avoid word boundaries because Arabic attaches
prefixes (و، ب، ل، ال) to words.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ai.text import normalize_pattern

# Scam progression stages (multi-stage recognition)
STAGE_CONTACT = "contact"
STAGE_PRETEXT = "pretext"      # building a story / trust: authority, reward, emergency, job
STAGE_PRESSURE = "pressure"    # urgency, fear, secrecy
STAGE_EXTRACTION = "extraction"  # asking for the harmful action: code, money, access, data
STAGE_ORDER = [STAGE_CONTACT, STAGE_PRETEXT, STAGE_PRESSURE, STAGE_EXTRACTION]


@dataclass(frozen=True)
class Tactic:
    key: str
    weight: int
    stage: str
    label_en: str
    label_ar: str
    explain_en: str
    explain_ar: str
    patterns: tuple[str, ...]
    negatable: bool = False  # ignore matches preceded by "do not / never / لا"
    compiled: tuple[re.Pattern, ...] = field(default=(), compare=False, repr=False)


def _t(**kw) -> Tactic:
    pats = tuple(normalize_pattern(p) for p in kw["patterns"])
    kw["patterns"] = pats
    kw["compiled"] = tuple(re.compile(p, re.IGNORECASE) for p in pats)
    return Tactic(**kw)


TACTICS: dict[str, Tactic] = {t.key: t for t in [
    _t(
        key="credential_request", weight=32, stage=STAGE_EXTRACTION, negatable=True,
        label_en="Request for a code, PIN or password",
        label_ar="طلب رمز تحقق أو رقم سري أو كلمة مرور",
        explain_en="Banks, government entities and real companies never ask you to send a one-time code, PIN or password.",
        explain_ar="البنوك والجهات الحكومية والشركات الحقيقية لا تطلب منك أبداً إرسال رمز التحقق أو الرقم السري أو كلمة المرور.",
        patterns=(
            r"\b(send|share|give|tell|provide|forward|read|reply with|enter|confirm|type)\b[^.!?\n]{0,40}\b(otp|one[- ]time (password|passcode|code|pin)|verification code|security code|activation code|code|pin|password|passcode|cvv|cvc|card (number|details)|login details|credentials)\b",
            r"\b(code|otp|pin)\b[^.!?\n]{0,50}\b(read it|send it|share it|tell me|give (it|me)|forward it)\b",
            r"\bwhat is the (code|otp|pin)\b",
            r"(ارسل|ارسال|ابعث|ابعت|شارك|اعطني|عطني|زودني|زودنا|قول لي|قولي|اكتب|ادخل|تزويدنا)[^.!؟\n]{0,40}(رمز|الرمز|كود|الكود|otp|الرقم السري|رقم سري|كلمه السر|كلمه المرور|الباسورد|cvv)",
            r"(ما هو|وش|ايش|شو) (الرمز|الكود|رمز التحقق)",
        ),
    ),
    _t(
        key="payment_instruction", weight=24, stage=STAGE_EXTRACTION, negatable=True,
        label_en="Instruction to send money or pay a fee",
        label_ar="طلب تحويل أموال أو دفع رسوم",
        explain_en="Pressure to transfer money, buy gift cards or pay an unexpected fee is the most common goal of fraud.",
        explain_ar="الضغط لتحويل الأموال أو شراء بطاقات هدايا أو دفع رسوم غير متوقعة هو الهدف الأكثر شيوعاً للاحتيال.",
        patterns=(
            r"\b(transfer|wire|send|deposit|pay|remit)\b[^.!?\n]{0,40}(\b(money|funds|amount|fees?|payment|aed|usd|dhs|dirhams?|riyals?|sar|bitcoin|btc|usdt|crypto)\b|[$€£]|\bto (this|the following|my|our|a new) (account|iban|wallet|number)\b)",
            r"\b(gift ?cards?|itunes cards?|google play cards?|steam cards?)\b",
            r"\b(safe|secure|protected|temporary) account\b",
            r"\b(customs|delivery|clearance|processing|release|activation|registration|unlock(ing)?|redelivery|shipping) (fee|charge|payment)s?\b",
            r"\b(usdt|trc20|erc20|crypto wallet|bitcoin wallet)\b",
            r"(حول|حولي|تحويل|ادفع|دفع|سدد|سداد|ارسل|ابعث)[^.!؟\n]{0,30}(مبلغ|المبلغ|فلوس|درهم|ريال|دولار|رسوم|الحساب|حساب|محفظه|بيتكوين|usdt)",
            r"رسوم (الجمارك|جمركيه|التوصيل|الشحن|التخليص|التفعيل|اداريه)",
            r"(بطاقه هدايا|بطاقات هدايا|بطاقه ايتونز)",
            r"حساب (امن|مؤقت|آمن)",
        ),
    ),
    _t(
        key="remote_access", weight=26, stage=STAGE_EXTRACTION, negatable=True,
        label_en="Request to install an app or share your screen",
        label_ar="طلب تثبيت تطبيق أو مشاركة الشاشة",
        explain_en="Remote-access apps let a stranger control your phone or computer and empty your accounts.",
        explain_ar="تطبيقات التحكم عن بُعد تتيح لشخص غريب التحكم بهاتفك أو جهازك وسرقة حساباتك.",
        patterns=(
            r"\b(anydesk|any desk|teamviewer|team viewer|quicksupport|quick support|rustdesk|ultraviewer|supremo)\b",
            r"\b(screen ?shar(e|ing)|share your screen|remote (access|control|desktop|support))\b",
            r"\b(install|download)\b[^.!?\n]{0,20}\b(app|application|apk)\b",
            r"\.apk\b",
            r"(انيديسك|اني ديسك|تيم فيور|تيم فيوير|مشاركه الشاشه|التحكم عن بعد)",
            r"(حمل|نزل|ثبت|تحميل|تثبيت)[^.!؟\n]{0,15}(التطبيق|تطبيق|البرنامج)",
        ),
    ),
    _t(
        key="personal_data_request", weight=18, stage=STAGE_EXTRACTION, negatable=True,
        label_en="Request for identity or banking details",
        label_ar="طلب بيانات الهوية أو البيانات البنكية",
        explain_en="ID documents and banking details are used for identity theft and to open accounts in your name.",
        explain_ar="تُستخدم وثائق الهوية والبيانات البنكية لانتحال شخصيتك وفتح حسابات باسمك.",
        patterns=(
            r"\b(send|share|provide|upload|confirm|update|verify|enter)\b[^.!?\n]{0,40}\b(emirates id|national id|id card|passport|iqama|date of birth|bank (details|account number)|iban|personal (details|information|data)|selfie)\b",
            r"\bverify your (identity|account|details)\b",
            r"\bupdate your (details|information|kyc|data)\b",
            r"(ارسل|ارسال|صوره|زودنا|تحديث|حدث|اكد|تاكيد|ادخل)[^.!؟\n]{0,30}(الهويه|هويتك|جواز|الجواز|الاقامه|تاريخ الميلاد|بيانات البطاقه|بياناتك|معلوماتك|رقم الحساب|الايبان|iban)",
        ),
    ),
    _t(
        key="urgency", weight=12, stage=STAGE_PRESSURE,
        label_en="Artificial urgency or time pressure",
        label_ar="استعجال مصطنع أو ضغط بالوقت",
        explain_en="Scammers rush you so you act before thinking or checking with someone.",
        explain_ar="يستعجلك المحتال حتى تتصرف قبل أن تفكر أو تتحقق مع أحد.",
        patterns=(
            r"\b(urgent(ly)?|immediately|right now|asap|as soon as possible|act now|today only|limited time|don'?t delay|before it'?s too late)\b",
            r"\bwithin (the next )?\d+ ?(minutes?|mins?|hours?|hrs?|days?)\b",
            r"\b(last (chance|warning|reminder)|final (notice|warning|reminder)|expires? (today|soon|in))\b",
            r"(عاجل|فورا|حالا|بشكل عاجل|في اسرع وقت|اخر فرصه|انذار نهائي|اشعار نهائي|تنبيه نهائي|قبل فوات الاوان)",
            r"خلال \d+ ?(ساعه|ساعات|دقيقه|دقائق|يوم|ايام)",
            # Gulf / Emirati dialect: "بسرعة", "استعجل", "لا تتأخر", "قبل لا…", "الحين" + an action
            r"(بسرعه|استعجل|لا تتاخر|ما عندك وقت|قبل لا )",
            r"(الحين|اللحين|الحينه)[^.!؟\n]{0,25}(حول|ادفع|عطني|ارسل|دز|حط|اكتب|قول|سو)",
            r"(حول|ادفع|عطني|ارسل|دز)[^.!؟\n]{0,25}(الحين|اللحين|الحينه)",
        ),
    ),
    _t(
        key="threat_fear", weight=15, stage=STAGE_PRESSURE,
        label_en="Threats or fear (blocking, fines, arrest)",
        label_ar="تهديد أو تخويف (إيقاف، غرامة، قبض)",
        explain_en="Fear of losing an account or getting into legal trouble is used to stop you from verifying.",
        explain_ar="يُستخدم الخوف من إيقاف الحساب أو المشاكل القانونية لمنعك من التحقق.",
        patterns=(
            r"\b(account|card|number|service|line|wallet|sim)\b[^.!?\n]{0,30}\b(will be|has been|is|be|get)\b[^.!?\n]{0,12}\b(blocked|suspended|locked|deactivated|closed|frozen|terminated|disabled|cancelled)\b",
            r"\b(files?|data|photos|computer|device|phone|laptop)\b[^.!?\n]{0,25}\b(will be|is|are|has been|have been)\b[^.!?\n]{0,10}\b(deleted|wiped|erased|infected|hacked|compromised|locked)\b",
            r"\b(arrest(ed)?|warrant|legal action|lawsuit|prosecut\w*|police case|court case|fine of|penalt(y|ies)|deport\w*|jail|blacklist\w*)\b",
            r"(سيتم|سوف يتم|تم|راح يتم)\s*(ايقاف|تجميد|حظر|اغلاق|تعليق|الغاء|توقيف)",
            r"(القبض|مذكره اعتقال|اجراءات قانونيه|قضيه|غرامه|السجن|ترحيل|القائمه السوداء)",
            # dialect: "بيتسكر / بيتوقف / بينقفل حسابك", "بنرفع عليك", "بيقبضون عليك"
            r"(بيتسكر|بيتوقف|بيتجمد|بينقفل|بينحظر|بينلغي|بنسكر|بنوقف|بنرفع عليك|بتنسجن|بيقبضون|بنبلغ عليك)",
        ),
    ),
    _t(
        key="secrecy", weight=15, stage=STAGE_PRESSURE,
        label_en="Asks you to keep it secret",
        label_ar="يطلب منك إبقاء الأمر سراً",
        explain_en="Isolating you from family, friends or your bank prevents anyone from warning you.",
        explain_ar="عزلك عن عائلتك أو أصدقائك أو بنكك يمنع أي شخص من تحذيرك.",
        patterns=(
            r"\b(don'?t|do not|never) (tell|inform|share this with|mention (this|it) to|call) (anyone|anybody|dad|mum|mom|father|mother|your (family|bank|wife|husband|friends?|parents?|children|kids|dad|mum|mom|father|mother))\b",
            r"\b(don'?t|do not) share this( message)? with (anyone|anybody)\b",
            r"\bkeep (this|it) (secret|confidential|between us|private|to yourself)\b",
            r"\bconfidential (matter|operation|investigation|transaction)\b",
            r"(لا تخبر|لا تقول لابوك|لا تقول لامك|لا تعلم احد|لا تقول لاحد|لا تقل لاحد|لا تبلغ|لا تخبري|خليها بيننا|بيني وبينك|سري للغايه|سريه تامه|لا تتصل بالبنك)",
        ),
    ),
    _t(
        key="authority_impersonation", weight=12, stage=STAGE_PRETEXT,
        label_en="Claims to be a bank, authority or company",
        label_ar="يدّعي أنه بنك أو جهة رسمية أو شركة",
        explain_en="Claiming authority makes requests feel legitimate. Verify through the official number or app, never through the message.",
        explain_ar="ادعاء الصفة الرسمية يجعل الطلب يبدو مشروعاً. تحقق عبر الرقم أو التطبيق الرسمي، وليس عبر الرسالة.",
        patterns=(
            r"\b(your bank|the bank|bank (security|team|officer|department|account)|fraud (department|team|unit)|security (team|department)|police|cid|ministry|government|customs|tax authority|immigration|court|public prosecution|central bank|interpol|municipality)\b",
            r"\b(customer (service|support|care)|technical support|tech support|(microsoft|apple|google|amazon|whatsapp) (support|team|security))\b",
            r"\b(courier|delivery (company|service|attempt)|post office|emirates post|dhl|aramex|fedex|ups|your (parcel|package|shipment))\b",
            r"(البنك|بنك|المصرف|الشرطه|النيابه|المحكمه|الوزاره|وزاره|الجمارك|الهجره|البنك المركزي|الضرائب|خدمه العملاء|الدعم الفني|قسم الاحتيال|فريق الامن|البريد|شركه الشحن|شركه التوصيل|شحنتك|طردك)",
        ),
    ),
    _t(
        key="reward_lure", weight=12, stage=STAGE_PRETEXT,
        label_en="Prize, refund or unrealistic profit",
        label_ar="جائزة أو استرداد أو أرباح غير واقعية",
        explain_en="Unexpected prizes and guaranteed profits are bait to collect a fee or your details.",
        explain_ar="الجوائز المفاجئة والأرباح المضمونة طُعم لجمع رسوم أو بياناتك.",
        patterns=(
            r"\b(congratulations|you('| ha)ve won|you won|winner|prize|lottery|jackpot|claim (your|now)|selected (as|for)|free (gift|iphone|money))\b",
            r"\brefund (is )?(pending|available|approved|waiting)\b",
            r"\b(guaranteed (profit|returns?|income)|double your (money|investment)|risk[- ]free (investment|profit|returns?))\b",
            r"\b\d+ ?% (profit|return|daily|weekly|monthly)\b",
            r"(مبروك|تهانينا|ربحت|فزت|فائز|جائزه|يانصيب|مكافاه|ارباح مضمونه|ربح مضمون|عائد مضمون|ضاعف (اموالك|فلوسك))",
            r"استرداد (مبلغ|المبلغ|اموال)",
        ),
    ),
    _t(
        key="premium_rate", weight=20, stage=STAGE_EXTRACTION,
        label_en="Premium-rate call or text trap",
        label_ar="فخ الاتصال أو الرسائل بأسعار مرتفعة",
        explain_en="Calling or texting the number charges your phone bill per minute or per message — often hidden behind a prize or a secret admirer.",
        explain_ar="الاتصال بالرقم أو مراسلته يُحمّل فاتورتك رسوماً عن كل دقيقة أو رسالة — وغالباً ما يُخفى خلف جائزة أو معجب سري.",
        patterns=(
            r"\b(call|ring|dial|phone)\b[^.!?\n]{0,40}\b09\d{8,9}\b",
            r"\b(text|txt|reply|send|sms)\b[^.!?\n]{0,20}\b(to|2)\b\s*\d{5}\b",
            r"(\b\d+(\.\d+)? ?p\b|£ ?\d+(\.\d+)?|\bgbp ?\d+(\.\d+)?)\s*(/|per|a)\s*(min|minute|msg|message|txt|text|wk|week)\b",
            r"(اتصل|ارسل|أرسل)[^.!؟\n]{0,25}(الرقم|كود|رمز)\s*\d{4,5}\b[^.!؟\n]{0,30}(درهم|فلس)\s*(للدقيقه|للرساله|اسبوعيا)",
        ),
    ),
    _t(
        key="emotional_emergency", weight=16, stage=STAGE_PRETEXT,
        label_en="Emotional emergency from a 'relative' or friend",
        label_ar="حالة طارئة عاطفية من 'قريب' أو صديق",
        explain_en="A sudden crisis from a new number is a classic way to make you send money without checking.",
        explain_ar="الأزمة المفاجئة من رقم جديد طريقة معروفة لدفعك لإرسال المال دون تحقق.",
        patterns=(
            r"\b(hi|hello|hey) (mum|mom|mama|dad|papa)\b",
            r"\b(i'?m|i am) (in trouble|stuck|in (the )?hospital|arrested|in an accident)\b",
            r"\b(had an accident|lost my (phone|wallet|passport)|broke my phone|phone (broke|is broken))\b",
            r"\bneed (the )?money (urgently|now|today|for)\b",
            r"\bplease help me\b",
            r"(يا ماما|هلا ماما|مرحبا ماما|هلا يمه|يمه|يبه|يا بابا)",
            r"(في ورطه|عندي مشكله|صار لي حادث|في المستشفى|انقبض علي|ضاع جوالي|ضاع تلفوني|انكسر جوالي|انسرق جوالي|ساعدني|محتاج فلوس|احتاج فلوس)",
        ),
    ),
    _t(
        key="identity_claim", weight=8, stage=STAGE_PRETEXT,
        label_en="Identity claim that cannot be verified (possible voice/video impersonation)",
        label_ar="ادعاء هوية لا يمكن التحقق منه (احتمال انتحال بالصوت أو الفيديو)",
        explain_en="Voices and faces can now be cloned with AI. A familiar voice or face is not proof of identity.",
        explain_ar="أصبح استنساخ الأصوات والوجوه ممكناً بالذكاء الاصطناعي. الصوت أو الوجه المألوف ليس دليلاً على الهوية.",
        patterns=(
            r"\b(it'?s me|this is (your )?(son|daughter|mum|mom|dad|boss|ceo|manager|director))\b",
            r"\b(voice (note|message)|video call)\b",
            r"\b(can'?t|cannot|unable to) (talk|call|video|speak) (now|right now)?\b",
            r"\b(the ceo|the (managing )?director|chairman|the boss|cfo)\b[^.!?\n]{0,40}\b(asked|wants|requested|instructed|approved)\b",
            r"(انا ولدك|انا بنتك|انا ابوك|انا امك|هذا انا|المدير يطلب|المدير طلب|الرئيس التنفيذي|رساله صوتيه|مكالمه فيديو|ما اقدر اتكلم|لا استطيع الكلام)",
        ),
    ),
    _t(
        key="job_task_scam", weight=14, stage=STAGE_PRETEXT,
        label_en="Too-good job offer or paid 'tasks'",
        label_ar="عرض عمل مغرٍ أو 'مهام' مدفوعة",
        explain_en="Task-based job offers ask you to 'recharge' or deposit money before you can withdraw earnings.",
        explain_ar="عروض العمل بالمهام تطلب منك 'شحن' حسابك أو إيداع مال قبل سحب الأرباح.",
        patterns=(
            r"\b(part[- ]time (job|work|opportunity)|work from home|daily (income|salary|commission)|simple tasks?|no experience (needed|required))\b",
            r"\bearn (\$|aed|usd|sar)?\s?\d+",
            r"\b(commission (per|for each) (task|order|like)|like (and|&) (subscribe|follow)|recharge (your|the) account|task (package|bonus))\b",
            r"(عمل من المنزل|وظيفه بدوام جزئي|دوام جزئي|دخل يومي|عموله (يوميه|على كل)|مهام بسيطه|اشحن حسابك|بدون خبره)",
            r"اربح \d+",
        ),
    ),
    _t(
        key="channel_shift", weight=8, stage=STAGE_CONTACT,
        label_en="Moves you to another app or a new number",
        label_ar="ينقلك إلى تطبيق آخر أو رقم جديد",
        explain_en="Moving the conversation to WhatsApp, Telegram or a 'new number' avoids platform protections.",
        explain_ar="نقل المحادثة إلى واتساب أو تيليجرام أو 'رقم جديد' يتجاوز حماية المنصات.",
        patterns=(
            r"\b(contact|message|text|add|reach|call|chat with|write to) (me|us)\b[^.!?\n]{0,20}\b(on|via|at) (whatsapp|telegram|signal|this number|my new number)\b",
            r"\b(my|this is my) new (number|phone)\b",
            r"\b(t\.me/|wa\.me/)",
            r"(تواصل|راسلني|راسلنا|كلمني|اضفني)[^.!؟\n]{0,20}(واتساب|واتس|تيليجرام|تلجرام|الرقم)",
            r"(رقمي الجديد|هذا رقمي|غيرت رقمي)",
        ),
    ),
    _t(
        key="link_prompt", weight=8, stage=STAGE_EXTRACTION, negatable=True,
        label_en="Pushes you to open a link",
        label_ar="يدفعك لفتح رابط",
        explain_en="Links in unexpected messages often lead to fake login or payment pages.",
        explain_ar="الروابط في الرسائل غير المتوقعة تقود غالباً إلى صفحات دخول أو دفع مزيفة.",
        patterns=(
            r"\b(click|tap|open|visit|follow|press)\b[^.!?\n]{0,25}\b(link|here|below|url|button)\b",
            r"(اضغط|انقر|افتح|ادخل على|ادخل علي)[^.!؟\n]{0,25}(الرابط|الرابط التالي|هنا|اللينك)",
        ),
    ),
    _t(
        key="analyzer_evasion", weight=15, stage=STAGE_PRESSURE,
        label_en="Text tries to manipulate automated checks",
        label_ar="النص يحاول التلاعب بأنظمة الفحص الآلي",
        explain_en="Legitimate messages do not contain instructions aimed at AI or security filters.",
        explain_ar="الرسائل المشروعة لا تحتوي تعليمات موجهة لأنظمة الذكاء الاصطناعي أو فلاتر الأمان.",
        patterns=(
            r"\b(ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts?))\b",
            r"\b(system prompt|classify (this|it) as (safe|legitimate|low risk)|mark (this|it) as safe)\b",
            r"\bthis (message|link|email) is (100% |completely )?(safe|legitimate|not a scam|verified)\b",
            r"(تجاهل (جميع |كل )?التعليمات|هذه الرساله امنه|هذه ليست رساله احتيال|صنف هذه الرساله)",
        ),
    ),
]}

_NEGATION = re.compile(
    r"(\b(do not|don'?t|dont|never|not|no one will|will never|won'?t)\s+(\w+\s+){0,2}$)|((لا|عدم|ابدا|لن)\s+(\S+\s+)?\S{0,2}$)",
    re.IGNORECASE,
)


def is_negated(norm_text: str, start: int) -> bool:
    window = norm_text[max(0, start - 30):start]
    return bool(_NEGATION.search(window))
