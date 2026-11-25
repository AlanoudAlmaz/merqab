import { FILMS } from "./theater.js";

const text = (en, ar) => ({ en, ar });
const scene = (kind, en, ar) => ({ k: kind, d: 3100, text: text(en, ar), ...(kind === "in" ? { from: text("Messages", "الرسائل") } : {}) });
const option = (id, label, safe, outcome, verdict) => ({
  id, label, safe, out: [outcome], verdict,
});
const existing = id => FILMS.find(film => film.id === id);

export const AWARENESS = [
  {
    id: "clue", tone: "#0369a1", icon: "🔎",
    title: text("Spot the clue", "اكتشف الإشارة"),
    logline: text("Choose the detail that gives the scam away.", "اختر التفصيل الذي يكشف محاولة الاحتيال."),
    tactics: ["urgency", "credential_request"],
    beats: [
      scene("in", "Your account will be locked in five minutes. Reply with the verification code to keep access.", "سيتم إيقاف حسابك خلال خمس دقائق. أرسل رمز التحقق في الرد لتجنّب الإيقاف."),
      { k: "decide", prompt: text("Tap the clearest warning sign.", "اضغط على أوضح علامة تحذير."), choices: [
        option("time", text("The message arrived in the evening", "وصلت الرسالة في المساء"), false,
          scene("sys", "Timing alone does not verify the sender.", "وقت الرسالة وحده لا يكشف هوية المرسل."),
          text("Look at what the message wants you to do.", "ركّز على الإجراء الذي تطلبه الرسالة.")),
        option("code", text("It asks me to send a verification code", "تطلب مني إرسال رمز التحقق"), true,
          scene("sys", "You keep the code private and verify through the official app.", "احتفظت بالرمز لنفسك وتحققت عبر التطبيق الرسمي."),
          text("You spotted the request that put the account at risk.", "حددت الطلب الذي كان سيعرّض حسابك للخطر.")),
      ] },
    ],
    rule: text("Treat a request to share a verification code as a warning, even if the sender looks familiar.", "اعتبر طلب مشاركة رمز التحقق علامة تحذير حتى لو بدا اسم المرسل مألوفًا."),
  },
  existing("voice"),
  existing("parcel"),
  {
    id: "family-plan", tone: "#0f766e", icon: "🏠",
    title: text("Make a family plan", "اتفقوا على خطة للأسرة"),
    logline: text("Pick the reply you want your family to use next time.", "اختر الرد الذي تبي أسرتك تستخدمه المرة القادمة."),
    tactics: ["identity_claim"],
    beats: [
      scene("in", "Family chat: What should we do if someone calls from a new number and says they need money?", "مجموعة الأسرة: شو نسوي لو اتصل شخص من رقم يديد وقال إنه من الأهل ويحتاج فلوس؟"),
      { k: "decide", prompt: text("Choose a reply for the family chat.", "اختر ردًا ترسله في مجموعة الأسرة."), choices: [
        option("callback", text("Hang up and call them on their saved number", "سكروا الخط واتصلوا بالشخص على رقمه المحفوظ"), true,
          scene("sys", "The family agrees on a callback and a trusted second contact.", "اتفقت الأسرة على إعادة الاتصال والتواصل مع شخص موثوق إذا تعذّر التحقق."),
          text("You gave everyone a clear action they can remember.", "اتفقتم على خطوة واضحة يسهل تذكّرها.")),
        option("photo", text("Ask them to send a profile photo", "اطلبوا منه يرسل صورة شخصية"), false,
          scene("sys", "The caller sends a photo copied from a public profile.", "الطرف الآخر يرسل صورة أخذها من حساب عام."),
          text("A familiar photo can be copied. Verify through a saved contact.", "الصورة المألوفة ممكن تننسخ. تحقّقوا عبر رقم محفوظ.")),
      ] },
    ],
    rule: text("Agree on a callback and a trusted backup contact before there is an emergency.", "اتفقوا على طريقة إعادة الاتصال وشخص موثوق بديل قبل وقوع طارئ."),
  },
  {
    id: "response", tone: "#a34f0c", icon: "🛡️",
    title: text("You already paid", "إذا دفعت بالفعل"),
    logline: text("Decide what to do first after a suspicious charge.", "حدّد أول خطوة بعد ظهور عملية دفع مشبوهة."),
    tactics: ["payment_instruction"],
    beats: [
      scene("sys", "A payment has gone through. A second message offers a refund and asks for another code.", "تم خصم المبلغ. وصلت رسالة ثانية تعرض استرداده وتطلب رمزًا آخر."),
      { k: "decide", prompt: text("Which action comes first?", "شو أول خطوة تتخذها؟"), choices: [
        option("bank", text("Contact my bank through its official app or number", "أتواصل مع البنك من تطبيقه أو رقمه الرسمي"), true,
          scene("sys", "You reach your bank and ask about securing the card and disputing the payment.", "تواصلت مع البنك وسألت عن تأمين البطاقة والاعتراض على العملية."),
          text("You took the issue to the party that can act on the payment.", "تواصلت مع الجهة اللي تقدر تتعامل مع عملية الدفع.")),
        option("refund", text("Reply with the code to get the refund", "أرسل الرمز عشان يرجع المبلغ"), false,
          scene("sys", "The sender asks for yet another code. The refund is still unverified.", "المرسل يطلب رمزًا إضافيًا، والاسترداد ما زال غير موثوق."),
          text("Stop sharing information and contact your bank directly.", "وقف مشاركة المعلومات وتواصل مباشرة مع البنك.")),
      ] },
    ],
    rule: text("Contact the bank through an official channel and keep the relevant messages and payment details.", "تواصل مع البنك عبر قناة رسمية واحتفظ بالرسائل وتفاصيل عملية الدفع ذات الصلة."),
  },
  {
    id: "community-report", tone: "#6244a6", icon: "📣",
    title: text("Warn someone else", "احمِ غيرك بتنبيه"),
    logline: text("Choose what to share when others get the same message.", "اختر شو تشارك لما يوصل نفس الاحتيال لأشخاص آخرين."),
    tactics: ["link_prompt", "personal_data_request"],
    beats: [
      scene("in", "A neighbour received the same delivery message. You want to warn the community.", "وصلت نفس رسالة التوصيل لجارك. تبي تحذّر المجتمع منها."),
      { k: "decide", prompt: text("Which warning would you publish?", "أي تنبيه تختار تنشره؟"), choices: [
        option("redact", text("Describe the scam and hide private details and the active link", "أشرح طريقة الاحتيال وأخفي البيانات الخاصة والرابط القابل للفتح"), true,
          scene("sys", "People can recognise the warning sign without opening a suspicious link.", "يقدر الناس يتعرّفون على علامة الاحتيال بدون فتح رابط مشبوه."),
          text("Your warning helps others act safely.", "التنبيه يساعد غيرك ياخذ إجراء آمن.")),
        option("forward", text("Forward the original screenshot and active link", "أرسل الصورة الأصلية والرابط القابل للفتح"), false,
          scene("sys", "The original may expose private details and somebody could open the link.", "الرسالة الأصلية قد تكشف بيانات خاصة، وممكن شخص يفتح الرابط."),
          text("Share what people need to recognise the scam and protect themselves.", "شارك التفاصيل اللي تساعد الناس يتعرّفون على الاحتيال ويحمون أنفسهم.")),
      ] },
    ],
    rule: text("Use the report form to share a description and remove details that identify the victim.", "استخدم نموذج البلاغ لوصف الاحتيال واحذف التفاصيل التي تحدد هوية المتضرر."),
  },
];
