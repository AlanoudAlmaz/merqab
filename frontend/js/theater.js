// Scam Theater — short interactive dramatizations. Each film plays on a phone stage, pauses at the moment of
// decision (with a countdown, so the viewer feels the pressure tactic), branches to the outcome of the choice and ends
// with the lesson and the real MERQAB engine tactics involved. Scripts are training dramatizations written for MERQAB
// (not real incidents); names, numbers and links are fictional and defanged.
import { h, isRTL, L, t } from "./core.js";

const REDUCED = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const tx = (en, ar) => ({ en, ar });
// the "account" film uses a common social platform as its example
const liveBrand = { en: "Instagram", ar: "إنستغرام" };
export const ft = (obj) => L(obj).replaceAll("{brand}", L(liveBrand));

const ICON_PATHS = {
  search: "M20 20l-4-4M17 11a6 6 0 1 1-12 0 6 6 0 0 1 12 0Z",
  call: "M7 3h3l2 5-3 2a13 13 0 0 0 5 5l2-3 5 2v3a3 3 0 0 1-3 3C10 20 4 14 4 6a3 3 0 0 1 3-3Z",
  parcel: "M4 7l8-4 8 4v10l-8 4-8-4V7Zm0 0 8 4 8-4m-8 4v10",
  family: "m3 11 9-7 9 7M5 10v10h14V10m-9 10v-5h4v5",
  shield: "M12 3 4 6v6c0 4 3 8 8 9 5-1 8-5 8-9V6l-8-3Z",
  report: "M4 4h16v12H9l-5 4V4Zm4 4h8m-8 4h5",
  bank: "m3 9 9-5 9 5H3Zm2 3v5m5-5v5m4-5v5m5-5v5M3 20h18",
  lock: "M7 10V7a5 5 0 0 1 10 0v3M5 10h14v11H5z",
  check: "m5 12 5 5 9-10",
  play: "m9 5 11 7-11 7V5Z",
  pause: "M9 5v14m6-14v14",
  restart: "M4 10a8 8 0 1 1 2 8M4 4v6h6",
};
export function awarenessIcon(name) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  for (const [key, value] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": "1.65", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) {
    svg.setAttribute(key, value);
  }
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", ICON_PATHS[name] || ICON_PATHS.shield);
  svg.append(path);
  return svg;
}

export const FILMS = [
  {
    id: "voice", icon: "🎙️", tone: "#be123c", situation: "video", sector: "family",
    title: tx("“Mum, it’s me…”", "«أمي، هذا أنا…»"),
    logline: tx("A cloned voice, a fake accident, two minutes to decide.", "صوت مُقلَّد، وحادث مزيّف، ودقيقتان للقرار."),
    tactics: ["emotional_emergency", "identity_claim", "urgency", "secrecy", "payment_instruction"],
    beats: [
      { k: "lock", d: 2600, app: "📞", title: tx("Unknown number", "رقم غير معروف"), body: tx("+971 5• ••• 4417 · calling…", "‎+971 5• ••• 4417 · يتصل…"), cap: tx("22:41. Mariam is about to sleep when her phone rings.", "الساعة 22:41. مريم على وشك النوم حين يرن هاتفها.") },
      { k: "call", d: 2200, name: tx("Unknown", "غير معروف"), cap: tx("She answers. It sounds exactly like her son, Omar.", "تردّ. الصوت يشبه ابنها عمر تماماً.") },
      { k: "voice", d: 4200, who: tx("“Omar”", "«عمر»"), text: tx("Mum… it’s me. I had an accident, the car is wrecked. My phone broke — I’m calling from a friend’s.", "أمي… هذا أنا. صار لي حادث والسيارة تحطمت. تلفوني انكسر، أكلمك من تلفون ربيعي."), say: true },
      { k: "voice", d: 4200, who: tx("“Omar”", "«عمر»"), text: tx("The other driver wants 4,000 dirhams now or he calls the police. Please — don’t tell Dad.", "السايق الثاني يبي 4,000 درهم الحين وإلا بيتصل بالشرطة. تكفين، لا تقولين لأبوي."), say: true },
      { k: "in", d: 3000, from: tx("Unknown", "غير معروف"), text: tx("IBAN AE07 0331 •••• •••• 2290 — send now, I’ll pay you back tonight", "IBAN AE07 0331 •••• •••• 2290 — حوّلي الحين وأرجعها لك الليلة"), cap: tx("An account number arrives while she is still on the call.", "يصلها رقم حساب وهي ما زالت على الخط.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "pay", label: tx("Transfer the money — he’s in trouble", "أحوّل المبلغ — ابني في ورطة"), safe: false,
            out: [
              { k: "sys", d: 2400, text: tx("Transfer of AED 4,000 completed", "تم تحويل 4,000 درهم"), cap: tx("The money leaves in seconds.", "المبلغ يخرج خلال ثوانٍ.") },
              { k: "voice", d: 3400, who: tx("“Omar”", "«عمر»"), text: tx("Thank you… one more thing, the police need 3,000 more for the report.", "شكراً… بس الشرطة تبي 3,000 زيادة عشان البلاغ."), say: true },
              { k: "sys", d: 2800, text: tx("Next morning, the real Omar calls: he was asleep at home.", "الصباح يتصل عمر الحقيقي: كان نايم في البيت."), cap: tx("The voice was cloned from his public videos.", "الصوت مُقلَّد من مقاطعه المنشورة.") }],
            verdict: tx("You lost AED 4,000 — and they came back for more.", "خسرت 4,000 درهم — ورجعوا يطلبون أكثر.") },
          { id: "callback", label: tx("Hang up and call Omar on his saved number", "أغلق الخط وأتصل بعمر على رقمه المحفوظ"), safe: true,
            out: [
              { k: "call", d: 2200, name: tx("Omar ❤️ (saved)", "عمر ❤️ (محفوظ)"), cap: tx("She calls the number already in her phone.", "تتصل بالرقم المحفوظ في هاتفها.") },
              { k: "voice", d: 3400, who: tx("Omar", "عمر"), text: tx("Mum? I’m home, I’m fine. What accident?", "أمي؟ أنا في البيت وبخير. أي حادث؟"), say: true }],
            verdict: tx("Scam stopped. One call to a saved number broke the story.", "تم إيقاف الاحتيال. اتصال واحد برقم محفوظ كشف القصة.") },
          { id: "codeword", label: tx("Ask for the family code word", "أسأله عن كلمة السر العائلية"), safe: true,
            out: [
              { k: "voice", d: 3000, v: "female", who: tx("Mariam", "مريم"), text: tx("If it’s you, tell me our family word.", "إذا أنت فعلاً، قل لي كلمة السر حقتنا."), say: true },
              { k: "sys", d: 2600, text: tx("Call ended by the other side.", "أنهى الطرف الآخر المكالمة."), cap: tx("A cloned voice can copy Omar — not a secret he never posted online.", "الصوت المقلَّد ينسخ عمر، لكنه لا يعرف سراً لم يُنشر أبداً.") }],
            verdict: tx("Scam stopped. The code word did what a voice can’t.", "تم إيقاف الاحتيال. كلمة السر فعلت ما لا يفعله الصوت.") }] }],
    rule: tx("A familiar voice is not proof. Hang up, call back on the saved number, or ask the family code word.", "الصوت المألوف ليس دليلاً. أغلق الخط واتصل بالرقم المحفوظ، أو اسأل عن كلمة السر العائلية."),
  },
  {
    id: "account", icon: "🔐", tone: "#0891b2", situation: "link", sector: "social",
    title: tx("“Your {brand} account will be disabled”", "«سيتم تعطيل حسابك في {brand}»"),
    logline: tx("A copyright warning, a login page, and a stolen account.", "تحذير حقوق نشر، وصفحة دخول، وحساب مسروق."),
    tactics: ["authority_impersonation", "threat_fear", "urgency", "link_prompt", "credential_request"],
    beats: [
      { k: "lock", d: 2800, app: "✉️", title: tx("{brand} Support", "دعم {brand}"), body: tx("Your account violates our copyright policy and will be disabled in 24h. Appeal: hxxps://{brand}-appeal-center[.]pages[.]dev", "حسابك يخالف سياسة حقوق النشر وسيُعطَّل خلال 24 ساعة. للاعتراض: hxxps://{brand}-appeal-center[.]pages[.]dev"), cap: tx("Noura runs a small business on {brand}. Losing the account means losing her customers.", "نورة تدير مشروعاً صغيراً على {brand}. خسارة الحساب تعني خسارة زبائنها.") },
      { k: "page", d: 3600, url: "{brand}-appeal-center[.]pages[.]dev", title: tx("Appeal form — log in to confirm", "نموذج الاعتراض — سجّل الدخول للتأكيد"), fields: [tx("Username", "اسم المستخدم"), tx("Password", "كلمة المرور")], cap: tx("A free page builder, a familiar logo, and a login box.", "منصة صفحات مجانية، وشعار مألوف، وخانة دخول.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "login", label: tx("Log in quickly to save my account", "أسجّل الدخول بسرعة لأنقذ حسابي"), safe: false,
            out: [
              { k: "in", d: 3000, from: tx("{brand}", "{brand}"), text: tx("Your login code is 552 031. Your email address was changed.", "رمز الدخول 552 031. تم تغيير بريدك الإلكتروني."), cap: tx("They log in, change the email, and lock her out.", "يدخلون، ويغيّرون البريد، ويقفلون الحساب عليها.") },
              { k: "sys", d: 3000, text: tx("Her followers receive: “Invest with me — DM for details 💰”", "متابعوها يستلمون: «استثمروا معي — راسلوني للتفاصيل 💰»"), cap: tx("Her account is now used to scam her own customers.", "حسابها يُستخدم الآن للاحتيال على زبائنها.") }],
            verdict: tx("Account stolen — and turned against the people who trust her.", "سُرق الحساب — واستُخدم ضد من يثقون بها.") },
          { id: "app", label: tx("Open the {brand} app and check notifications there", "أفتح تطبيق {brand} وأتحقق من التنبيهات هناك"), safe: true,
            out: [{ k: "sys", d: 3000, text: tx("Account status: no issues.", "حالة الحساب: لا توجد مشكلات."), cap: tx("Real warnings appear inside the app — not in a link.", "التحذيرات الحقيقية تظهر داخل التطبيق — لا عبر رابط.") }],
            verdict: tx("Safe. The official app showed the truth in seconds.", "بأمان. التطبيق الرسمي أظهر الحقيقة خلال ثوانٍ.") },
          { id: "mfa", label: tx("Ignore it and turn on two-step login", "أتجاهلها وأفعّل التحقق بخطوتين"), safe: true,
            out: [{ k: "sys", d: 3000, text: tx("Two-step login: ON", "التحقق بخطوتين: مُفعّل"), cap: tx("Even a stolen password won’t open the account now.", "حتى كلمة مرور مسروقة لن تفتح الحساب الآن.") }],
            verdict: tx("Safe — and harder to steal from now on.", "بأمان — وأصعب سرقةً من الآن.") }] }],
    rule: tx("Platforms warn you inside the app. Never log in through a link in a message.", "المنصات تحذّرك داخل التطبيق. لا تسجّل الدخول أبداً من رابط في رسالة."),
  },
  {
    id: "parcel", icon: "📦", tone: "#b45309", situation: "link", sector: "courier",
    title: tx("The 6-dirham parcel", "طرد بستة دراهم"),
    logline: tx("A tiny customs fee. A very big door.", "رسوم جمارك صغيرة… وباب كبير."),
    tactics: ["authority_impersonation", "urgency", "link_prompt", "credential_request"],
    beats: [
      { k: "lock", d: 2600, app: "💬", title: tx("ARAMEX-AE", "ARAMEX-AE"), body: tx("Your parcel is on hold. Pay AED 6.50 customs fee within 24h: hxxps://aramex-ae-fee[.]top", "طردك معلّق. ادفع 6.50 درهم رسوم جمارك خلال 24 ساعة: hxxps://aramex-ae-fee[.]top"), cap: tx("Khalid is actually waiting for a delivery.", "خالد ينتظر شحنة فعلاً.") },
      { k: "page", d: 3600, url: "aramex-ae-fee[.]top", title: tx("Customs payment", "سداد الجمارك"), fields: [tx("Card number", "رقم البطاقة"), tx("Expiry · CVV", "الانتهاء · CVV")], cap: tx("The page looks right: logo, colours, a tracking number.", "الصفحة تبدو صحيحة: الشعار والألوان ورقم تتبع.") },
      { k: "sys", d: 2600, text: tx("⏱ Parcel will be returned in 23:59:41", "⏱ سيُعاد الطرد خلال 23:59:41"), cap: tx("A countdown appears.", "يظهر عدّاد تنازلي.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "pay", label: tx("It’s only 6.50 — pay it", "مجرد 6.50 — أدفعها"), safe: false,
            out: [
              { k: "in", d: 3000, from: tx("Bank", "البنك"), text: tx("OTP 418 220 for AED 3,870.00 at ONLINE-STORE. Do not share.", "رمز التحقق 418 220 لعملية 3,870.00 درهم لدى متجر إلكتروني. لا تشاركه."), cap: tx("Minutes later: a real one-time code, for a very different amount.", "بعد دقائق: رمز حقيقي، لمبلغ مختلف تماماً.") },
              { k: "page", d: 3200, url: "aramex-ae-fee[.]top", title: tx("Verify your payment", "أكّد عملية الدفع"), fields: [tx("Enter the code we sent", "أدخل الرمز المرسل")], cap: tx("The fake page now asks for that code.", "الصفحة المزيفة تطلب هذا الرمز الآن.") }],
            verdict: tx("Card details and the code went to criminals — the AED 6.50 was bait.", "بيانات البطاقة والرمز ذهبت للمحتالين — الـ6.50 كانت طُعماً.") },
          { id: "app", label: tx("Ignore the link, track it in the official app", "أتجاهل الرابط وأتتبع الشحنة من التطبيق الرسمي"), safe: true,
            out: [
              { k: "sys", d: 3000, text: tx("Official app: “In transit — no fees due.”", "التطبيق الرسمي: «قيد الشحن — لا رسوم مستحقة».") , cap: tx("No fee. No hold. The message was fake.", "لا رسوم ولا تعليق. الرسالة مزيفة.") }],
            verdict: tx("Safe. Opening the official app yourself skipped the trap completely.", "بأمان. فتح التطبيق الرسمي بنفسك تجاوز الفخ بالكامل.") },
          { id: "check", label: tx("Paste it into MERQAB first", "ألصقها في مرقاب أولاً"), safe: true,
            out: [
              { k: "sys", d: 3200, text: tx("MERQAB: High risk · look-alike courier domain · payment pressure", "مرقاب: خطر مرتفع · نطاق شحن مقلَّد · ضغط للدفع"), cap: tx("The check takes seconds and explains why.", "الفحص يأخذ ثوانٍ ويشرح السبب.") }],
            verdict: tx("Safe. You checked before you clicked.", "بأمان. فحصت قبل أن تضغط.") }] }],
    rule: tx("Couriers and authorities don’t collect fees through SMS links. Open the official app yourself.", "شركات الشحن والجهات الرسمية لا تحصّل رسوماً عبر روابط الرسائل. افتح التطبيق الرسمي بنفسك."),
  },
  {
    id: "bank", icon: "🏦", tone: "#0369a1", situation: "official", sector: "bank",
    title: tx("“This is your bank’s fraud team”", "«معك فريق الاحتيال في بنكك»"),
    logline: tx("They know your name, your card, your last purchase.", "يعرفون اسمك وبطاقتك وآخر عملية شراء.") ,
    tactics: ["authority_impersonation", "threat_fear", "urgency", "credential_request"],
    beats: [
      { k: "call", d: 2200, name: tx("800 BANK (shown)", "800 BANK (ظاهر)"), cap: tx("Caller ID shows the bank’s name. Caller ID can be faked.", "يظهر اسم البنك في هوية المتصل — ويمكن تزويرها.") },
      { k: "voice", d: 4400, who: tx("“Fraud team”", "«فريق الاحتيال»"), text: tx("Ms Huda, we blocked a suspicious AED 2,950 payment on your card ending 4471.", "أستاذة هدى، أوقفنا عملية مشبوهة بـ2,950 درهم على بطاقتك المنتهية بـ4471."), say: true },
      { k: "voice", d: 4400, who: tx("“Fraud team”", "«فريق الاحتيال»"), text: tx("To cancel it I’m sending a code — read it to me in the next minute, or the payment goes through.", "عشان نلغيها برسل لك رمز — اقرئيه لي خلال دقيقة وإلا العملية بتمر."), say: true },
      { k: "in", d: 2800, from: tx("Bank", "البنك"), text: tx("Your OTP is 772 905. Never share this code with anyone, including bank staff.", "رمز التحقق 772 905. لا تشارك هذا الرمز مع أي أحد، بما في ذلك موظفي البنك."), cap: tx("The SMS itself says: never share it.", "الرسالة نفسها تقول: لا تشاركه.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "read", label: tx("Read the code — they’re protecting me", "أقرأ الرمز — هم يحمونني"), safe: false,
            out: [{ k: "sys", d: 3000, text: tx("New device added to your banking app. Transfer AED 18,400 sent.", "أُضيف جهاز جديد لتطبيق البنك. تم تحويل 18,400 درهم."), cap: tx("The code didn’t cancel anything — it approved their login.", "الرمز لم يلغِ شيئاً — بل وافق على دخولهم.") }],
            verdict: tx("Account taken over. The code was the key they needed.", "تم الاستيلاء على الحساب. الرمز كان المفتاح الذي يحتاجونه.") },
          { id: "hangup", label: tx("Hang up and call the number on my card", "أغلق الخط وأتصل بالرقم خلف بطاقتي"), safe: true,
            out: [{ k: "voice", d: 3400, who: tx("Real bank", "البنك الحقيقي"), text: tx("There is no blocked payment. We never ask for codes by phone.", "لا توجد عملية موقوفة. نحن لا نطلب الرموز بالهاتف أبداً."), say: true }],
            verdict: tx("Safe. You verified through a channel you chose.", "بأمان. تحققت عبر قناة اخترتها أنت.") },
          { id: "quiz", label: tx("Ask them to prove who they are", "أطلب منهم إثبات هويتهم"), safe: false,
            out: [{ k: "voice", d: 3600, who: tx("“Fraud team”", "«فريق الاحتيال»"), text: tx("Of course — your Emirates ID ends 3-1-9 and you live in Khalifa City. Now the code, quickly.", "أكيد — هويتك تنتهي بـ3-1-9 وساكنة في مدينة خليفة. الحين الرمز بسرعة."), say: true }],
            verdict: tx("Risky. Leaked personal data makes them sound real — knowing your details proves nothing.", "خطر. البيانات المسرَّبة تجعلهم يبدون حقيقيين — معرفتهم لبياناتك لا تثبت شيئاً.") }] }],
    rule: tx("No bank ever asks for a code by phone. Hang up and call the number on your card.", "لا يوجد بنك يطلب رمزاً بالهاتف. أغلق الخط واتصل بالرقم الموجود على بطاقتك."),
  },
  {
    id: "invest", icon: "📈", tone: "#7c3aed", situation: "pay", sector: "investment",
    title: tx("30% a day", "30% يومياً"),
    logline: tx("A group full of winners. None of them are real.", "مجموعة مليئة بالرابحين… ولا أحد منهم حقيقي.") ,
    tactics: ["reward_lure", "channel_shift", "urgency", "payment_instruction"],
    beats: [
      { k: "lock", d: 2400, app: "💬", title: tx("“AI Gold Signals VIP”", "«AI Gold Signals VIP»"), body: tx("You were added to the group by +44 7•••", "تمت إضافتك إلى المجموعة بواسطة ‎+44 7•••"), cap: tx("Sara never asked to join.", "سارة لم تطلب الانضمام.") },
      { k: "in", d: 2600, from: tx("Ahmed (member)", "أحمد (عضو)"), text: tx("Withdrew 12,000 today 🙏 thank you coach!", "سحبت 12,000 اليوم 🙏 شكراً يا كوتش!") , cap: tx("Profit screenshots every few minutes.", "صور أرباح كل بضع دقائق.") },
      { k: "in", d: 2600, from: tx("Lina (member)", "لينا (عضوة)"), text: tx("Started with 1,000 last week, now 9,400 😍", "بدأت بـ1,000 الأسبوع الماضي والحين 9,400 😍") },
      { k: "in", d: 3400, from: tx("Coach (admin)", "الكوتش (المشرف)"), text: tx("Only 3 VIP slots left today. Minimum deposit 5,000 USDT via our app 👉 hxxps://ai-gold-pro[.]app", "باقي 3 مقاعد VIP اليوم. أقل إيداع 5,000 USDT عبر تطبيقنا 👉 hxxps://ai-gold-pro[.]app"), cap: tx("Then the pressure: limited slots, today only.", "ثم الضغط: مقاعد محدودة، اليوم فقط.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "test", label: tx("Deposit a small amount to test it", "أودع مبلغاً صغيراً للتجربة"), safe: false,
            out: [
              { k: "sys", d: 2600, text: tx("App balance: 1,000 → 1,480 USDT", "رصيد التطبيق: 1,000 ← 1,480 USDT"), cap: tx("The numbers go up. They are just numbers on a screen.", "الأرقام ترتفع. إنها مجرد أرقام على شاشة.") },
              { k: "sys", d: 3000, text: tx("Withdrawal blocked: pay 20% ‘tax’ first.", "السحب موقوف: ادفع 20% «ضريبة» أولاً."), cap: tx("Then withdrawals need one more payment. And another.", "ثم يحتاج السحب دفعة أخرى. وأخرى.") }],
            verdict: tx("Every deposit is gone. Fake profits are how they get the bigger one.", "كل الإيداعات ضاعت. الأرباح الوهمية هي طريقتهم للحصول على المبلغ الأكبر.") },
          { id: "verify", label: tx("Check if they’re licensed, then leave", "أتحقق من الترخيص ثم أغادر"), safe: true,
            out: [{ k: "sys", d: 3000, text: tx("Not found on the regulator’s licensed list.", "غير موجود في قائمة الجهات المرخَّصة لدى الجهة الرقابية."), cap: tx("Licensed firms don’t recruit in random chat groups.", "الشركات المرخصة لا تجنّد في مجموعات دردشة عشوائية.") }],
            verdict: tx("Safe. You checked the licence and reported the group.", "بأمان. تحققت من الترخيص وأبلغت عن المجموعة.") },
          { id: "ask", label: tx("Ask the members if it’s real", "أسأل الأعضاء إذا كان حقيقياً"), safe: false,
            out: [{ k: "in", d: 3200, from: tx("Ahmed (member)", "أحمد (عضو)"), text: tx("100% real sis, I’m on my 4th withdrawal 🔥", "حقيقي 100% أختي، هذا رابع سحب لي 🔥"), cap: tx("The ‘members’ belong to the scammers too.", "«الأعضاء» تابعون للمحتالين أيضاً.") }],
            verdict: tx("Risky. In these groups, the ‘winners’ are part of the script.", "خطر. في هذه المجموعات «الرابحون» جزء من السيناريو.") }] }],
    rule: tx("Guaranteed high returns plus a deadline is a scam. Check the regulator’s list — never a chat group.", "عوائد مرتفعة مضمونة مع مهلة قصيرة = احتيال. تحقق من قائمة الجهة الرقابية، لا من مجموعة دردشة."),
  },
  {
    id: "police", icon: "🚓", tone: "#334155", situation: "official", sector: "government",
    title: tx("“Your ID has been suspended”", "«تم إيقاف هويتك»"),
    logline: tx("An official tone, a fine, and a two-hour deadline.", "نبرة رسمية، ومخالفة، ومهلة ساعتين.") ,
    tactics: ["authority_impersonation", "threat_fear", "urgency", "link_prompt", "personal_data_request"],
    beats: [
      { k: "lock", d: 2800, app: "✉️", title: tx("UAE-POLICE-NOTICE", "UAE-POLICE-NOTICE"), body: tx("Your Emirates ID is suspended for an unpaid violation (AED 2,500). Pay within 2 hours to avoid arrest: hxxps://moi-ae-pay[.]live", "تم إيقاف هويتك لمخالفة غير مدفوعة (2,500 درهم). ادفع خلال ساعتين لتجنب القبض: hxxps://moi-ae-pay[.]live"), cap: tx("Yousef has never had a violation.", "يوسف لم يرتكب أي مخالفة.") },
      { k: "page", d: 3400, url: "moi-ae-pay[.]live", title: tx("Violation payment", "سداد المخالفة"), fields: [tx("Emirates ID number", "رقم الهوية"), tx("Card number · CVV", "رقم البطاقة · CVV")], cap: tx("The page asks for his ID and his card.", "الصفحة تطلب هويته وبطاقته.") },
      { k: "decide", prompt: tx("What would you do?", "ماذا ستفعل؟"),
        choices: [
          { id: "pay", label: tx("Pay now — I can’t risk arrest", "أدفع الحين — ما أقدر أخاطر بالقبض"), safe: false,
            out: [{ k: "sys", d: 3000, text: tx("Card used abroad 3 times · ID details sold", "استُخدمت البطاقة 3 مرات خارج الدولة · بيعت بيانات الهوية"), cap: tx("Fear made the decision for him.", "الخوف اتخذ القرار عنه.") }],
            verdict: tx("Money and identity stolen. Police don’t threaten arrest by SMS link.", "سُرق المال والهوية. الشرطة لا تهدد بالقبض عبر رابط في رسالة.") },
          { id: "official", label: tx("Check violations in the official app", "أتحقق من المخالفات في التطبيق الرسمي"), safe: true,
            out: [{ k: "sys", d: 3000, text: tx("Official app: “No violations.”", "التطبيق الرسمي: «لا توجد مخالفات».") , cap: tx("Two minutes, no risk.", "دقيقتان، بلا مخاطرة.") }],
            verdict: tx("Safe. You checked through the official channel.", "بأمان. تحققت عبر القناة الرسمية.") },
          { id: "report", label: tx("Report it to Aman / eCrime", "أبلّغ عنه لأمان / الجرائم الإلكترونية"), safe: true,
            out: [{ k: "sys", d: 3000, text: tx("Report received. Thank you for protecting others.", "تم استلام البلاغ. شكراً لحمايتك الآخرين.") }],
            verdict: tx("Safe — and you helped protect others.", "بأمان — وساعدت في حماية غيرك.") }] }],
    rule: tx("Authorities don’t demand payment through links with arrest threats. Check the official app or website yourself.", "الجهات الرسمية لا تطلب الدفع عبر روابط مع تهديد بالقبض. تحقق من التطبيق أو الموقع الرسمي بنفسك."),
  },
];

// which film fits a live threat: social and tech logins → parcel/link pattern; banks → bank; couriers → parcel …
const SECTOR_FILM = { bank: "bank", payment: "bank", courier: "parcel", government: "police", investment: "invest", crypto: "invest", family: "voice" };
export function filmForBrand(brand, sectorHint) {
  const b = (brand || "").toLowerCase();
  if (/dhl|aramex|fedex|ups|emirates ?post|post/.test(b)) return "parcel";
  if (/binance|crypto|coinbase|bybit/.test(b)) return "invest";
  if (/bank|adcb|enbd|fab|mashreq|adib|dib|rak|cbd|paypal|visa|mastercard/.test(b)) return "bank";
  if (/uaepass|moi|police|icp|gov|tamm|dubainow/.test(b)) return "police";
  if (/facebook|instagram|whatsapp|meta|tiktok|snapchat|netflix|apple|google|microsoft|amazon|steam|roblox|outlook|office/.test(b)) return "account";
  return SECTOR_FILM[sectorHint] || "parcel";
}

const RESULTS_KEY = "mirqab.theater";
export function theaterResults() { try { return JSON.parse(localStorage.getItem(RESULTS_KEY) || "{}"); } catch { return {}; } }
function saveResult(id, safe) { const r = theaterResults(); r[id] = { safe, at: Date.now() }; try { localStorage.setItem(RESULTS_KEY, JSON.stringify(r)); } catch {} }

// ------------------------------------------------------------------------------------------------ phone stage
function screenFor(b) {
  switch (b.k) {
    case "lock": return h("div", { class: "ph-lock" }, h("div", { class: "ph-time" }, "22:41"),
      h("div", { class: "ph-notif in" }, h("span", { class: "ph-app" }, b.app), h("div", {}, h("b", {}, ft(b.title)), h("p", { dir: "auto" }, ft(b.body)))));
    case "call": return h("div", { class: "ph-call" }, h("div", { class: "ph-avatar" }, "👤"), h("b", {}, ft(b.name)), h("span", { class: "ph-call-s" }, t("th.calling")),
      h("div", { class: "ph-call-btns" }, h("i", { class: "dec" }, "✕"), h("i", { class: "acc" }, "✆")));
    case "voice": return h("div", { class: "ph-call live" }, h("div", { class: "ph-avatar pulse" }, "👤"), h("b", {}, ft(b.who)), h("span", { class: "ph-call-s" }, "00:" + String(10 + Math.floor(Math.random() * 40))),
      h("div", { class: "ph-wave", "aria-hidden": "true" }, ...Array.from({ length: 22 }, (_, i) => h("i", { style: { "--i": i } }))),
      h("p", { class: "ph-transcript", dir: "auto" }, ft(b.text)));
    case "in": return h("div", { class: "ph-chat" }, h("div", { class: "ph-chat-h" }, h("b", {}, ft(b.from))),
      h("div", { class: "ph-typing", "aria-hidden": "true" }, h("i"), h("i"), h("i")),
      h("div", { class: "ph-bubble", dir: "auto" }, ft(b.text)));
    case "page": return h("div", { class: "ph-page" }, h("div", { class: "ph-url" }, "🔒 ", h("span", { dir: "ltr" }, b.url.replaceAll("{brand}", liveBrand.en.toLowerCase().replace(/\s+/g, "")))),
      h("div", { class: "ph-page-b" }, h("div", { class: "ph-logo" }), h("b", {}, ft(b.title)), ...b.fields.map(f => h("div", { class: "ph-field" }, ft(f))), h("div", { class: "ph-pay" }, t("th.pay_btn"))));
    case "sys": return h("div", { class: "ph-sys" }, h("p", { dir: "auto" }, ft(b.text)));
    default: return h("div");
  }
}

// ------------------------------------------------------------------------------------------------ voice
// Narration uses the browser's built-in voice. speak() resolves when the line has finished, so a film never talks
// over itself.
// ------------------------------------------------------------------------------------------------ player
// tacticByKey: real MERQAB engine taxonomy (from /api/community/shield) used to name what each film demonstrates.
export function theater({ tacticByKey, onDecoder, onPlayed, onStart, onAdvance, films = FILMS }) {
  let film = films[0], idx = 0, phase = "idle", timer = null, beats = [], choice = null, cc = true, countdown = null, token = 0;
  const screen = h("div", { class: "ph-screen", "aria-live": "polite" });
  const caption = h("div", { class: "th-cc", "aria-live": "polite" });
  const overlay = h("div", { class: "th-overlay" });
  const bar = h("div", { class: "th-bar" }, h("i"));
  const playBtn = h("button", { type: "button", class: "th-btn", "aria-label": t("th.play") }, "▶");
  const ccBtn = h("button", { type: "button", class: "th-btn on", "aria-pressed": "true", title: t("th.captions") }, "CC");
  const restartBtn = h("button", { type: "button", class: "th-btn", title: t("th.restart"), "aria-label": t("th.restart") }, "↺");
  const titleEl = h("div", { class: "th-title" });
  const stage = h("div", { class: "th-stage" },
    h("div", { class: "th-glow" }),
    h("div", { class: "th-phone" }, h("div", { class: "ph-notch" }), screen),
    caption, overlay);
  const reel = h("div", { class: "th-reel", role: "tablist", "aria-label": t("th.reel") });
  const debrief = h("div", { class: "th-debrief", "aria-live": "polite" });
  const root = h("div", { class: onAdvance ? "theater th-guided" : "theater" },
    h("div", { class: "th-screen-wrap" }, stage,
      h("div", { class: "th-controls" }, playBtn, restartBtn, bar, ccBtn), titleEl),
    onAdvance ? null : h("div", { class: "th-side" }, reel, debrief));

  function drawReel() {
    if (onAdvance) return;
    const res = theaterResults();
    reel.replaceChildren(...films.map(f => h("button", { type: "button", role: "tab", class: `th-ep ${f.id === film.id ? "on" : ""}`, "aria-selected": String(f.id === film.id),
      style: { "--tone": f.tone }, onclick: () => load(f.id, true) },
      h("span", { class: "th-ep-i" }, f.icon),
      h("span", { class: "th-ep-t" }, h("b", {}, ft(f.title)), h("small", {}, ft(f.logline))),
      res[f.id] ? h("span", { class: `th-ep-r ${res[f.id].safe ? "ok" : "no"}`, title: t(res[f.id].safe ? "th.you_safe" : "th.you_lost") }, res[f.id].safe ? "✓" : "✕") : null)));
  }
  const setControl = (button, icon, fallback) => button.replaceChildren(onAdvance ? awarenessIcon(icon) : fallback);
  if (onAdvance) {
    setControl(restartBtn, "restart", "↺");
  }
  function progress() {
    const pre = film.beats.findIndex(b => b.k === "decide");
    const total = pre + (choice ? choice.out.length : 2);
    const done = phase === "end" ? total : choice ? pre + idx : idx;
    bar.firstChild.style.width = `${Math.min(100, done / total * 100)}%`;
    bar.style.setProperty("--mark", `${pre / total * 100}%`);
  }
  function show(b) {
    const node = screenFor(b);
    screen.replaceChildren(node);
    if (!REDUCED) { node.classList.add("enter"); }
    caption.textContent = cc && b.cap ? ft(b.cap) : "";
    caption.hidden = !caption.textContent;

  }
  function step() {
    clearTimeout(timer);
    if (phase !== "playing") return;
    const b = beats[idx];
    if (!b) return choice ? end() : null;
    if (b.k === "decide") return decide(b);
    const run = ++token;
    show(b);
    progress();
    timer = setTimeout(() => {
      if (run === token && phase === "playing") { idx++; step(); }
    }, REDUCED ? Math.max(1800, b.d) : b.d);
  }
  function decide(b) {
    phase = "deciding"; setControl(playBtn, "play", "▶");
    let left = 12;
    const ring = h("div", { class: "th-count" }, h("b", {}, String(left)));
    const pressure = h("p", { class: "th-pressure", hidden: true }, t("th.pressure"));
    overlay.replaceChildren(h("div", { class: "th-decide" },
      h("div", { class: "th-decide-h" }, onAdvance ? null : ring, h("div", {}, h("div", { class: "th-kicker" }, t("th.paused")), h("b", {}, ft(b.prompt)))),
      h("div", { class: "th-choices" }, ...b.choices.map((c, i) => h("button", { type: "button", class: "th-choice", style: { "--i": i },
        onclick: () => pick(c) }, h("span", {}, String.fromCharCode(65 + i)), ft(c.label)))),
      pressure));
    overlay.classList.add("on");
    overlay.querySelector(".th-choice")?.focus();
    clearInterval(countdown);
    if (onAdvance) return;
    countdown = setInterval(() => {
      left--; ring.firstChild.textContent = String(Math.max(0, left)); ring.style.setProperty("--p", `${(12 - left) / 12 * 100}%`);
      if (left <= 0) { clearInterval(countdown); pressure.hidden = false; ring.classList.add("out"); }
    }, 1000);
  }
  function pick(c) {
    clearInterval(countdown);
    overlay.classList.remove("on"); overlay.replaceChildren();
    choice = c; beats = c.out; idx = 0; phase = "playing"; setControl(playBtn, "pause", "❚❚");
    step();
  }
  function end() {
    phase = "end"; setControl(playBtn, "play", "▶"); progress();
    saveResult(film.id, choice.safe); drawReel(); onPlayed?.();
    const tactics = film.tactics.map(k => tacticByKey[k]).filter(Boolean);
    if (onAdvance) {
      const advance = h("button", { type: "button", class: "btn", onclick: onAdvance },
        t(film === films.at(-1) ? "aw.finish" : "th.next_film"));
      overlay.replaceChildren(h("section", { class: `th-recap ${choice.safe ? "ok" : "no"}` },
        h("div", { class: "th-kicker" }, t(choice.safe ? "th.you_safe" : "th.you_lost")),
        h("h2", {}, ft(choice.verdict)),
        h("p", {}, ft(film.rule)),
        tactics.length ? h("div", { class: "th-tac-chips" }, ...tactics.map(tc => h("span", { title: L(tc, "explain") }, L(tc, "label")))) : null,
        h("div", { class: "th-next" }, advance,
          h("button", { type: "button", class: "btn secondary", onclick: () => load(film.id, true) }, t("th.try_other")))));
      overlay.classList.add("on");
      advance.focus({ preventScroll: true });
      return;
    }

    overlay.replaceChildren(h("div", { class: `th-end ${choice.safe ? "ok" : "no"}` }, h("span", {}, choice.safe ? "🛡️" : "⚠️"), h("b", {}, ft(choice.verdict))));
    overlay.classList.add("on");
    debrief.replaceChildren(...[
      h("div", { class: `th-verdict ${choice.safe ? "ok" : "no"}` }, h("div", { class: "th-kicker" }, t(choice.safe ? "th.you_safe" : "th.you_lost")), h("p", {}, ft(choice.verdict))),
      h("div", { class: "th-rule" }, h("div", { class: "th-kicker" }, t("th.rule")), h("p", {}, ft(film.rule))),
      tactics.length ? h("div", { class: "th-tactics" }, h("div", { class: "th-kicker" }, t("th.tactics")),
        h("div", { class: "th-tac-chips" }, ...tactics.map(tc => h("span", { title: L(tc, "explain") }, L(tc, "label"))))) : null,
      h("div", { class: "th-next" },
        h("button", { type: "button", class: "btn sm", onclick: () => { const n = films[(films.indexOf(film) + 1) % films.length]; load(n.id, true); } }, t("th.next_film")),
        h("button", { type: "button", class: "btn ghost sm", onclick: () => load(film.id, true) }, t("th.try_other")),
        onDecoder ? h("button", { type: "button", class: "btn ghost sm", onclick: () => onDecoder(film.situation) }, t("th.real_life")) : null)].filter(Boolean));
  }
  function load(id, autoplay) {
    clearTimeout(timer); clearInterval(countdown); token++;
    film = films.find(f => f.id === id) || films[0];
    idx = 0; choice = null; beats = film.beats; phase = "idle";
    stage.style.setProperty("--tone", film.tone);
    setControl(playBtn, "play", "▶");
    playBtn.setAttribute("aria-label", t("th.play"));
    titleEl.replaceChildren(h("b", {}, ft(film.title)), ...(!onAdvance ? [h("span", { class: "small" }, ft(film.logline))] : []));
    overlay.replaceChildren(h("button", { type: "button", class: "th-poster", onclick: () => play() },
      h("span", { class: "th-poster-i" }, onAdvance ? awarenessIcon(({ clue: "search", voice: "call", parcel: "parcel", "family-plan": "family", response: "shield", "community-report": "report" })[film.id]) : film.icon), h("b", {}, ft(film.title)), h("span", {}, ft(film.logline)), h("span", { class: "th-poster-play" }, "▶ ", t("th.watch"))));
    overlay.classList.add("on");
    screen.replaceChildren(h("div", { class: "ph-lock idle" }, h("div", { class: "ph-time" }, "22:40")));
    caption.hidden = true;
    debrief.replaceChildren(h("p", { class: "th-hint" }, t("th.hint")));
    drawReel(); progress();
    if (autoplay) play();
  }
  function play() {
    if (phase === "end") return load(film.id, true);
    if (phase === "deciding") return;
    overlay.classList.remove("on"); overlay.replaceChildren();
    onStart?.();
    phase = "playing"; setControl(playBtn, "pause", "❚❚"); playBtn.setAttribute("aria-label", t("th.pause"));
    step();
  }
  function pause() { if (phase !== "playing") return; phase = "paused"; token++; clearTimeout(timer); setControl(playBtn, "play", "▶"); playBtn.setAttribute("aria-label", t("th.play")); }
  playBtn.addEventListener("click", () => phase === "playing" ? pause() : play());
  restartBtn.addEventListener("click", () => load(film.id, true));
  ccBtn.addEventListener("click", () => { cc = !cc; ccBtn.classList.toggle("on", cc); ccBtn.setAttribute("aria-pressed", String(cc)); if (!cc) caption.hidden = true; });
  stage.addEventListener("keydown", (e) => { if (e.key === " " && phase !== "deciding") { e.preventDefault(); phase === "playing" ? pause() : play(); } });
  stage.tabIndex = 0;
  load(film.id, false);
  return { node: root, load, stop: () => { token++; clearTimeout(timer); clearInterval(countdown); } };
}
