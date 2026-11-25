// Admin-only console: sends a clearly labelled DEMO alert to devices whose owners opted in.
// Signing in uses the normal MERQAB staff login; the server checks the admin role on every call.
import { api, h, loadLang, setSession, state, toast } from "./core.js";

const root = () => document.getElementById("adm");

function loginView() {
  const u = h("input", { id: "au", autocomplete: "username", required: true, maxlength: "64" });
  const p = h("input", { id: "ap", type: "password", autocomplete: "current-password", required: true, maxlength: "200" });
  const msg = h("p", { class: "small", role: "alert" });
  const f = h("form", { class: "sh-card adm-card" },
    h("img", { src: "/assets/logo-mark.png", width: "44", height: "44", alt: "" }), h("h1", {}, "Demo alert console"),
    h("p", { class: "muted" }, "Administrators only. Alerts go only to phones that ticked “Allow demonstration alerts”, and are always labelled [DEMO]."),
    h("label", { for: "au" }, "Username"), u, h("label", { for: "ap" }, "Password"), p,
    h("button", { class: "btn lg", type: "submit" }, "Sign in"), msg);
  f.addEventListener("submit", async (e) => {
    e.preventDefault(); msg.textContent = "";
    try {
      const r = await api("/auth/login", { method: "POST", body: { username: u.value.trim(), password: p.value } });
      p.value = "";
      if (r.user.role !== "admin") { msg.textContent = "This account is not an administrator."; return; }
      setSession(r); consoleView();
    } catch (err) { msg.textContent = err.message; }
  });
  root().replaceChildren(f);
}

async function consoleView() {
  let st;
  try { st = await api("/push/stats"); } catch (e) { setSession(null); return loginView(); }
  const fields = {
    title_en: h("input", { maxlength: "80", value: "Fake bank SMS circulating" }),
    title_ar: h("input", { maxlength: "80", dir: "rtl", value: "رسائل بنك مزيّفة متداولة" }),
    body_en: h("textarea", { maxlength: "220", rows: "3" }, "Messages claim your card is blocked and ask you to open a link. Banks never ask for codes by SMS."),
    body_ar: h("textarea", { maxlength: "220", rows: "3", dir: "rtl" }, "رسائل تدّعي إيقاف بطاقتك وتطلب فتح رابط. البنوك لا تطلب الرموز عبر الرسائل."),
  };
  const send = h("button", { class: "btn lg", type: "submit" }, `Send DEMO alert to ${st.demo_consent} opted-in device(s)`);
  const f = h("form", { class: "sh-card adm-card" },
    h("div", { class: "cm-kicker" }, "Signed in as " + state.user.username),
    h("h1", {}, "Send a demonstration alert"),
    h("div", { class: "sh-stats" }, h("div", { class: "sh-stat low" }, h("b", {}, String(st.devices)), h("small", {}, "registered devices")),
      h("div", { class: "sh-stat medium" }, h("b", {}, String(st.demo_consent)), h("small", {}, "opted in to demo"))),
    h("p", { class: "small muted" }, "Phones receive “[DEMO] …” or “[تجريبي] …” in their own language, with “Demonstration alert, not a real threat.” appended."),
    h("label", {}, "Title (English)"), fields.title_en, h("label", {}, "Title (Arabic)"), fields.title_ar,
    h("label", {}, "Message (English)"), fields.body_en, h("label", {}, "Message (Arabic)"), fields.body_ar,
    send,
    h("h2", {}, "Recent pushes"),
    h("ul", { class: "sh-feed" }, ...st.log.map((x) => h("li", { class: `k-${x.kind}` }, h("b", {}, `${x.kind} · ${x.title || ""}`),
      h("p", {}, `sent ${x.sent} · failed ${x.failed} · expired removed ${x.removed}${x.actor ? " · by " + x.actor : ""}`), h("time", {}, x.ts)))),
    h("button", { class: "btn secondary", type: "button", onclick: () => { setSession(null); loginView(); } }, "Sign out"));
  f.addEventListener("submit", async (e) => {
    e.preventDefault(); send.disabled = true;
    try {
      const body = Object.fromEntries(Object.entries(fields).map(([k, el]) => [k, el.value.trim()]));
      const r = await api("/push/demo", { method: "POST", body });
      toast(`Delivered to ${r.sent} of ${r.devices} device(s)`); setTimeout(consoleView, 800);
    } catch (err) { toast(err.message); send.disabled = false; }
  });
  root().replaceChildren(f);
}

(async () => {
  await loadLang("en");
  document.documentElement.classList.add("dark");
  state.token ? consoleView() : loginView();
})();
