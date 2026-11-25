// MERQAB Mobile Shield: install + activation, real permission states, Web Push, protection dashboard,
// local threat history and the Live Call Guardian.
// Honesty rules: every status shown here is read from the browser/OS or the server at render time. Nothing is
// simulated; anything the web platform cannot do is labelled "unavailable" or "native app (roadmap)".
import { h, state, t, toast, L } from "./core.js";

// ------------------------------------------------------------------------------------------------ environment
const ua = navigator.userAgent;
export const env = {
  ios: /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1),
  android: /Android/i.test(ua),
  standalone: () => window.navigator.standalone === true || matchMedia("(display-mode: standalone)").matches,
  secure: window.isSecureContext,
  sw: "serviceWorker" in navigator,
  push: "PushManager" in window && "Notification" in window,
  speech: !!(window.SpeechRecognition || window.webkitSpeechRecognition),
  media: !!navigator.mediaDevices?.getUserMedia,
  recorder: "MediaRecorder" in window,
  vibrate: "vibrate" in navigator,
  geo: "geolocation" in navigator,
};
const platform = () => (env.ios ? "ios" : env.android ? "android" : /Mobi/.test(ua) ? "other" : "desktop");

// ------------------------------------------------------------------------------------------------ local state
const LS = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};
const DEV = "mirqab.device", HIST = "mirqab.history", LIVE = "mirqab.liveInbox";

/** Every check made on this phone is kept on this phone only (never uploaded) for the threat history. */
export function addHistory(entry) {
  const hst = LS.get(HIST, []);
  hst.unshift({ ts: new Date().toISOString(), ...entry });
  LS.set(HIST, hst.slice(0, 60));
}

// ------------------------------------------------------------------------------------------------ service worker
let swReg = null;
export async function registerSW() {
  if (!env.sw || !env.secure) return null;
  try {
    swReg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    navigator.serviceWorker.addEventListener("message", (e) => {
      if (e.data?.type !== "mirqab-push") return;
      const inbox = LS.get(LIVE, []);
      inbox.unshift({ ts: e.data.ts || new Date().toISOString(), title: e.data.title, body: e.data.body, kind: e.data.kind, url: e.data.url });
      LS.set(LIVE, inbox.slice(0, 30));
      toast(e.data.title);
      document.dispatchEvent(new CustomEvent("mirqab-push"));
    });
  } catch { swReg = null; }
  return swReg;
}

async function deviceApi(path, { method = "GET", body } = {}) {
  const dev = LS.get(DEV, null);
  const headers = { "Content-Type": "application/json" };
  if (dev?.token) headers["X-Device-Token"] = dev.token;
  const r = await fetch(`/api${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  if (!r.ok) { const e = new Error(j?.detail || t("err.generic")); e.status = r.status; throw e; }
  return j;
}

// ------------------------------------------------------------------------------------------------ permissions
async function permState(name) {
  try { return (await navigator.permissions.query({ name })).state; } catch { return "unknown"; }
}
export async function readPermissions() {
  return {
    notifications: "Notification" in window ? (Notification.permission === "default" ? "prompt" : Notification.permission === "granted" ? "granted" : "denied") : "unsupported",
    microphone: env.media ? await permState("microphone") : "unsupported",
    camera: env.media ? await permState("camera") : "unsupported",
    geolocation: env.geo ? await permState("geolocation") : "unsupported",
  };
}

function b64ToBytes(b64) {
  const p = "=".repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + p).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

// Must run inside a tap (iOS requires a user gesture for the permission prompt).
export async function activatePush({ demo = false, topics = ["alerts", "campaigns"] } = {}) {
  if (!env.secure) throw new Error(t("sh.err_https"));
  if (env.ios && !env.standalone()) throw new Error(t("sh.err_install_first"));
  if (!env.push) throw new Error(t("sh.err_no_push"));
  const cfg = await (await fetch("/api/push/config")).json();
  if (!cfg.available) throw new Error(t("sh.err_server_push"));
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error(t("sh.err_denied"));
  const reg = swReg || (await registerSW()) || (await navigator.serviceWorker.ready);
  let sub = await reg.pushManager.getSubscription();
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(cfg.public_key) });
  const j = sub.toJSON();
  const lang = ["ar", "en", "ur", "hi", "tl", "zh", "fr", "es", "ru"].includes(state.lang) ? state.lang : "en";
  const r = await deviceApi("/devices", { method: "POST", body: { subscription: { endpoint: j.endpoint, keys: j.keys }, lang, topics, demo_consent: demo, platform: platform() } });
  LS.set(DEV, { token: r.device_token, id: r.device.id });
  return r.device;
}

async function disconnectDevice() {
  try { await deviceApi("/devices/me", { method: "DELETE" }); } catch {}
  try { const reg = swReg || (await navigator.serviceWorker.getRegistration()); const s = await reg?.pushManager.getSubscription(); await s?.unsubscribe(); } catch {}
  LS.del(DEV); LS.del(LIVE);
}

// ------------------------------------------------------------------------------------------------ page
let stopFns = [];
export function stopShield() { stopFns.forEach((f) => { try { f(); } catch {} }); stopFns = []; }

export async function shieldPage(view, sub) {
  stopShield();
  if (sub === "call") return callGuardian(view);
  const root = h("div", { class: "sh" });
  view.replaceChildren(root);
  const draw = async () => {
    const perms = await readPermissions();
    let device = null, inbox = [], devErr = null;
    if (LS.get(DEV, null)) {
      try { const r = await deviceApi("/devices/me"); device = r.device; inbox = r.inbox; }
      catch (e) { if (e.status === 401) LS.del(DEV); else devErr = e.message; }
    }
    let info = {}; try { info = await (await fetch("/api/shield/info")).json(); } catch {}
    let alerts = []; try { alerts = (await (await fetch("/api/community/alerts")).json()).alerts || []; } catch {}
    root.replaceChildren(...[
      hero(device, perms, info),
      !device ? activation(info, perms, draw) : null,
      capabilities(device, perms, info),
      guardianLauncher(),
      device ? controls(device, draw) : null,
      permissionsPanel(perms, draw),
      liveAlerts(inbox, alerts, device),
      history(),
      roadmap(),
      devErr ? h("p", { class: "notice warn" }, devErr) : null,
    ].filter(Boolean));
  };
  const onPush = () => draw();
  document.addEventListener("mirqab-push", onPush);
  stopFns.push(() => document.removeEventListener("mirqab-push", onPush));
  await draw();
}

function hero(device, perms, info) {
  const active = !!device && perms.notifications === "granted";
  const lvl = active ? "on" : device ? "partial" : "off";
  return h("section", { class: `sh-hero ${lvl}` },
    h("div", { class: "sh-core", "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("img", { src: "/assets/logo-mark.png", alt: "" })),
    h("div", { class: "sh-hero-txt" },
      h("div", { class: "cm-kicker" }, t("sh.kicker")),
      h("h1", {}, t(`sh.state_${lvl}`)),
      h("p", {}, t(`sh.state_${lvl}_sub`)),
      h("div", { class: "sh-chips" },
        chip(env.standalone() ? "ok" : "off", env.standalone() ? t("sh.c_installed") : t("sh.c_browser")),
        chip(device ? "ok" : "off", device ? `${t("sh.c_device")} · ${device.id}` : t("sh.c_no_device")),
        chip(perms.notifications === "granted" ? "ok" : perms.notifications === "denied" ? "bad" : "off", `${t("sh.p_notifications")}: ${t(`sh.ps_${perms.notifications}`)}`),
        chip(info.https ? "ok" : "bad", info.https ? "HTTPS" : t("sh.c_not_https")))));
}
const chip = (kind, text) => h("span", { class: `sh-chip ${kind}` }, text);

function activation(info, perms, redraw) {
  const box = h("section", { class: "sh-card sh-activate" });
  const desktop = !env.ios && !env.android && !/Mobi/.test(ua);
  // A QR code only helps when a phone can reach the address: never for localhost / 127.0.0.1
  const local = /^(localhost|127\.|\[?::1\]?)/.test(location.hostname) || /\/\/(localhost|127\.)/.test(info.url || "");
  const qrImg = h("img", { src: "/api/qr.svg?path=" + encodeURIComponent("/#/shield"), alt: t("sh.qr_alt"), width: "180", height: "180" });
  const qr = local ? h("p", { class: "notice small" }, t("sh.qr_local"))
    : h("figure", { class: "sh-qr" }, qrImg, h("figcaption", {}, t("sh.qr_caption"), h("br"), h("b", { dir: "ltr" }, info.url || location.origin)));
  qrImg.addEventListener("error", () => qr.replaceWith(h("p", { class: "notice small" }, t("sh.qr_unavailable"))));
  if (env.ios && !env.standalone()) {
    box.append(h("h2", {}, t("sh.install_title")), h("p", { class: "muted" }, t("sh.install_sub")),
      h("ol", { class: "sh-steps" },
        h("li", {}, h("span", { class: "sh-ios-share", "aria-hidden": "true" }), t("sh.install_1")),
        h("li", {}, h("span", { class: "sh-ios-add", "aria-hidden": "true" }, "+"), t("sh.install_2")),
        h("li", {}, h("img", { src: "/assets/icons/icon-192.png", alt: "", width: "28", height: "28" }), t("sh.install_3"))),
      h("p", { class: "small muted" }, t("sh.install_note")));
    return box;
  }
  const demo = h("input", { type: "checkbox", id: "sh-demo" });
  const uae = h("input", { type: "checkbox", id: "sh-uae" });
  const btn = h("button", { class: "btn lg sh-go", type: "button" }, t("sh.activate"));
  const msg = h("p", { class: "small", role: "status" });
  btn.addEventListener("click", async () => {
    btn.disabled = true; msg.textContent = t("sh.activating");
    try {
      const topics = ["alerts", "campaigns"];
      if (uae.checked && (await uaeFromLocation())) topics.push("uae");
      await activatePush({ demo: demo.checked, topics });
      toast(t("sh.activated")); await redraw();
      try { await deviceApi("/devices/me/test", { method: "POST" }); } catch {}
    } catch (e) { msg.textContent = e.message; msg.className = "small notice warn"; btn.disabled = false; }
  });
  box.append(
    h("h2", {}, t("sh.activate_title")), h("p", { class: "muted" }, t("sh.activate_sub")),
    h("ul", { class: "sh-consent" },
      h("li", {}, t("sh.consent_push")), h("li", {}, t("sh.consent_data")), h("li", {}, t("sh.consent_revoke"))),
    h("label", { class: "sh-opt", for: "sh-uae" }, uae, h("span", {}, h("b", {}, t("sh.opt_uae")), h("small", {}, t("sh.opt_uae_sub")))),
    h("label", { class: "sh-opt", for: "sh-demo" }, demo, h("span", {}, h("b", {}, t("sh.opt_demo")), h("small", {}, t("sh.opt_demo_sub")))),
    btn, msg, desktop ? qr : null);
  if (!env.push || !env.secure) btn.disabled = true, msg.textContent = !env.secure ? t("sh.err_https") : t("sh.err_no_push");
  return box;
}

// Location is used once, on this phone, only to decide "inside the UAE or not". Coordinates are never sent.
async function uaeFromLocation() {
  if (!env.geo) return false;
  try {
    const p = await new Promise((res, rej) => navigator.geolocation.getCurrentPosition(res, rej, { maximumAge: 3600e3, timeout: 10000, enableHighAccuracy: false }));
    const { latitude: la, longitude: lo } = p.coords;
    const inUae = la > 22.4 && la < 26.4 && lo > 51 && lo < 56.6;
    LS.set("mirqab.region", inUae ? "uae" : "other");
    return inUae;
  } catch { return false; }
}

function capabilities(device, perms, info) {
  const push = device && perms.notifications === "granted";
  const caps = [
    ["msg", "active", "sh.cap_msg", "sh.cap_msg_sub", "#/home"],
    ["call", env.media && (env.speech || info.stt_server) ? (perms.microphone === "granted" ? "active" : "ready") : "unavailable", "sh.cap_call",
      env.speech ? "sh.cap_call_sub" : info.stt_server ? "sh.cap_call_sub_server" : "sh.cap_call_sub_none", "#/shield/call"],
    ["push", push ? "active" : env.push && env.secure && (!env.ios || env.standalone()) ? "ready" : "unavailable", "sh.cap_push",
      env.ios && !env.standalone() ? "sh.cap_push_sub_install" : "sh.cap_push_sub"],
    ["camp", push && device.topics.includes("campaigns") ? "active" : push ? "off" : "ready", "sh.cap_camp", "sh.cap_camp_sub"],
    ["uae", push && device.topics.includes("uae") ? "active" : "off", "sh.cap_uae", "sh.cap_uae_sub"],
    ["ai", info.ai_layer ? "active" : "off", "sh.cap_ai", info.ai_layer ? "sh.cap_ai_sub_on" : "sh.cap_ai_sub_off"],
    ["cell", "unavailable", "sh.cap_cell", "sh.cap_cell_sub"],
    ["sms", "future", "sh.cap_sms", "sh.cap_sms_sub"],
    ["callerid", "future", "sh.cap_callerid", "sh.cap_callerid_sub"],
    ["safari", "future", "sh.cap_safari", "sh.cap_safari_sub"],
  ];
  return h("section", { class: "sh-card" },
    h("div", { class: "cm-kicker" }, t("sh.caps_kicker")), h("h2", {}, t("sh.caps_title")),
    h("div", { class: "sh-legend" }, ...["active", "ready", "off", "unavailable", "future"].map((s) => h("span", { class: `sh-st ${s}` }, t(`sh.st_${s}`)))),
    h("div", { class: "sh-caps" }, ...caps.map(([k, st, title, sub, href]) => h(href ? "a" : "div", { class: `sh-cap ${st}`, href: href || null },
      h("span", { class: `sh-st ${st}` }, t(`sh.st_${st}`)), h("b", {}, t(title)), h("small", {}, t(sub))))));
}

function guardianLauncher() {
  return h("a", { class: "sh-guard-cta", href: "#/shield/call" },
    h("span", { class: "sh-wave", "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("i"), h("i")),
    h("span", {}, h("b", {}, t("sh.guard_cta")), h("small", {}, t("sh.guard_cta_sub"))), h("span", { class: "sh-arrow", "aria-hidden": "true" }, "›"));
}

function controls(device, redraw) {
  const topicBox = (k) => {
    const c = h("input", { type: "checkbox", checked: device.topics.includes(k) });
    c.addEventListener("change", async () => {
      const set = new Set(device.topics); c.checked ? set.add(k) : set.delete(k);
      if (k === "uae" && c.checked && !(await uaeFromLocation())) { c.checked = false; toast(t("sh.uae_not_detected")); return; }
      try { await deviceApi("/devices/me", { method: "PATCH", body: k === "demo" ? { demo_consent: c.checked } : { topics: [...set] } }); toast(t("sh.saved")); redraw(); }
      catch (e) { c.checked = !c.checked; toast(e.message); }
    });
    return h("label", { class: "sh-opt" }, c, h("span", {}, h("b", {}, t(`sh.topic_${k}`)), h("small", {}, t(`sh.topic_${k}_sub`))));
  };
  const test = h("button", { class: "btn", type: "button" }, t("sh.test"));
  test.addEventListener("click", async () => {
    test.disabled = true;
    try { await deviceApi("/devices/me/test", { method: "POST" }); toast(t("sh.test_sent")); setTimeout(redraw, 2500); }
    catch (e) { toast(e.status === 429 ? t("sh.test_wait") : e.message); }
    finally { setTimeout(() => (test.disabled = false), 4000); }
  });
  const off = h("button", { class: "btn secondary", type: "button" }, t("sh.disconnect"));
  off.addEventListener("click", async () => {
    if (!off.dataset.sure) { off.dataset.sure = "1"; off.textContent = t("sh.disconnect_sure"); return; }
    await disconnectDevice(); toast(t("sh.disconnected")); redraw();
  });
  return h("section", { class: "sh-card" },
    h("div", { class: "cm-kicker" }, t("sh.notif_kicker")), h("h2", {}, t("sh.notif_title")),
    h("div", { class: "sh-row" }, test, h("span", { class: "small muted" }, t("sh.test_sub"))),
    topicBox("alerts"), topicBox("campaigns"), topicBox("uae"), topicBox("demo"),
    h("div", { class: "sh-row sh-danger" }, off, h("span", { class: "small muted" }, t("sh.disconnect_sub"))));
}

function permissionsPanel(perms, redraw) {
  const ask = {
    notifications: null,   // asked during activation (needs the service worker + subscription)
    microphone: async () => { const s = await navigator.mediaDevices.getUserMedia({ audio: true }); s.getTracks().forEach((x) => x.stop()); },
    camera: async () => { const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }); s.getTracks().forEach((x) => x.stop()); },
    geolocation: async () => { await uaeFromLocation(); },
  };
  return h("section", { class: "sh-card" },
    h("div", { class: "cm-kicker" }, t("sh.perm_kicker")), h("h2", {}, t("sh.perm_title")),
    h("div", { class: "sh-perms" }, ...Object.entries(perms).map(([k, st]) => {
      const b = ask[k] && st === "prompt" ? h("button", { class: "btn secondary sm", type: "button" }, t("sh.allow")) : null;
      b?.addEventListener("click", async () => { try { await ask[k](); } catch {} redraw(); });
      return h("div", { class: `sh-perm ${st}` }, h("b", {}, t(`sh.p_${k}`)), h("span", { class: `sh-st ${st === "granted" ? "active" : st === "denied" ? "unavailable" : "off"}` }, t(`sh.ps_${st}`)),
        h("small", {}, t(`sh.pu_${k}`)), b);
    })),
    h("p", { class: "small muted" }, t(env.ios ? "sh.revoke_ios" : "sh.revoke_other")));
}

function liveAlerts(inbox, alerts, device) {
  const local = LS.get(LIVE, []);
  const items = [...(inbox || []).map((x) => ({ ...x, src: "push" })), ...local.filter((l) => !(inbox || []).some((x) => x.title === l.title && x.ts === l.ts)).map((x) => ({ ...x, src: "push" }))]
    .sort((a, b) => (b.ts || "").localeCompare(a.ts || "")).slice(0, 12);
  return h("section", { class: "sh-card" },
    h("div", { class: "cm-kicker" }, t("sh.alerts_kicker")), h("h2", {}, t("sh.alerts_title")),
    items.length ? h("ul", { class: "sh-feed" }, ...items.map((x) => h("li", { class: `k-${x.kind}` },
      h("span", { class: "sh-tag" }, t(`sh.kind_${x.kind}`)), h("b", {}, x.title), h("p", {}, x.body), h("time", {}, new Date(x.ts).toLocaleString(state.lang)))))
      : h("p", { class: "muted small" }, device ? t("sh.alerts_none") : t("sh.alerts_none_off")),
    alerts.length ? h("div", {}, h("h3", {}, t("sh.verified_title")),
      h("ul", { class: "sh-feed" }, ...alerts.slice(0, 5).map((a) => h("li", { class: "k-alert" },
        h("span", { class: "sh-tag" }, t("sh.kind_alert")), h("b", {}, L(a, "title")), h("p", {}, L(a, "summary")))))) : null);
}

function history() {
  const hst = LS.get(HIST, []);
  const clear = h("button", { class: "btn secondary sm", type: "button" }, t("sh.hist_clear"));
  clear.addEventListener("click", () => { LS.del(HIST); clear.closest("section").replaceWith(history()); });
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  hst.forEach((x) => (counts[x.level] = (counts[x.level] || 0) + 1));
  return h("section", { class: "sh-card" },
    h("div", { class: "cm-kicker" }, t("sh.hist_kicker")), h("h2", {}, t("sh.hist_title")),
    h("div", { class: "sh-stats" }, ...["critical", "high", "medium", "low"].map((k) => h("div", { class: `sh-stat ${k}` }, h("b", {}, String(counts[k] || 0)), h("small", {}, t(`sh.lvl_${k}`))))),
    hst.length ? h("ul", { class: "sh-hist" }, ...hst.slice(0, 15).map((x) => h("li", { class: x.level },
      h("span", { class: "sh-dot" }), h("div", {}, h("b", {}, t(`sh.src_${x.source}`) + " · " + t(`sh.lvl_${x.level}`) + ` (${x.score})`),
        h("small", {}, [x.label, new Date(x.ts).toLocaleString(state.lang)].filter(Boolean).join(" · "))))))
      : h("p", { class: "muted small" }, t("sh.hist_none")),
    h("div", { class: "sh-row" }, clear, h("span", { class: "small muted" }, t("sh.hist_private"))));
}

function roadmap() {
  return h("details", { class: "sh-card sh-road" }, h("summary", {}, h("b", {}, t("sh.road_title")), h("small", {}, t("sh.road_sub"))),
    h("ul", {}, ...["sms", "callerid", "safari", "callaudio", "background"].map((k) => h("li", {}, h("b", {}, t(`sh.road_${k}`)), h("small", {}, t(`sh.road_${k}_sub`))))));
}

// ------------------------------------------------------------------------------------------------ Live Call Guardian
function callGuardian(view) {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  let lang = state.lang === "ar" ? "ar-AE" : "en-US";
  let running = false, rec = null, stream = null, actx = null, meterRaf = 0, finals = "", interim = "", lastSent = "", sendTimer = 0;
  let maxScore = 0, lastLevel = "low", tactics = new Map(), mediaRec = null, srFailed = false;
  const LEVELS = ["low", "medium", "high", "critical"];

  const gauge = h("div", { class: "cg-gauge low" }, h("b", {}, "0"), h("small", {}, t("sh.lvl_low")));
  const status = h("p", { class: "cg-status", role: "status" }, t("sh.cg_idle"));
  const meter = h("div", { class: "cg-meter", "aria-hidden": "true" }, ...Array.from({ length: 24 }, () => h("i")));
  const transcript = h("div", { class: "cg-transcript", "aria-live": "polite", dir: "auto" }, h("span", { class: "muted" }, t("sh.cg_transcript_ph")));
  const tacticList = h("div", { class: "cg-tactics" });
  const advice = h("div", { class: "cg-advice", hidden: true });
  const flash = h("div", { class: "cg-flash", hidden: true, "aria-hidden": "true" });
  const typed = h("textarea", { class: "cg-typed", dir: "auto", rows: "2", placeholder: t("sh.cg_typed_ph"), hidden: true });
  const langSel = h("div", { class: "seg cg-lang", role: "tablist" });
  const drawLang = () => langSel.replaceChildren(...[["ar-AE", "العربية / الإماراتية"], ["en-US", "English"]].map(([v, n]) =>
    h("button", { type: "button", role: "tab", "aria-selected": String(v === lang), disabled: running, onclick: () => { lang = v; drawLang(); } }, n)));
  drawLang();
  const startBtn = h("button", { class: "btn lg cg-start", type: "button" }, t("sh.cg_start"));
  const consent = h("input", { type: "checkbox", id: "cg-consent" });

  function setRisk(r) {
    const lvl = r.risk.level, score = r.risk.score;
    gauge.className = `cg-gauge ${lvl}`;
    gauge.style.setProperty("--p", String(score));
    gauge.replaceChildren(h("b", {}, String(score)), h("small", {}, t(`sh.lvl_${lvl}`)));
    for (const tc of r.tactics) if (!tactics.has(tc.key)) tactics.set(tc.key, tc);
    tacticList.replaceChildren(...[...tactics.values()].map((tc) => h("span", { class: "cg-tac" }, h("b", {}, L(tc)), tc.quote ? h("q", { dir: "auto" }, tc.quote) : null)));
    const p = r.intervention?.primary;
    if (p && LEVELS.indexOf(lvl) >= 2) { advice.hidden = false; advice.replaceChildren(h("b", {}, L(p)), ...(p.do_now || []).slice(0, 3).map((d) => h("p", {}, L(d)))); }
    if (LEVELS.indexOf(lvl) > LEVELS.indexOf(lastLevel) && LEVELS.indexOf(lvl) >= 2) warn(lvl);
    lastLevel = LEVELS.indexOf(lvl) > LEVELS.indexOf(lastLevel) ? lvl : lastLevel;
    maxScore = Math.max(maxScore, score);
  }

  function warn(lvl) {
    flash.hidden = false; flash.className = `cg-flash ${lvl}`; setTimeout(() => (flash.hidden = true), 1600);
    if (env.vibrate) navigator.vibrate(lvl === "critical" ? [300, 120, 300, 120, 300] : [250, 120, 250]);
    try {   // audible alarm through the audio context unlocked by the Start tap
      const ctx = actx || new (window.AudioContext || window.webkitAudioContext)();
      [0, 0.28, 0.56].forEach((d) => {
        const o = ctx.createOscillator(), g = ctx.createGain();
        o.frequency.value = lvl === "critical" ? 980 : 760; o.type = "square";
        g.gain.setValueAtTime(0.0001, ctx.currentTime + d); g.gain.exponentialRampToValueAtTime(0.25, ctx.currentTime + d + 0.02);
        g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + d + 0.22);
        o.connect(g).connect(ctx.destination); o.start(ctx.currentTime + d); o.stop(ctx.currentTime + d + 0.24);
      });
    } catch {}
    status.textContent = t(lvl === "critical" ? "sh.cg_warn_critical" : "sh.cg_warn_high");
  }

  async function analyzeNow() {
    const text = (finals + " " + interim).trim();
    if (!text || text === lastSent) return;
    lastSent = text;
    try {
      const r = await fetch("/api/guardian/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ transcript: text, lang: lang.startsWith("ar") ? "ar" : "en" }) });
      if (r.status === 429) { status.textContent = t("sh.cg_slow"); return; }
      if (!r.ok) throw new Error();
      if (running) setRisk(await r.json());
    } catch { status.textContent = t("sh.cg_net"); }
  }
  const schedule = (ms = 900) => { clearTimeout(sendTimer); sendTimer = setTimeout(analyzeNow, ms); };

  function showTranscript() {
    transcript.replaceChildren(...[h("span", {}, finals), interim ? h("span", { class: "cg-interim" }, " " + interim) : null].filter(Boolean));
    transcript.scrollTop = transcript.scrollHeight;
  }

  function startRecognition() {
    rec = new SR();
    rec.lang = lang; rec.continuous = true; rec.interimResults = true; rec.maxAlternatives = 1;
    rec.onresult = (e) => {
      interim = "";
      for (let i = e.resultIndex; i < e.results.length; i++) {
        const tx = e.results[i][0].transcript;
        if (e.results[i].isFinal) { finals = (finals + " " + tx).trim(); schedule(150); } else interim += tx;
      }
      showTranscript(); if (interim) schedule(1200);
    };
    rec.onerror = (e) => {
      if (e.error === "not-allowed" || e.error === "service-not-allowed") { srFailed = true; status.textContent = t("sh.cg_sr_denied"); fallbackInput(); }
      else if (e.error === "network") status.textContent = t("sh.cg_net");
    };
    rec.onend = () => { if (running && !srFailed) { try { rec.start(); } catch {} } };   // iOS stops after silence: keep listening
    rec.start();
  }

  function fallbackInput() { typed.hidden = false; typed.focus(); }
  typed.addEventListener("input", () => { finals = typed.value; showTranscript(); schedule(700); });

  function startMeter() {
    try {
      actx = new (window.AudioContext || window.webkitAudioContext)();
      const an = actx.createAnalyser(); an.fftSize = 64;
      actx.createMediaStreamSource(stream).connect(an);
      const data = new Uint8Array(an.frequencyBinCount), bars = [...meter.children];
      const tick = () => { an.getByteFrequencyData(data); bars.forEach((b, i) => b.style.setProperty("--v", String((data[i % data.length] || 0) / 255))); meterRaf = requestAnimationFrame(tick); };
      tick();
    } catch {}
  }

  // No browser speech engine: record short chunks and transcribe them on the server (OpenAI), if configured.
  async function startServerSTT() {
    let info = {}; try { info = await (await fetch("/api/shield/info")).json(); } catch {}
    if (!info.stt_server || !env.recorder) { status.textContent = t("sh.cg_no_stt"); fallbackInput(); return; }
    const loop = () => {
      if (!running) return;
      const chunks = []; mediaRec = new MediaRecorder(stream);
      mediaRec.ondataavailable = (e) => e.data.size && chunks.push(e.data);
      mediaRec.onstop = async () => {
        if (chunks.length) {
          const fd = new FormData(); const blob = new Blob(chunks, { type: mediaRec.mimeType || "audio/mp4" });
          fd.append("audio", blob, "chunk." + (blob.type.includes("webm") ? "webm" : "m4a")); fd.append("lang", lang.slice(0, 2));
          try { const r = await fetch("/api/guardian/transcribe", { method: "POST", body: fd }); if (r.ok) { const j = await r.json(); if (j.text) { finals = (finals + " " + j.text).trim(); showTranscript(); schedule(100); } } else if (r.status === 502) status.textContent = t("sh.cg_stt_err"); } catch {}
        }
        loop();
      };
      mediaRec.start(); setTimeout(() => mediaRec?.state === "recording" && mediaRec.stop(), 5000);
    };
    loop();
  }

  async function start() {
    if (!consent.checked) { status.textContent = t("sh.cg_need_consent"); consent.focus(); return; }
    if (!env.secure || !env.media) { status.textContent = t("sh.err_https"); return; }
    try { stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } }); }
    catch { status.textContent = t("sh.cg_mic_denied"); return; }
    running = true; finals = interim = lastSent = ""; tactics.clear(); maxScore = 0; lastLevel = "low"; srFailed = false;
    startBtn.textContent = t("sh.cg_stop"); startBtn.classList.add("on"); drawLang(); root.classList.add("live");
    status.textContent = t("sh.cg_listening"); showTranscript(); startMeter();
    if (SR) { try { startRecognition(); } catch { await startServerSTT(); } } else await startServerSTT();
  }

  function stop(reason) {
    if (!running) return;
    running = false; clearTimeout(sendTimer);
    try { rec && (rec.onend = null, rec.abort()); } catch {} rec = null;
    try { mediaRec?.state === "recording" && mediaRec.stop(); } catch {} mediaRec = null;
    stream?.getTracks().forEach((x) => x.stop()); stream = null;          // microphone released
    cancelAnimationFrame(meterRaf); try { actx?.close(); } catch {} actx = null;
    startBtn.textContent = t("sh.cg_start"); startBtn.classList.remove("on"); drawLang(); root.classList.remove("live");
    status.textContent = reason || t("sh.cg_stopped");
    if (finals.trim()) addHistory({ source: "call", level: lastLevel, score: maxScore, label: [...tactics.values()].map((x) => L(x)).slice(0, 3).join("، ") });
  }

  startBtn.addEventListener("click", () => (running ? stop() : start()));
  const onHide = () => { if (document.hidden && running) stop(t("sh.cg_stopped_bg")); };
  document.addEventListener("visibilitychange", onHide);
  stopFns.push(() => { stop(); document.removeEventListener("visibilitychange", onHide); });

  const root = h("section", { class: "cg" },
    flash,
    h("a", { class: "cg-back", href: "#/home" }, "‹ ", t("nav.home")),
    h("div", { class: "cm-kicker" }, t("sh.cg_kicker")), h("h1", {}, t("sh.cg_title")), h("p", { class: "muted" }, t("sh.cg_sub")),
    h("div", { class: "cg-stage" }, gauge, h("div", { class: "cg-side" }, meter, status, langSel)),
    h("label", { class: "sh-opt cg-consent", for: "cg-consent" }, consent, h("span", {}, h("b", {}, t("sh.cg_consent")), h("small", {}, t("sh.cg_consent_sub")))),
    startBtn,
    h("div", { class: "cg-cols" },
      h("div", {}, h("h3", {}, t("sh.cg_live_transcript")), transcript, typed),
      h("div", {}, h("h3", {}, t("sh.cg_detected")), tacticList, advice)),
    h("details", { class: "cg-how" }, h("summary", {}, t("sh.cg_how")),
      h("p", {}, t("sh.cg_how_1")), h("p", {}, t("sh.cg_how_2")), h("p", {}, t("sh.cg_how_3")),
      h("p", { class: "small muted" }, SR ? t("sh.cg_engine_browser") : t("sh.cg_engine_server"))));
  view.replaceChildren(root);
}

// ------------------------------------------------------------------------------------------------ strip on the Check page
// The mobile-shield idea lives inside the existing Check page: QR to open MERQAB on a phone, one-tap activation,
// the Call Guardian, and a link to the protection settings. Every state shown is read live.
export async function mobileStrip() {
  const box = h("section", { class: "ms" });
  let info = {}; try { info = await (await fetch("/api/shield/info")).json(); } catch {}
  const perms = await readPermissions();
  const dev = LS.get(DEV, null);
  const active = !!dev && perms.notifications === "granted";
  const phone = env.ios || env.android || /Mobi/.test(ua);
  const local = /^(localhost|127\.|\[?::1\]?)/.test(location.hostname);
  const state_ = active ? "on" : dev ? "partial" : "off";
  const actions = h("div", { class: "ms-actions" });
  if (!active) {
    if (env.ios && !env.standalone()) actions.append(h("a", { class: "btn", href: "#/shield" }, t("ms.install")));
    else if (env.push && env.secure) {
      const b = h("button", { class: "btn", type: "button" }, t("sh.activate"));
      b.addEventListener("click", async () => {
        b.disabled = true;
        try { await activatePush({ topics: ["alerts", "campaigns"] }); toast(t("sh.activated")); try { await deviceApi("/devices/me/test", { method: "POST" }); } catch {} box.replaceWith(await mobileStrip()); }
        catch (e) { toast(e.message); b.disabled = false; }
      });
      actions.append(b);
    }
  }
  actions.append(h("a", { class: "btn secondary", href: "#/shield/call" }, t("sh.guard_cta")),
    h("a", { class: "ms-more", href: "#/shield" }, t("ms.settings")));
  const qr = !phone ? (local ? h("figure", { class: "ms-qr ms-qr-preview" },
      h("div", { class: "ms-qr-art" }, h("img", { src: "/api/qr/preview.svg", alt: t("sh.qr_preview_alt"), width: "132", height: "132" }),
        h("img", { class: "ms-qr-logo", src: "/assets/logo-mark.png", alt: "", "aria-hidden": "true" })),
      h("figcaption", {}, t("sh.qr_preview")))
    : h("figure", { class: "ms-qr" }, h("img", { src: "/api/qr.svg?path=" + encodeURIComponent("/#/home"), alt: t("sh.qr_alt"), width: "132", height: "132" }),
      h("figcaption", {}, t("ms.scan")))) : null;
  qr?.querySelector("img")?.addEventListener("error", () => qr.replaceWith(h("div", { class: "ms-qr ms-qr-off" }, h("small", {}, t("sh.qr_unavailable"), " ", info.url || location.origin))));
  box.className = `ms ${state_}`;
  box.replaceChildren(...[qr,
    h("div", { class: "ms-body" },
      h("div", { class: "cm-kicker" }, t("ms.kicker")),
      h("h2", {}, t(`ms.title_${state_}`)),
      h("p", { class: "muted" }, t(phone ? `ms.sub_phone_${state_}` : "ms.sub_desktop")),
      actions)].filter(Boolean));
  return box;
}
