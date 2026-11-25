// Core utilities: safe DOM builder, i18n, API client, session state.
// All user/evidence content is inserted with textContent — never innerHTML.

export const state = {
  lang: "en",
  dict: {},
  token: sessionStorage.getItem("mirqab.token") || null,
  user: JSON.parse(sessionStorage.getItem("mirqab.user") || "null"),
  simple: localStorage.getItem("mirqab.simple") === "1",
  lastCheck: null,
  caps: null,
};

const dicts = {};

// Interface languages. Content produced by the engine and the radar (reasons, campaign names, warnings) is
// written in Arabic and English; other languages show the English version of that content.
export const LANGS = [
  { code: "ar", name: "العربية", label: "Arabic", dir: "rtl", locale: "ar-AE" },
  { code: "en", name: "English", label: "English", dir: "ltr", locale: "en-GB" },
  { code: "ur", name: "اردو", label: "Urdu", dir: "rtl", locale: "ur-PK" },
  { code: "hi", name: "हिन्दी", label: "Hindi", dir: "ltr", locale: "hi-IN" },
  { code: "tl", name: "Filipino", label: "Filipino", dir: "ltr", locale: "fil-PH" },
  { code: "zh", name: "中文", label: "Chinese", dir: "ltr", locale: "zh-CN" },
  { code: "fr", name: "Français", label: "French", dir: "ltr", locale: "fr-FR" },
  { code: "es", name: "Español", label: "Spanish", dir: "ltr", locale: "es-ES" },
  { code: "ru", name: "Русский", label: "Russian", dir: "ltr", locale: "ru-RU" },
];
export const langInfo = (c = state.lang) => LANGS.find(l => l.code === c) || LANGS[1];
export const isRTL = () => langInfo().dir === "rtl";
export const locale = () => langInfo().locale;
export function pickLang(saved, nav) {
  if (saved && LANGS.some(l => l.code === saved)) return saved;
  const n = (nav || "").toLowerCase();
  const m = LANGS.find(l => n.startsWith(l.code) || (l.code === "tl" && n.startsWith("fil")));
  return m ? m.code : "en";
}

async function dict(lang) {
  if (!dicts[lang]) {
    const r = await fetch(`i18n/${lang}.json`, { cache: "no-cache" });
    dicts[lang] = await r.json();
  }
  return dicts[lang];
}
export async function loadLang(lang) {
  lang = LANGS.some(l => l.code === lang) ? lang : "en";
  const [d] = await Promise.all([dict(lang), dict("en")]);
  state.lang = lang;
  state.dict = d;
  try { localStorage.setItem("mirqab.lang", lang); } catch {}
  document.documentElement.lang = lang;
  document.documentElement.dir = langInfo(lang).dir;
}

// a string missing in the chosen language falls back to English, never to the raw key
export const t = (k) => state.dict[k] ?? dicts.en?.[k] ?? k;
// pick the right language from {en, ar} objects or *_en/*_ar fields
export const L = (obj, base) => {
  if (!obj) return "";
  if (base) return obj[`${base}_${state.lang}`] ?? obj[`${base}_en`] ?? "";
  return obj[state.lang] ?? obj.en ?? "";
};

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style") for (const [p, val] of Object.entries(v)) el.style.setProperty(p, val);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("show"), 3200);
}

export class ApiError extends Error {
  constructor(status, detail) { super(detail); this.status = status; }
}

export async function api(path, { method = "GET", body, form, raw } = {}) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  let r;
  try { r = await fetch(`/api${path}`, { method, headers, body: payload }); }
  catch { throw new ApiError(0, t("err.network")); }
  if (r.status === 401 && state.token) { setSession(null); }
  if (!r.ok) {
    let detail = t("err.generic");
    try { const j = await r.json(); detail = j.detail || detail; if (j.errors?.length) detail += ` (${j.errors.map(e => e.field).join(", ")})`; } catch {}
    throw new ApiError(r.status, detail);
  }
  return raw ? r : r.json();
}

export function setSession(data) {
  state.token = data?.token || null;
  state.user = data?.user || null;
  if (state.token) {
    sessionStorage.setItem("mirqab.token", state.token);
    sessionStorage.setItem("mirqab.user", JSON.stringify(state.user));
  } else {
    sessionStorage.removeItem("mirqab.token");
    sessionStorage.removeItem("mirqab.user");
  }
}

export const hasRole = (r) => {
  const rank = { investigator: 1, reviewer: 2, admin: 3 };
  return state.user && rank[state.user.role] >= rank[r];
};

export async function withBusy(btn, label, fn) {
  const original = [...btn.childNodes];
  btn.disabled = true;
  btn.replaceChildren(h("span", { class: "spinner", "aria-hidden": "true" }), label);
  try { return await fn(); }
  finally { btn.disabled = false; btn.replaceChildren(...original); }
}

export function download(filename, content, type = "text/plain") {
  const blob = content instanceof Blob ? content : new Blob([content], { type: `${type};charset=utf-8` });
  const a = h("a", { href: URL.createObjectURL(blob), download: filename });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

export const fmtTime = (iso) => {
  if (!iso) return "";
  const d = new Date(iso.length <= 16 ? iso : iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(locale(), { dateStyle: "medium", timeStyle: "short" });
};

export const errorBox = (e) => h("div", { class: "notice warn", role: "alert" }, e.message || t("err.generic"));

// Language menu: a button showing the current language and a list of all languages (keyboard accessible).
export function langPicker(onPick, cls = "lang-btn") {
  const cur = langInfo();
  const btn = h("button", { type: "button", class: cls, "aria-haspopup": "listbox", "aria-expanded": "false", title: "Language · اللغة" },
    h("span", { class: "lang-globe", "aria-hidden": "true" }, "🌐"), h("span", { class: "lang-cur", lang: cur.code }, cur.name));
  const items = LANGS.map(l => h("li", { role: "option", tabindex: "-1", lang: l.code, dir: l.dir, "data-code": l.code,
    "aria-selected": String(l.code === cur.code), class: l.code === cur.code ? "on" : "" },
    h("span", {}, l.name), l.code !== state.lang ? h("small", { dir: "ltr" }, l.label) : h("small", { "aria-hidden": "true" }, "✓")));
  const menu = h("ul", { class: "lang-menu", role: "listbox", "aria-label": "Language", hidden: true }, ...items);
  const wrap = h("div", { class: "lang-wrap" }, btn, menu);
  const close = (focus) => { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); document.removeEventListener("pointerdown", outside, true); if (focus) btn.focus(); };
  const outside = (e) => { if (!wrap.contains(e.target)) close(false); };
  const open = () => {
    menu.hidden = false; btn.setAttribute("aria-expanded", "true");
    (items.find(i => i.classList.contains("on")) || items[0]).focus();
    document.addEventListener("pointerdown", outside, true);
  };
  const choose = async (code) => { close(true); if (code !== state.lang) { await loadLang(code); onPick(code); } };
  btn.addEventListener("click", () => menu.hidden ? open() : close(true));
  btn.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); open(); } });
  items.forEach((li, i) => {
    li.addEventListener("click", () => choose(li.dataset.code));
    li.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus(); }
      else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(li.dataset.code); }
      else if (e.key === "Escape" || e.key === "Tab") close(e.key === "Escape");
    });
  });
  return wrap;
}
