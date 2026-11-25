// MIRGAB single-page app: routing, Home, Smart Protection, Community, Reports, Settings.
import { api, errorBox, h, hasRole, isRTL, L, langPicker, loadLang, pickLang, setSession, state, t, toast, withBusy } from "./core.js";
import { awarenessInProgress, communityExperience, stopCommunity } from "./community.js";
import { getJourney, goExplore, journeyBar } from "./journey.js";
import { landingPage, stopLanding } from "./landing.js";
import { renderResult } from "./result.js";
import { radarPage, stopRadar } from "./publicRadar.js";
import { addHistory, mobileStrip, registerSW, shieldPage, stopShield } from "./shield.js";
import { accuracyPage } from "./accuracy.js";
// installed app (Home Screen): standalone-only layout tweaks
try { if (navigator.standalone || matchMedia("(display-mode: standalone)").matches) document.documentElement.classList.add("pwa"); } catch {}

const ICONS = {
  home: "M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z M9 12l2 2 4-4",
  radar: "M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0-18 0 M12 12m-5 0a5 5 0 1 0 10 0a5 5 0 1 0-10 0 M12 12l6-6",
  investigate: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M21 21l-5-5",
  shield: "M12 2 4 5v6c0 5.5 3.4 9.6 8 11 4.6-1.4 8-5.5 8-11V5z M8 12h2l1.2-3 1.8 6 1.2-3H16",
  community: "M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M16 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M2 20c0-3 3-5 6-5s6 2 6 5 M14 15c3 0 8 1 8 5",
  settings: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M19 12l2-1-1-3-2 .3-1.5-1.5L17 5l-3-1-1 2h-2L10 4 7 5l.5 1.8L6 8.3 4 8l-1 3 2 1v0l-2 1 1 3 2-.3 1.5 1.5L7 19l3 1 1-2h2l1 2 3-1-.5-1.8 1.5-1.5 2 .3 1-3z",
};
const NAV = ["home", "radar", "community"];   // investigation opens in context inside LIVE; no settings or sign-in pages

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none"); svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8"); svg.setAttribute("stroke-linecap", "round"); svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name].split(" M")) {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", d.startsWith("M") ? d : "M" + d);
    svg.append(p);
  }
  return svg;
}

function renderChrome(active) {
  const links = (withIcons) => NAV.map(k => h("a", { href: `#/${k}`, "aria-current": k === active ? "page" : null },
    withIcons ? icon(k) : null, h("span", {}, t(`nav.${k}`))));
  document.getElementById("topnav").replaceChildren(...links(false));
  document.getElementById("bottomnav").replaceChildren(...links(true));
  document.getElementById("langSlot").replaceChildren(langPicker(() => route()));
  setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
  document.querySelector(".skip").textContent = t("nav.home");
  document.documentElement.classList.toggle("simple", state.simple);
  document.title = `${t("app.name")} — ${t(`nav.${active}`)}`;
  document.body.dataset.page = active;   // LIVE gets an immersive dark canvas
}

// ----------------------------------------------------------------------------- Home
// One check experience: input → explainable result, with live early warnings underneath.
async function homePage(view) {
  // A link sent from the Threat Constellation ("Check this link") arrives as a one-time prefill.
  const pre = JSON.parse(sessionStorage.getItem("mirqab.prefill") || "null");
  sessionStorage.removeItem("mirqab.prefill");
  let kind = pre?.kind || "text";
  const out = h("div", { id: "out" });
  const ta = h("textarea", { id: "pin", dir: "auto", maxlength: "20000", "aria-label": t("home.placeholder") });
  const urlIn = h("input", { type: "text", id: "purl", dir: "ltr", inputmode: "url", autocomplete: "off", spellcheck: "false", "aria-label": t("protect.ph.url") });
  const file = h("input", { type: "file", id: "pfile", accept: ".png,.jpg,.jpeg,.webp,.pdf,.txt,.eml" });
  const fileName = h("span", { class: "small muted" }, t("protect.no_file"));
  file.addEventListener("change", () => { fileName.textContent = file.files[0]?.name || t("protect.no_file"); });
  const filePick = h("div", { class: "filepick" }, h("label", { for: "pfile", class: "btn secondary", style: { margin: 0 } }, t("protect.choose_file")), file, fileName);
  const media = h("input", { type: "file", id: "pmedia", accept: ".jpg,.jpeg,.png,.webp,.mp3,.wav,.m4a,.ogg,.opus,.mp4,.mov" });
  const mediaName = h("span", { class: "small muted" }, t("protect.no_file"));
  media.addEventListener("change", () => { mediaName.textContent = media.files[0]?.name || t("protect.no_file"); });
  const mediaPick = h("div", { class: "filepick df-pick" }, h("span", { class: "df-ico", "aria-hidden": "true" }),
    h("div", {}, h("b", {}, t("df.pick_title")), h("p", { class: "small muted" }, t("df.pick_sub"))),
    h("label", { for: "pmedia", class: "btn secondary", style: { margin: 0 } }, t("protect.choose_file")), media, mediaName);
  const btn = h("button", { class: "btn lg", type: "submit" }, t("home.check"));
  let qrSource = false;
  const inputArea = h("div");
  const tabs = h("div", { class: "seg", role: "tablist" });
  const jph = getJourney() && !pre?.content ? `${t("jb.check_ph")} ${L(getJourney(), "name")}` : null;
  const drawInput = () => {
    tabs.replaceChildren(...["text", "conversation", "url", "file", "deepfake"].map(k => h("button", {
      type: "button", role: "tab", "aria-selected": String(k === kind), onclick: () => { kind = k; out.replaceChildren(); drawInput(); } }, t(`protect.tab.${k}`))));
    if (kind === "file") inputArea.replaceChildren(filePick, h("p", { class: "small hint" }, t("protect.file_hint")));
    else if (kind === "deepfake") inputArea.replaceChildren(mediaPick, h("p", { class: "small hint" }, t("df.hint")));
    else if (kind === "url") { inputArea.replaceChildren(urlIn); urlIn.placeholder = jph || t("protect.ph.url"); }
    else { ta.placeholder = kind === "text" ? (jph || t("home.placeholder")) : t("protect.ph.conversation"); ta.style.minHeight = kind === "conversation" ? "200px" : "120px"; inputArea.replaceChildren(ta); }
  };
  drawInput();
  const run = async () => {
    out.replaceChildren();
    await withBusy(btn, t("protect.analyzing"), async () => {
      try {
        if (kind === "deepfake") {
          if (!media.files[0]) return toast(t("protect.no_file"));
          const fd = new FormData(); fd.append("file", media.files[0]);
          const dfr = await api("/deepfake/scan", { method: "POST", form: fd });
          out.replaceChildren(renderDeepfake(dfr));
          addHistory({ source: "deepfake", level: { high: "high", medium: "medium" }[dfr.level] || "low", score: dfr.level === "high" ? 70 : dfr.level === "medium" ? 45 : 0, label: media.files[0]?.name || "" });
        } else if (kind === "file") {
          if (!file.files[0]) return toast(t("protect.no_file"));
          const fd = new FormData(); fd.append("file", file.files[0]);
          const r = await api("/analyze/file", { method: "POST", form: fd });
          if (!r.result) { out.replaceChildren(h("div", { class: "notice warn" }, r.note)); return; }
          out.replaceChildren(renderResult(r.result, { extractedText: r.text, headerSignals: r.header_signals }));
          addHistory({ source: "file", level: r.result.risk.level, score: r.result.risk.score, label: file.files[0]?.name || "" });
        } else {
          let content = kind === "url" ? urlIn.value.trim() : ta.value;
          if (!content.trim()) return;
          const k = kind === "text" && /^\s*(https?:\/\/|www\.)\S+\s*$/i.test(content) ? "url" : kind;
          const r = await api("/analyze", { method: "POST", body: { kind: k, content } });
          out.replaceChildren(renderResult(r, { sourceText: content }));
          addHistory({ source: qrSource ? "qr" : k, level: r.risk.level, score: r.risk.score, label: r.patterns?.[0] ? L(r.patterns[0], "name") : "" });
          qrSource = false;
        }
        out.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (e) { out.replaceChildren(errorBox(e)); }
    });
  };
  const journey = getJourney();
  const pulse = h("a", { class: "hero-pulse", href: "#/radar", hidden: true });
  const form = h("form", { class: "hero" },
    h("div", { class: "hero-orb", "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("b")),
    journeyBar(), pulse, h("h1", {}, t("home.title")), h("p", {}, t("home.subtitle")), tabs, inputArea,
    h("div", { class: "row", style: { "margin-top": "12px" } }, btn));
  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
  if (pre?.content) { if (kind === "url") urlIn.value = pre.content; else ta.value = pre.content; }
  else if (journey) setTimeout(() => (kind === "url" ? urlIn : ta).focus({ preventScroll: true }), 0);
  const warnings = h("div", { class: "stack" }, h("p", { class: "muted" }, t("common.loading")));
  const strip = h("div");
  mobileStrip().then((el) => strip.replaceWith(el)).catch(() => strip.remove());
  view.replaceChildren(form, out, strip,
    h("section", { class: "home-warn" }, h("div", { class: "section-title" }, h("h2", {}, t("home.warnings_title")),
      h("a", { href: "#/radar", class: "small" }, `${t("home.view_all")} ${isRTL() ? "←" : "→"}`)), warnings));
  try {
    const [alerts, radar] = await Promise.all([api("/community/alerts"), api("/radar/public")]);
    const rows = [
      ...alerts.slice(0, 2).map(a => h("a", { class: "warn-row verified", href: "#/community" },
        h("span", { class: "badge verified" }, t("warn.validated")), h("b", {}, L(a, "title")), h("span", { class: "small muted" }, L(a, "summary")))),
      ...radar.campaigns.slice(0, 3).map(c => h("a", { class: `warn-row ${c.status}`, href: `#/radar/${c.id}`, onclick: (e) => { e.preventDefault(); goExplore({ campaign_id: c.id }); } },
        h("span", { class: `badge ${c.status === "confirmed" ? "critical" : "inference"}` }, t(`warn.${c.status}`)),
        h("b", {}, t(`pr.sector.${c.sector}`)), h("span", { class: "small muted" }, `${L(c, "harm")} · ${c.size} ${t("radar.sites")}`))),
    ];
    warnings.replaceChildren(rows.length ? h("div", { class: "warn-grid" }, ...rows) : h("div", { class: "card" }, h("p", { class: "empty" }, t("home.alerts_empty"))));
    // live state, only from the radar's own counts; hidden when the radar has nothing to report
    if (radar.enabled && radar.source_updated_at) {
      pulse.hidden = false;
      pulse.replaceChildren(h("span", { class: "dot running", "aria-hidden": "true" }), h("b", {}, t("radar.live")));
    }
  } catch (e) { warnings.replaceChildren(errorBox(e)); }
  if (pre?.autorun && pre.content) run();
}

// ----------------------------------------------------------------------------- Community
async function communityPage(view) {
  await communityExperience(view);
}

// ----------------------------------------------------------------------------- Router
async function route() {
  if (awarenessInProgress() && !/^#\/community(?:\/|$)/.test(location.hash)) {
    history.replaceState(null, "", "#/community");
    toast(t("aw.locked"));
    return false;
  }
  // the entrance: shown at the site root (once per visit) or at #/welcome; deep links go straight in
  const bare = !location.hash || location.hash === "#" || location.hash === "#/";
  if (location.hash === "#/welcome" || (bare && !sessionStorage.getItem("mirqab.entered"))) {
    stopRadar();
    landingPage(document.getElementById("view"), () => { location.hash = "#/home"; });
    return false;
  }
  stopLanding();
  stopCommunity();
  stopShield();
  let [, page = "home", sub] = (location.hash || "#/home").split("/");
  if (!page) page = "home";
  if (page === "protect") page = "home";                                    // merged into Home
  // removed pages: investigation, cases, reports, sign-in and settings are not part of the public product
  if (["investigate", "reports", "login", "settings"].includes(page) || (page === "radar" && (sub === "case" || sub === "cases"))) {
    location.replace(page === "settings" ? "#/home" : "#/radar"); return false;
  }
  const active = NAV.includes(page) ? page : "home";
  renderChrome(active);
  const view = document.getElementById("view");
  stopRadar();
  view.replaceChildren();
  if (page === "accuracy") { await accuracyPage(view); return true; }
  if (page === "shield") { await shieldPage(view, sub); return true; }   // opened from the Check page, not a menu tab
  if (active === "home") await homePage(view);
  else if (active === "radar") await radarPage(view, sub);

  else await communityPage(view);
  return true;
}

async function init() {
  let saved = null; try { saved = localStorage.getItem("mirqab.lang"); } catch {}
  await loadLang(pickLang(saved, navigator.language));
  document.getElementById("themeBtn").addEventListener("click", () => setTheme(document.documentElement.classList.contains("dark") ? "light" : "dark"));
  setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
  state.simple = false; localStorage.removeItem("mirqab.simple");   // simple mode removed; browser zoom covers larger text
  window.addEventListener("hashchange", async () => {
    if (await route()) { document.getElementById("view").focus({ preventScroll: true }); window.scrollTo(0, 0); }
  });
  setSession(null);   // no staff sessions in the public app
  registerSW();
  // Android share sheet ("Share → MIRGAB") lands here with ?share_text / share_url
  const q = new URLSearchParams(location.search);
  const shared = [q.get("share_title"), q.get("share_text"), q.get("share_url")].filter(Boolean).join("\n").trim();
  if (shared) {
    const onlyUrl = /^\s*https?:\/\/\S+\s*$/i.test(shared);
    sessionStorage.setItem("mirqab.prefill", JSON.stringify({ kind: onlyUrl ? "url" : "text", content: shared.slice(0, 20000) }));
    sessionStorage.setItem("mirqab.entered", "1");
    history.replaceState(null, "", "/#/home");
  }
  // installed app opens straight into the shield
  if ((window.navigator.standalone || matchMedia("(display-mode: standalone)").matches) && !location.hash) sessionStorage.setItem("mirqab.entered", "1");
  route();
}

init();

// ---------------------------------------------------------------- theme (dark by default, remembered per browser)
const SUN = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>';
const MOON = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M20.5 14.6A8.5 8.5 0 0 1 9.4 3.5a8.5 8.5 0 1 0 11.1 11.1Z"/></svg>';
export function setTheme(mode) {
  const dark = mode !== "light";
  document.documentElement.classList.toggle("dark", dark);
  try { localStorage.setItem("mirqab.theme", dark ? "dark" : "light"); } catch {}
  const b = document.getElementById("themeBtn");
  if (!b) return;
  b.innerHTML = dark ? SUN : MOON;                       // static icons only
  const label = t(dark ? "theme.to_light" : "theme.to_dark");
  b.setAttribute("aria-label", label); b.title = label;
}
(() => { let m = "dark"; try { m = localStorage.getItem("mirqab.theme") || "dark"; } catch {} document.documentElement.classList.toggle("dark", m !== "light"); })();

// ---------------------------------------------------------------- deepfake scan result
function renderDeepfake(r) {
  const p = r.provenance, a = r.ai_review || {};
  const head = { high: ["bad", "df.v_high"], medium: ["warn", "df.v_medium"], unknown: ["none", "df.v_unknown"] }[r.level] || ["none", "df.v_unknown"];
  return h("section", { class: `card df-res ${head[0]}` },
    h("div", { class: "df-head" }, h("span", { class: "df-badge" }, t(`df.kind_${r.kind}`)), h("h2", {}, t(head[1]))),
    h("div", { class: "df-block" }, h("div", { class: "cm-kicker" }, t("df.provenance")),
      h("ul", { class: "df-list" }, ...p.findings.map(f => h("li", { class: f.level }, h("span", {}, f.level === "strong" ? "⚠" : "ℹ"), L(f))))),
    h("div", { class: "df-block" }, h("div", { class: "cm-kicker" }, t("df.ai_review")),
      a.status === "used" ? h("div", {},
        h("p", { class: `df-ai ${a.assessment}` }, h("b", {}, t(`df.a_${a.assessment}`)), a.confidence ? ` · ${t("res.confidence")}: ${t(`conf.${a.confidence}`)}` : ""),
        a.signs.length ? h("ul", { class: "df-list" }, ...a.signs.map(sg => h("li", {}, h("span", {}, "•"), L(sg)))) : null,
        h("p", { class: "small muted" }, `${t("df.ai_caveat")} (${a.model})`))
      : h("p", { class: "small muted" }, t(a.status === "not_applicable" ? `df.na_${r.kind}` : a.status === "failed" ? "df.ai_failed" : "df.ai_off"))),
    h("div", { class: "df-block df-do" }, h("div", { class: "cm-kicker" }, t("res.do_now")),
      h("p", {}, t("rn.a_video")), h("p", { class: "small" }, t("rn.voice_note")),
      h("a", { class: "btn secondary sm", href: "#/community" }, t("df.practice"))),
    h("p", { class: "small muted" }, L(r, "limits"), " ", t("df.not_stored")));
}
