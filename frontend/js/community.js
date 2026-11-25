// MERQAB Community — one living experience instead of a list of sections:
//   Pulse (real-time community signal) → Decoder (what is happening + where you are in the scam chain)
//   → Scam Theater (interactive films) → Family Circle (plan + warnings) → Signal board (verified warnings, reports)
//   with an Emergency mode for "it already happened".
// Community is about awareness only — scenarios, tips, a test and what to do if it already happened. It takes nothing from
// the radar: content comes from the scam-tactics engine (/api/community/shield), verified warnings and the report API;
// personal progress stays in this browser.
import { api, errorBox, h, L, locale, t, withBusy } from "./core.js";
import { awarenessIcon, theater } from "./theater.js";
import { AWARENESS } from "./awareness.js";

const fmtN = (n) => Number(n || 0).toLocaleString(locale());
const PROGRESS = "mirqab.awareness.films.v2";
let cleanup = [];
let activeJourney = false;
let visit = 0;
export const awarenessInProgress = () => activeJourney;
export function stopCommunity() {
  visit++;
  activeJourney = false;
  cleanup.forEach(f => f());
  cleanup = [];
}

const ECRIME = "https://u.ae/en/information-and-services/justice-safety-and-the-law/cyber-safety-and-digital-security/report-cybercrimes-online";

function responseChecklist(openReport) {
  const acts = [
    { k: "s1", icon: "bank", extra: null },
    { k: "s2", icon: "shield", extra: h("div", { class: "em-ch" },
      h("a", { href: "tel:8002626" }, h("b", {}, "800 2626"), h("span", {}, t("rc.aman"))),
      h("a", { href: "sms:2828" }, h("b", {}, "SMS 2828"), h("span", {}, t("rc.aman_sms"))),
      h("a", { href: ECRIME, target: "_blank", rel: "noopener noreferrer" }, h("b", {}, t("rc.ecrime")), h("span", {}, t("rc.ecrime_sub"))),
      h("a", { href: "tel:999" }, h("b", {}, "999"), h("span", {}, t("rc.emergency")))) },
    { k: "s3", icon: "lock", extra: null },
    { k: "s4", icon: "report", extra: h("button", { type: "button", class: "btn ghost sm", onclick: () => { openReport(); } }, t("rc.report_here")) }];
  const done = new Set();
  const list = h("div", { class: "em-acts" });
  function draw() {
    list.replaceChildren(...acts.map(a => h("div", { class: `em-act ${done.has(a.k) ? "done" : ""}` },
      h("span", { class: "em-act-i" }, awarenessIcon(done.has(a.k) ? "check" : a.icon)),
      h("div", {}, h("b", {}, t(`rc.${a.k}`)), h("p", {}, t(`rc.${a.k}_how`)), a.extra),
      h("button", { type: "button", class: "em-done", "aria-pressed": String(done.has(a.k)), onclick: () => { done.has(a.k) ? done.delete(a.k) : done.add(a.k); draw(); } }, done.has(a.k) ? t("cm.em_undo") : t("cm.em_done")))));
  }
  draw();
  return list;
}

function emergency(ctx) {
  document.querySelector(".em")?.remove();
  const started = Date.now();
  const clock = h("b", { class: "em-clock" }, "00:00");
  const tickT = setInterval(() => { const s = Math.floor((Date.now() - started) / 1000); clock.textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; }, 1000);
  const close = () => { clearInterval(tickT); node.remove(); document.removeEventListener("keydown", esc); document.body.classList.remove("em-open"); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  const list = responseChecklist(() => { close(); ctx.openReport(); });
  const node = h("div", { class: "em", role: "dialog", "aria-modal": "true", "aria-label": t("rc.title") },
    h("div", { class: "em-in" },
      h("div", { class: "em-top" }, h("div", {}, h("div", { class: "em-kicker" }, t("cm.em_kicker")), h("h2", {}, t("rc.title")), h("p", {}, t("rc.sub"))),
        h("div", { class: "em-timer" }, h("small", {}, t("cm.em_since")), clock), h("button", { type: "button", class: "em-x", "aria-label": t("common.close"), onclick: close }, "✕")),
      list,
      h("p", { class: "em-src" }, t("rc.source"))));
  document.body.append(node); document.body.classList.add("em-open");
  document.addEventListener("keydown", esc);
  node.querySelector(".em-done")?.focus();
  cleanup.push(close);
}

export async function communityExperience(view) {
  stopCommunity();
  const currentVisit = visit;
  view.replaceChildren(h("div", { class: "cm-loading" }, h("span", { class: "dot running" }), t("common.loading")));
  const shield = await api("/community/shield").catch(error => ({ error }));
  if (currentVisit !== visit) return;
  if (shield.error) { view.replaceChildren(errorBox(shield.error)); return; }
  const ctx = {};
  // report form (unchanged behaviour: anonymised, stored as unverified, shown back exactly as stored)
  const repTa = h("textarea", { id: "rep", dir: "auto", placeholder: t("com.report_ph"), maxlength: "5000" });
  const repOut = h("div");
  const repBtn = h("button", { class: "btn", type: "submit" }, t("com.report_submit"));
  const repForm = h("form", { class: "bd-report" }, h("div", { class: "cm-label" }, t("com.report_title")), h("p", { class: "small cm-muted" }, t("com.report_hint")),
    repTa, h("div", { class: "row", style: { "margin-top": "10px" } }, repBtn), repOut);
  repForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (repTa.value.trim().length < 10) return;
    await withBusy(repBtn, t("com.report_submit"), async () => {
      try {
        const r = await api("/community/reports", { method: "POST", body: { text: repTa.value } });
        repTa.value = "";
        repOut.replaceChildren(h("p", { class: "small", style: { "margin-top": "10px" } }, L(r, "message")), h("b", { class: "small" }, t("com.report_stored")), h("pre", { class: "box", dir: "auto" }, r.stored_text));
      } catch (ex) { repOut.replaceChildren(errorBox(ex)); }
    });
  });
  const saved = Number(sessionStorage.getItem(PROGRESS));
  let index = Number.isInteger(saved) && saved >= 0 && saved <= AWARENESS.length ? saved : 0;
  activeJourney = index > 0 && index < AWARENESS.length;
  const title = h("h1", {}, t("aw.cinema_title"));
  const count = h("span", { class: "aw-count", role: "status" });
  const progress = h("progress", { max: AWARENESS.length, "aria-label": t("aw.progress") });
  const chapterMarks = AWARENESS.map(() => h("i"));
  const stage = h("div", { class: "aw-stage" });
  const chapters = h("div", { class: "aw-chapters", "aria-hidden": "true" }, chapterMarks);
  const updateProgress = () => {
    progress.value = index;
    chapterMarks.forEach((mark, i) => { mark.dataset.state = i < index ? "done" : i === index ? "current" : "pending"; });
  };
  const urgent = h("button", { type: "button", class: "btn secondary sm", onclick: () => emergency(ctx) }, t("cm.sos"));
  const page = h("div", { class: "cm aw aw-film" },
    h("header", { class: "aw-header" }, title,
      h("div", { class: "aw-progress" }, count, progress, chapters),
      urgent),
    stage);

  ctx.openReport = () => {
    const dialog = h("dialog", { class: "aw-report", "aria-label": t("com.report_title") },
      h("button", { class: "btn secondary sm", type: "button", onclick: () => dialog.close() }, t("common.close")), repForm);
    document.body.append(dialog);
    dialog.addEventListener("close", () => dialog.remove(), { once: true });
    cleanup.push(() => { if (dialog.open) dialog.close(); });
    dialog.showModal();
    repTa.focus();
  };
  function showSummary(moveFocus = false) {
    player.stop();
    urgent.hidden = true;
    count.textContent = `${fmtN(AWARENESS.length)} / ${fmtN(AWARENESS.length)}`;
    updateProgress();
    const heading = h("h2", { tabindex: "-1" }, t("aw.done"));
    stage.replaceChildren(h("section", { class: "aw-intro aw-complete" }, heading,
      h("div", { class: "row" }, h("a", { class: "btn secondary", href: "#/home" }, t("nav.home")),
        h("button", { class: "btn ghost", type: "button", onclick: () => { index = 0; sessionStorage.setItem(PROGRESS, "0"); showFilm(false); } }, t("aw.restart")))),
      h("section", { class: "aw-response", "aria-labelledby": "aw-response-title" },
        h("h2", { id: "aw-response-title" }, t("aw.real_incident")),
        responseChecklist(() => ctx.openReport()),
        h("p", { class: "em-src" }, t("rc.source"))));
    stage.scrollTop = 0;
    if (moveFocus) heading.focus();
  }
  const player = theater({
    films: AWARENESS,
    tacticByKey: Object.fromEntries(shield.stages.flatMap(s => s.tactics).map(tc => [tc.key, tc])),
    onStart: () => { activeJourney = true; },
    onAdvance: () => {
      index++;
      sessionStorage.setItem(PROGRESS, String(index));
      activeJourney = index < AWARENESS.length;
      if (activeJourney) showFilm(true);
      else showSummary(true);
    },
  });
  cleanup.push(player.stop);
  function showFilm(autoplay) {
    urgent.hidden = false;
    count.textContent = `${fmtN(index + 1)} / ${fmtN(AWARENESS.length)}`;
    updateProgress();
    stage.replaceChildren(player.node);
    stage.scrollTop = 0;
    player.load(AWARENESS[index].id, autoplay);
    if (autoplay) player.node.querySelector(".th-stage")?.focus();
  }
  // welcome screen: the page opens on a short invitation, the first scenario starts only when the visitor asks for it
  function showWelcome() {
    urgent.hidden = false;
    count.textContent = `0 / ${fmtN(AWARENESS.length)}`;
    updateProgress();
    const start = h("button", { type: "button", class: "btn aw-go", onclick: () => showFilm(true) }, t("aw.welcome_cta"));
    stage.replaceChildren(h("section", { class: "aw-welcome", "aria-labelledby": "aw-welcome-title" },
      h("div", { class: "aw-w-kicker" }, t("aw.welcome_kicker")),
      h("h2", { id: "aw-welcome-title" }, t("aw.welcome_title")),
      h("p", { class: "aw-w-sub" }, t("aw.welcome_sub").replace("{n}", fmtN(AWARENESS.length))),
      h("ol", { class: "aw-w-list" }, AWARENESS.map((film, i) => h("li", {}, h("span", {}, fmtN(i + 1)), L(film.title)))),
      h("div", { class: "aw-w-actions" }, start, h("span", { class: "aw-w-time" }, t("aw.welcome_time")))));
    stage.scrollTop = 0;
    start.focus({ preventScroll: true });
  }
  view.replaceChildren(page);
  if (index === AWARENESS.length) showSummary();
  else if (index === 0) showWelcome();
  else showFilm(false);
}
