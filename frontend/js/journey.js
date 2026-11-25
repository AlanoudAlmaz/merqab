// One protection journey across LIVE, Smart Protection and Family Shield.
// When someone explores a campaign, its context (name, status, the scam's next step, approved warnings)
// travels with them, so Check and Family Shield can speak about the same threat and lead back to it.
import { h, L, t } from "./core.js";

const KEY = "mirqab.journey";
const read = (k, store = sessionStorage) => { try { return JSON.parse(store.getItem(k) || "null"); } catch { return null; } };
const write = (k, v, store = sessionStorage) => { try { v == null ? store.removeItem(k) : store.setItem(k, JSON.stringify(v)); } catch { /* storage off */ } };

export const getJourney = () => read(KEY);
export const clearJourney = () => write(KEY, null);

// Built only from the intelligence view payload (real campaign data and published warnings).
export function setJourneyFromIntel(d) {
  const c = d.campaign, s = d.sites[0];
  write(KEY, {
    target: c ? { campaign_id: c.id } : { item_id: s.id },
    name_en: c ? c.name_en : s.host, name_ar: c ? c.name_ar : s.host,
    status: c ? c.status : s.status, campaign_id: c?.id || null, hosts: d.sites.map(x => x.host),
    script: d.script, warnings: d.warnings.map(w => ({ id: w.id, title_en: w.title_en, title_ar: w.title_ar, summary_en: w.summary_en, summary_ar: w.summary_ar, actions: w.actions })),
  });
}

// Who the person is protecting (shared with Family Shield's audiences).
export const PERSONAS = ["everyone", "seniors", "students", "families", "businesses"];
export const getPersona = () => { const p = read("mirqab.persona", localStorage); return PERSONAS.includes(p) ? p : "everyone"; };
export const setPersona = (p) => write("mirqab.persona", p, localStorage);

// Ask LIVE to open the intelligence view once it has loaded.
export function goExplore(target) {
  write("mirqab.openIntel", target);
  if (document.querySelector(".cst")) window.dispatchEvent(new Event("mirqab-explore"));   // already on LIVE
  else location.hash = "#/radar";
}
export function takeExplore() { const v = read("mirqab.openIntel"); write("mirqab.openIntel", null); return v; }

// A slim bar that keeps the threat in view and leads back to its intelligence.
export function journeyBar({ onClose } = {}) {
  const j = getJourney();
  if (!j) return null;
  const bar = h("div", { class: `jb ${j.status}`, role: "region", "aria-label": t("jb.label") },
    h("span", { class: "jb-dot", "aria-hidden": "true" }),
    h("span", { class: "jb-text" }, h("span", { class: "jb-k" }, t("jb.protecting")), h("b", {}, L(j, "name")),
      h("span", { class: `badge ${j.status === "confirmed" ? "critical" : "inference"}` }, t(`warn.${j.status}`))),
    h("button", { class: "jb-btn", type: "button", onclick: () => goExplore(j.target) }, `◎ ${t("jb.back")}`),
    h("button", { class: "jb-x", type: "button", "aria-label": t("jb.clear"), onclick: () => { clearJourney(); bar.remove(); onClose?.(); } }, "✕"));
  return bar;
}
