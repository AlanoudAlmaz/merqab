// Contextual intelligence view for MERQAB LIVE: Detect → Explore → Understand → Prevent.
// Opens over the radar when a campaign or finding is explored. The Scam Campaign DNA graph has two kinds
// of edge only — "this site carries this trait" and an explained link between two sites — both from
// /api/radar/intel. Evidence shown is public (CT log / OpenPhish); case data appears only for signed-in users.
import cytoscape from "../vendor/cytoscape.esm.min.js";
import { api, errorBox, fmtTime, h, L, t } from "./core.js";
import { getPersona, PERSONAS, setJourneyFromIntel, setPersona } from "./journey.js";

const REDUCED = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const defang = (x) => x.replace(/\./g, "[.]");
const short = (s, n = 28) => s.length > n ? s.slice(0, n - 1) + "…" : s;
let open = null;   // { root, cy, onKey }

export function closeIntel() {
  if (!open) return;
  open.cy?.destroy();
  document.removeEventListener("keydown", open.onKey);
  open.root.remove();
  document.body.classList.remove("cst-locked");
  open.restoreFocus?.focus?.({ preventScroll: true });
  open = null;
}

const STYLE = [
  { selector: "node[kind='site']", style: { "width": "data(size)", "height": "data(size)", "background-color": "#a78bfa",
    "label": "data(label)", "font-size": 10, "color": "#c7d6df", "text-valign": "bottom", "text-margin-y": 5, "min-zoomed-font-size": 7,
    "text-background-color": "#081621", "text-background-opacity": 0.75, "text-background-padding": 2, "text-background-shape": "roundrectangle",
    "underlay-color": "#a78bfa", "underlay-opacity": 0.18, "underlay-padding": 5, "z-index": 10 } },
  { selector: "node[kind='site'][status='confirmed']", style: { "background-color": "#fb7185", "underlay-color": "#fb7185" } },
  { selector: "node[kind='gene']", style: { "shape": "round-rectangle", "width": "label", "height": 22, "padding": 8,
    "background-color": "#0e2a3b", "border-width": 1.5, "border-color": "#5eead4", "label": "data(label)", "font-size": 10,
    "font-weight": 600, "color": "#99f6e4", "text-valign": "center", "text-halign": "center", "z-index": 12 } },
  { selector: "edge[kind='carries']", style: { "width": 1.2, "line-color": "#5eead4", "opacity": 0.28, "curve-style": "straight", "line-style": "dotted" } },
  { selector: "edge[kind='link']", style: { "width": 2, "line-color": "#f0abfc", "opacity": 0.7, "curve-style": "unbundled-bezier",
    "control-point-distances": 30, "line-style": "dashed", "line-dash-pattern": [7, 5] } },
  { selector: "edge[kind='link'][strength='strong']", style: { "width": 3, "opacity": 0.9 } },
  { selector: "edge[kind='link'][strength='weak']", style: { "width": 1.4, "opacity": 0.5, "line-dash-pattern": [2, 6] } },
  { selector: ".dim", style: { "opacity": 0.1 } },
  { selector: "node.hl", style: { "border-color": "#ffffff", "border-width": 2.5 } },
  { selector: "edge.hl", style: { "opacity": 1, "line-color": "#ffffff" } },
  { selector: "node.hl[kind='site']", style: { "min-zoomed-font-size": 0, "z-index": 30 } },
  { selector: "node.focus", style: { "border-color": "#fde68a", "border-width": 3 } },
];

function dnaElements(d) {
  const els = [];
  const sites = [...d.sites].sort((a, b) => a.first_seen.localeCompare(b.first_seen));
  const R2 = Math.max(170, Math.min(sites.length * 26, 560)), R1 = d.genes.length > 1 ? Math.max(70, R2 * 0.42) : 0;
  sites.forEach((s, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(1, sites.length);
    els.push({ data: { id: `s${s.id}`, kind: "site", status: s.status, label: short(s.host), size: 16 + Math.round(((s.score || 40) - 40) / 60 * 14) },
      position: sites.length === 1 ? { x: 0, y: R2 * 0.55 } : { x: R2 * Math.cos(a), y: R2 * Math.sin(a) } });
  });
  d.genes.forEach((g, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(1, d.genes.length);
    els.push({ data: { id: g.id, kind: "gene", label: `${L(g, "label")}: ${short(g.value, 22)}` },
      position: d.genes.length === 1 ? { x: 0, y: 0 } : { x: R1 * Math.cos(a), y: R1 * Math.sin(a) } });
    g.members.forEach(m => els.push({ data: { id: `${g.id}-s${m}`, kind: "carries", source: `s${m}`, target: g.id } }));
  });
  d.links.forEach((l, i) => els.push({ data: { id: `l${i}`, kind: "link", source: `s${l.a}`, target: `s${l.b}`, strength: l.strength, i } }));
  return els;
}

function sourceLine(s) {
  const ev = s.evidence || {};
  return s.status === "confirmed"
    ? [t("cst.src_feed"), s.active ? t("radar.listed") : t("radar.not_listed"), ev.fetched_at ? fmtTime(ev.fetched_at) : null].filter(Boolean).join(" · ")
    : [t("cst.src_ct"), ev.log, ev.issuer ? `${t("cst.issuer")} ${ev.issuer}` : null, ev.certificate_time ? fmtTime(ev.certificate_time) : null].filter(Boolean).join(" · ");
}

// Evidence basis: confirmed vs suspected share, sources, time span, strongest explained link.
function basisBar(d) {
  const b = d.basis, n = b.confirmed + b.suspected;
  const src = Object.entries(b.sources).map(([k, v]) => h("span", { class: "iv-src" }, `${t(k === "ct" ? "cst.src_ct" : "cst.src_feed")} ×${v}`));
  return h("div", { class: "iv-basis" },
    h("div", { class: "iv-split", role: "img", "aria-label": `${b.confirmed} ${t("radar.confirmed_short")}, ${b.suspected} ${t("radar.suspected_short")}` },
      b.confirmed ? h("i", { class: "c", style: { flex: b.confirmed } }) : null, b.suspected ? h("i", { class: "s", style: { flex: b.suspected } }) : null),
    h("div", { class: "iv-basis-row small" },
      h("span", {}, h("b", { class: "c" }, b.confirmed), ` ${t("radar.confirmed_short")}`, b.confirmed ? ` (${b.listed_now} ${t("iv.listed_now")})` : ""),
      h("span", {}, h("b", { class: "s" }, b.suspected), ` ${t("radar.suspected_short")}`),
      ...src,
      h("span", { class: "muted" }, `${fmtTime(b.first_seen)} → ${fmtTime(b.last_seen)}`)),
    b.strongest ? h("div", { class: "small muted" }, `${t("iv.strongest")}: `, h("bdi", {}, L(b.strongest, "reason"))) : null,
    n && !b.confirmed ? h("div", { class: "small iv-unverified" }, t("iv.unverified_note")) : null);
}

export async function openIntel(target, { refresh } = {}) {
  closeIntel();
  const body = h("div", { class: "iv-body" }, h("p", { class: "muted" }, t("common.loading")));
  const closeBtn = h("button", { class: "iv-close", type: "button", "aria-label": t("iv.close"), onclick: closeIntel }, "✕");
  const head = h("div", { class: "iv-head" }, h("div", { class: "iv-title" }, h("div", { class: "iv-kicker" }, t("iv.kicker"))), closeBtn);
  const root = h("div", { class: "iv", role: "dialog", "aria-modal": "true", "aria-label": t("iv.kicker") },
    h("div", { class: "iv-backdrop", onclick: closeIntel }), h("div", { class: "iv-card" }, head, body));
  const onKey = (e) => { if (e.key === "Escape") closeIntel(); };
  open = { root, cy: null, onKey, restoreFocus: document.activeElement };
  document.addEventListener("keydown", onKey);
  document.body.append(root);
  document.body.classList.add("cst-locked");
  closeBtn.focus({ preventScroll: true });
  const q = new URLSearchParams(target.campaign_id ? { campaign_id: target.campaign_id } : { item_id: String(target.item_id) });
  let d;
  try { d = await api(`/radar/intel?${q}`); } catch (e) { body.replaceChildren(errorBox(e)); return; }
  if (!open || open.root !== root) return;
  render(d, head, body, refresh);
}

function render(d, head, body, refresh) {
  const c = d.campaign;
  const byId = Object.fromEntries(d.sites.map(s => [s.id, s]));
  const focusSite = d.focus != null ? byId[d.focus] : null;
  const statusOf = c ? c.status : d.sites[0].status;
  head.querySelector(".iv-title").replaceChildren(
    h("div", { class: "iv-kicker" }, t("iv.kicker"), c ? ` · ${c.id}` : ""),
    h("h2", {}, c ? L(c, "name") : h("code", {}, defang(d.sites[0].host))),
    h("div", { class: "row small" },
      h("span", { class: `badge ${statusOf === "confirmed" ? "critical" : "inference"}` }, t(`warn.${statusOf}`)),
      c ? h("span", { class: "muted" }, `${c.size} ${t("radar.sites")} · ${t("radar.conf")} ${t(`conf.${c.confidence}`)}`) : null,
      d.warnings.length ? h("span", { class: "badge verified" }, t("cst.warned_public")) : null),
    basisBar(d));

  // ---------- Explore: DNA graph
  const graphBox = h("div", { class: "iv-graph", role: "img",
    "aria-label": `${t("iv.dna")}: ${d.sites.length} ${t("radar.sites")}, ${d.genes.length} ${t("iv.traits")}, ${d.links.length} ${t("cst.links")}` });
  const caption = h("div", { class: "iv-caption", "aria-live": "polite" }, t("iv.tap_hint"));
  const detail = h("div", { class: "iv-site" });
  const scrub = h("div", { class: "iv-scrub" });

  // ---------- Detect: evidence per site, in the order MERQAB first saw them
  const sorted = [...d.sites].sort((a, b) => a.first_seen.localeCompare(b.first_seen));
  const evidence = h("ol", { class: "iv-ev" }, ...sorted.map(s => h("li", {},
    h("button", { class: "iv-ev-btn", type: "button", onclick: () => pickSite(s.id) },
      h("span", { class: `dot ${s.status === "confirmed" ? "error" : "suspect"}` }),
      h("code", {}, defang(short(s.host, 36))), h("span", { class: "muted small" }, fmtTime(s.first_seen))),
    h("div", { class: "small muted" }, sourceLine(s)))));

  // ---------- Understand: why linked, harm, uncertainty
  const reasons = new Map();
  for (const l of d.links) { const k = l.strength + l.reason_en; reasons.set(k, [l, (reasons.get(k)?.[1] || 0) + 1]); }
  const understand = h("div", {},
    h("p", { class: "iv-harm" }, h("b", {}, `${t("radar.harm")}: `), L(d, "harm")),
    reasons.size ? h("ul", { class: "list-plain small" }, ...[...reasons.values()].map(([l, n]) => h("li", {},
      h("span", { class: `badge ${l.strength === "strong" ? "high" : l.strength === "moderate" ? "medium" : ""}` }, t(`radar.strength.${l.strength}`)), " ",
      h("bdi", {}, L(l, "reason")), n > 1 ? h("span", { class: "muted" }, ` × ${n}`) : null))) : null,
    c ? h("p", { class: "small muted" }, L(c, "uncertainty")) : h("p", { class: "small muted" }, t("iv.single_note")));

  // ---------- Prevent: what comes next, what to avoid, and three ways to act on it
  const warnings = d.warnings.length
    ? h("div", { class: "iv-warns" }, ...d.warnings.map(w => h("div", { class: "iv-warn" },
        h("div", { class: "row" }, h("span", { class: "badge verified" }, t("iv.approved")), h("b", {}, L(w, "title"))),
        h("p", { class: "small" }, L(w, "summary")),
        w.covers.length ? h("p", { class: "small muted" }, `${t("iv.covers")}: `, ...w.covers.map(x => h("code", {}, `${defang(x)} `))) : null)))
    : null;
  const sorted2 = sorted;
  const personaTip = h("p", { class: "iv-tip" });
  const personas = h("div", { class: "iv-personas", role: "radiogroup", "aria-label": t("iv.for_who") });
  const drawPersona = () => {
    const p = getPersona();
    personas.querySelectorAll("button").forEach(b => { const on = b.dataset.p === p; b.classList.toggle("on", on); b.setAttribute("aria-checked", String(on)); });
    personaTip.textContent = t(`pt.${p}`);
  };
  PERSONAS.forEach(p => personas.append(h("button", { type: "button", role: "radio", "data-p": p, onclick: () => { setPersona(p); drawPersona(); } }, t(`aud.${p}`))));
  drawPersona();
  const go = (hash) => () => { setJourneyFromIntel(d); closeIntel(); location.hash = hash; };
  const shareText = (w) => [`⚠️ ${L(w, "title")}`, "", L(w, "summary"), ...(w.actions || []).map(a => `• ${L(a)}`), "", `— ${t("sh.wa_sign")}`].join("\n");
  const journey = h("div", { class: "iv-journey" },
    h("button", { class: "iv-act", type: "button", onclick: go("#/home") }, h("span", { class: "iv-act-i" }, "🔍"),
      h("span", {}, h("b", {}, t("iv.act_check")), h("small", {}, t("iv.act_check_sub")))),
    h("button", { class: "iv-act", type: "button", onclick: go("#/community") }, h("span", { class: "iv-act-i" }, "🧭"),
      h("span", {}, h("b", {}, t("iv.act_learn")), h("small", {}, t("iv.act_learn_sub")))),
    d.warnings.length
      ? h("a", { class: "iv-act share", target: "_blank", rel: "noopener noreferrer", href: `https://wa.me/?text=${encodeURIComponent(shareText(d.warnings[0]))}` },
          h("span", { class: "iv-act-i" }, "📣"), h("span", {}, h("b", {}, t("iv.act_share")), h("small", {}, L(d.warnings[0], "title"))))
      : h("div", { class: "iv-act off", "aria-disabled": "true" }, h("span", { class: "iv-act-i" }, "📣"),
          h("span", {}, h("b", {}, t("iv.act_share")), h("small", {}, t("iv.no_warning")))));
  const protect = h("div", { class: "iv-protect" },
    h("div", { class: "iv-next" }, h("span", { class: "iv-next-k" }, t("iv.next_step")), h("p", {}, L(d.script, "next")),
      h("div", { class: "iv-chain" }, ...d.script.tactics.map((tc, k) => h("span", { class: "iv-chain-i", title: L(tc, "explain") },
        k ? h("i", { "aria-hidden": "true" }, "→") : null, L(tc, "label"))))),
    h("div", { class: "iv-avoid" }, h("span", { class: "iv-next-k" }, t("iv.avoid")),
      h("ul", { class: "list-plain small iv-prevent" }, ...d.prevention.map(p => h("li", {}, L(p))))),
    h("div", { class: "iv-for" }, h("span", { class: "iv-next-k" }, t("iv.for_who")), personas, personaTip),
    journey, warnings);
  const actions = h("div", { class: "row actions iv-auth" });   // one public action: check this exact link
  const checkSite = focusSite || sorted2.find(s => s.status === "confirmed") || sorted2[0];
  actions.append(h("button", { class: "btn ghost sm", type: "button", onclick: () => {
    sessionStorage.setItem("mirqab.prefill", JSON.stringify({ kind: "url", content: checkSite.url || `https://${checkSite.host}`, autorun: true }));
    setJourneyFromIntel(d); closeIntel(); location.hash = "#/home";
  } }, t("iv.check_this")));
  const step = (n, key, ...kids) => h("section", { class: "iv-step" }, h("h3", {}, h("span", { class: "iv-n" }, String(n)), t(key)), ...kids);
  body.replaceChildren(
    h("div", { class: "iv-explore" }, h("div", { class: "iv-step-h" }, h("span", { class: "iv-n" }, "2"), t("iv.explore")),
      graphBox, scrub, caption, h("div", { class: "iv-legend small" },
        h("span", {}, h("i", { class: "lg-gene" }), t("iv.trait")), h("span", {}, h("i", { class: "lg-carries" }), t("iv.carries")),
        h("span", {}, h("i", { class: "lg-link" }), t("iv.link"))), detail),
    h("div", { class: "iv-side" },
      step(4, "iv.prevent", protect),   // public protection first
      step(1, "iv.detect", evidence),
      step(3, "iv.understand", understand, actions)));

  // ---------- graph
  const cy = cytoscape({ container: graphBox, elements: dnaElements(d), style: STYLE, layout: { name: "preset" },
    minZoom: 0.08, maxZoom: 3, wheelSensitivity: 0.35, boxSelectionEnabled: false, autoungrabify: false });
  open.cy = cy;
  cy.fit(undefined, 36);
  if (!REDUCED) {  // traits settle first, then each site arrives in detection order
    const step = Math.min(60, 1200 / Math.max(1, d.sites.length));   // whole arrival stays under ~1.3 s
    cy.nodes("[kind='site']").forEach((n, i) => { const p = { ...n.position() }; n.position({ x: p.x * 0.6, y: p.y * 0.6 }).style("opacity", 0);
      n.delay(80 + i * step).animate({ position: p, style: { opacity: 1 } }, { duration: 500, easing: "ease-out-cubic" }); });
  }
  const clear = () => cy.elements().removeClass("dim hl");
  const spotlight = (eles) => { clear(); cy.elements().not(eles).addClass("dim"); eles.addClass("hl"); };
  function pickSite(id) {
    const s = byId[id]; const n = cy.getElementById(`s${id}`);
    spotlight(n.closedNeighborhood());
    const traits = d.genes.filter(g => g.members.includes(id));
    caption.replaceChildren(h("code", {}, defang(s.host)), ` — ${traits.length} ${t("iv.traits_shared")}`);
    detail.replaceChildren(h("div", { class: "iv-site-card" },
      h("div", { class: "row" }, h("span", { class: `badge ${s.status === "confirmed" ? "critical" : "inference"}` }, t(s.status === "confirmed" ? "radar.confirmed_short" : "radar.suspected_short")),
        h("span", { class: `badge ${s.risk_level}` }, `${t(`res.level.${s.risk_level}`)} · ${s.score ?? "—"}/100`)),
      h("code", { class: "iv-site-host" }, defang(s.host)),
      h("div", { class: "small muted" }, sourceLine(s)),
      h("div", { class: "small" }, `${t("cst.detected")} ${fmtTime(s.first_seen)} · ${t("radar.last_seen")} ${fmtTime(s.last_seen)}${s.seen_count > 1 ? ` · ×${s.seen_count}` : ""}`),
      s.reasons?.length ? h("div", { class: "small" }, s.reasons.map(r => L(r)).join(" · ")) : null));
  }
  cy.on("tap", "node[kind='gene']", (e) => {
    const g = d.genes.find(x => x.id === e.target.id());
    spotlight(e.target.closedNeighborhood());
    caption.replaceChildren(h("b", {}, `${L(g, "label")}: `), h("code", {}, g.value), ` — ${t("iv.carried_by")} ${g.members.length}/${d.sites.length} ${t("radar.sites")}`,
      g.radar_count > g.members.length ? ` · ${g.radar_count} ${t("iv.on_radar")}` : "");
    detail.replaceChildren();
  });
  cy.on("tap", "node[kind='site']", (e) => pickSite(Number(e.target.id().slice(1))));
  cy.on("tap", "edge[kind='link']", (e) => {
    const l = d.links[e.target.data("i")];
    spotlight(e.target.union(e.target.connectedNodes()));
    caption.replaceChildren(h("span", { class: `badge ${l.strength === "strong" ? "high" : l.strength === "moderate" ? "medium" : ""}` }, t(`radar.strength.${l.strength}`)), " ", h("bdi", {}, L(l, "reason")));
  });
  cy.on("tap", (e) => { if (e.target === cy) { clear(); caption.textContent = t("iv.tap_hint"); detail.replaceChildren(); } });
  if (focusSite) { cy.getElementById(`s${focusSite.id}`).addClass("focus"); pickSite(focusSite.id); }

  // Replay how the campaign grew: each step adds the next site in the order MERQAB first saw it.
  if (sorted.length > 2 && sorted.at(-1).first_seen > sorted[0].first_seen) {
    const out = h("output", { class: "small" });
    const range = h("input", { type: "range", min: "1", max: String(sorted.length), value: String(sorted.length), step: "1", "aria-label": t("iv.replay") });
    const show = () => {
      const k = Number(range.value), seen = new Set(sorted.slice(0, k).map(s => `s${s.id}`));
      cy.batch(() => cy.nodes("[kind='site']").forEach(n => {
        const on = seen.has(n.id());
        n.toggleClass("dim", !on); n.connectedEdges().toggleClass("dim", !on || n.connectedEdges().connectedNodes("[kind='site']").some(m => !seen.has(m.id())));
      }));
      out.textContent = `${fmtTime(sorted[k - 1].first_seen)} · ${k}/${sorted.length} ${t("radar.sites")}`;
    };
    range.addEventListener("input", show);
    scrub.replaceChildren(h("span", { class: "iv-next-k" }, `⏱ ${t("iv.replay")}`), range, out);
    out.textContent = `${fmtTime(sorted.at(-1).first_seen)} · ${sorted.length}/${sorted.length} ${t("radar.sites")}`;
  }
}
