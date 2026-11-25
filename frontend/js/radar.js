// Live Threat Radar — Threat Constellation.
// Every node is a stored radar finding; every edge is a link produced by Scam Campaign DNA with its
// stated reason (GET /api/radar/graph). Nothing is drawn for decoration. A keyboard/screen-reader
// friendly list view shows exactly the same data and uses the same detail panel and actions.
import cytoscape from "../vendor/cytoscape.esm.min.js";
import { api, errorBox, fmtTime, h, hasRole, L, locale, state, t, toast } from "./core.js";
import { closeIntel, openIntel } from "./intel.js";
import { takeExplore } from "./journey.js";
import { openReport } from "./report.js";

window.addEventListener("mirqab-explore", () => { const x = takeExplore(); if (x) openIntel(x); });

const REDUCED = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const REFRESH_MS = 15000;
const RECENT_MS = 60 * 60 * 1000;   // "newly discovered" = first seen within the last hour
let timer = null;
let cy = null;
let view = "graph";
const FILTER0 = { status: "all", brand: "", connectedOnly: true, source: "", since: "", minRisk: "", listedNow: false, warned: false, inCampaign: false };
let filter = { ...FILTER0 };
let searchTerm = "";
const GRAPH_LIMIT = 160;   // newest sites drawn; the rest stay reachable through search, filters and counts
let data = null;
let selected = null;           // {type: "node"|"campaign", id}
let openedAt = Date.now();
let playing = null;

// Stop running layouts/animations before tearing the graph down (switching view, filters or page).
function destroyCy() {
  if (!cy) return;
  stopMotion();
  try { cy.stop(true, false); cy.nodes().stop(true, false); } catch { /* already stopped */ }
  cy.destroy();
  cy = null;
}

export function stopRadar() {
  clearInterval(timer); timer = null;
  clearTimeout(playing); playing = null;
  closeIntel();
  destroyCy();
}

export function ago(iso) {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} ${t("radar.ago_s")}`;
  if (s < 3600) return `${Math.round(s / 60)} ${t("radar.ago_m")}`;
  if (s < 86400) return `${Math.round(s / 3600)} ${t("radar.ago_h")}`;
  return `${Math.round(s / 86400)} ${t("radar.ago_d")}`;
}
const secs = (n) => n == null ? "—" : ago(new Date(Date.now() - n * 1000).toISOString());
const fmtN = (n) => Number(n || 0).toLocaleString(locale());
const defang = (x) => x.replace(/\./g, "[.]");
const short = (host, n = 26) => host.length > n ? host.slice(0, n - 1) + "…" : host;
const dur = (a, b) => {
  const m = Math.round((new Date(b) - new Date(a)) / 60000);
  return m < 60 ? `+${m} ${t("radar.ago_m").split(" ")[0]}` : m < 1440 ? `+${Math.round(m / 60)} ${t("radar.ago_h").split(" ")[0]}` : `+${Math.round(m / 1440)} ${t("radar.ago_d").split(" ")[0]}`;
};

// ---------------------------------------------------------------- intelligence pipeline
// Sources → MIRGAB → results, as one live flow. Every number is from /api/radar: source health and
// freshness, certificates actually checked, the measured rate between two polls, and what came out.
function pipeline() {
  const el = (tag, cls, ...kids) => h(tag, { class: cls }, ...kids);
  const R = {};
  const lanes = el("div", "pl-lanes");
  R.ctDot = el("span", "dot idle"); R.ctMeta = el("div", "pl-meta"); R.ctLanes = lanes;
  R.opDot = el("span", "dot idle"); R.opMeta = el("div", "pl-meta"); R.opBig = el("b", "pl-big", "—"); R.feedLanes = el("div", "pl-lanes");
  R.certs = el("b", "pl-hero cst-num", "0"); R.rate = el("div", "pl-rate"); R.ratio = el("div", "pl-meta");
  R.conf = el("b", "pl-big", "—"); R.susp = el("b", "pl-big", "—"); R.camps = el("b", "pl-big", "—");
  R.pipeA = el("div", "pl-pipe"); R.pipeB = el("div", "pl-pipe");
  R.note = el("p", "pl-note"); R.note.hidden = true;
  const info = h("button", { class: "pl-info", type: "button", "aria-expanded": "false", "aria-label": t("pl.how"),
    onclick: () => { R.note.hidden = !R.note.hidden; info.setAttribute("aria-expanded", String(!R.note.hidden)); } }, "i");
  const node = el("section", "pl card-dark",
    el("div", "pl-col pl-src",
      el("div", "pl-h", t("pl.sources")),
      h("div", { class: "pl-box", title: t("pl.src_ct_tech") }, el("div", "pl-title", R.ctDot, t("pl.ct")), lanes, R.ctMeta),
      h("div", { class: "pl-box", title: t("pl.src_op_tech") }, el("div", "pl-title", R.opDot, t("pl.openphish")), R.feedLanes, el("div", "pl-line", R.opBig, ` ${t("pl.listed")}`), R.opMeta)),
    R.pipeA,
    el("div", "pl-col pl-core",
      el("div", "pl-h", t("pl.engine")),
      el("div", "pl-orb", el("div", "pl-ring"), el("div", "pl-ring r2"), el("div", "pl-orb-in", R.certs, el("span", "pl-sub", t("pl.certs_checked")))),
      R.rate, R.ratio),
    R.pipeB,
    el("div", "pl-col pl-out",
      el("div", "pl-h", t("pl.results")),
      el("div", "pl-res conf", R.conf, el("span", "", t("pl.confirmed"))),
      el("div", "pl-res susp", R.susp, el("span", "", t("pl.suspected"))),
      el("div", "pl-res camp", R.camps, el("span", "", t("pl.campaigns")))),
    info, R.note);
  let prev = null;
  function update(r, rollTo) {
    const s = r.service, src = Object.fromEntries(s.sources.map(x => [x.name, x]));
    const ct = src.ct || {}, cd = ct.detail || {};
    const feeds = s.sources.filter(x => x.name !== "ct");
    const stateCls = (x) => x.state === "ok" ? "running" : x.state === "degraded" ? "error" : "idle";
    const okFeeds = feeds.filter(f => f.state === "ok").length;
    const op = { state: okFeeds ? "ok" : feeds.some(f => f.state === "degraded") ? "degraded" : feeds[0]?.state };
    R.ctDot.className = `dot ${stateCls(ct)}`; R.opDot.className = `dot ${stateCls(op)}`;
    R.feedLanes.replaceChildren(...feeds.map(f => h("span", { class: `pl-lane ${f.state === "ok" ? "ok" : f.state === "degraded" ? "bad" : ""}`, title: `${L(f, "label")} — ${f.state}` },
      h("i", { style: { animationDelay: `${(f.name.length % 7) * 0.17}s` } }))));
    lanes.replaceChildren(...(cd.logs || []).map(l => h("span", { class: `pl-lane ${l.ok ? "ok" : "bad"}`, title: l.name },
      h("i", { style: { animationDelay: `${(l.name.length % 7) * 0.17}s` } }))));
    // count from the same per-log flags the lanes show, so the text and the bars always agree
    const okLogs = (cd.logs || []).filter(l => l.ok).length;
    R.ctMeta.textContent = [(cd.logs || []).length ? `${okLogs}/${cd.logs.length} ${t("radar.logs_ok")}` : null,
      cd.newest_certificate_age_seconds != null ? `${t("radar.newest_cert")} ${secs(cd.newest_certificate_age_seconds)}` : null].filter(Boolean).join(" · ") || "—";
    const listed = feeds.reduce((a, f) => a + (f.detail?.listed_now || 0), 0);
    const scanned = feeds.reduce((a, f) => a + (f.detail?.scanned || f.detail?.listed_now || 0), 0);
    R.opBig.textContent = feeds.some(f => f.detail?.listed_now != null) ? fmtN(listed) : "—";
    R.opMeta.textContent = `${okFeeds}/${feeds.length} ${t("pl.feeds_ok")}${scanned ? ` · ${fmtN(scanned)} ${t("pl.entries_scanned")}` : ""}`;
    const st = s.session_stats || {};
    rollTo(R.certs, st.certificates_processed || 0);
    const now = Date.now();
    if (prev && now > prev.t && (st.certificates_processed || 0) >= prev.n) {
      const rate = ((st.certificates_processed || 0) - prev.n) / ((now - prev.t) / 1000);
      R.rate.textContent = `≈ ${fmtN(Math.round(rate))} ${t("pl.per_sec")}`;
      // flow speed follows the measured rate; no flow when nothing is coming in
      const speed = rate > 0 ? Math.max(0.35, Math.min(3, 60 / Math.max(rate, 1))) : 0;
      for (const p of [R.pipeA, R.pipeB]) { p.style.setProperty("--flow", speed ? `${speed}s` : "0s"); p.classList.toggle("still", !speed); }
    } else if (!prev) R.rate.textContent = t("pl.measuring");
    prev = { t: now, n: st.certificates_processed || 0 };
    R.ratio.textContent = st.ct_flagged ? `${t("pl.one_in")} ${fmtN(Math.round((st.certificates_processed || 0) / st.ct_flagged))} ${t("pl.flagged")}` : "";
    R.conf.textContent = fmtN(r.counts.confirmed_listed_now);
    R.susp.textContent = fmtN(r.counts.suspected);
    R.camps.textContent = fmtN(r.counts.campaigns);
    R.pipeA.classList.toggle("down", ct.state !== "ok" && op.state !== "ok");
    R.note.textContent = `${L(s, "coverage_note")} ${t("cst.refresh_note")}`;
  }
  return { node, update };
}

// ---------------------------------------------------------------- graph (radar projection)
// Every position encodes data: distance from the centre = how long ago MIRGAB first saw the site
// (rings: 1 h, 24 h, 7 d, older); angle = its campaign sector. Nothing is placed for decoration.
const RINGS = [{ ms: 3600e3, r: 130, key: "cst.ring_1h" }, { ms: 86400e3, r: 250, key: "cst.ring_24h" },
  { ms: 7 * 86400e3, r: 370, key: "cst.ring_7d" }, { ms: 60 * 86400e3, r: 480, key: "cst.ring_old" }];
const R_MAX = 480;
const CONF = "#fb7185", SUSP = "#a78bfa", TEAL = "#5eead4";

function radiusFor(firstSeen) {
  const age = Math.max(0, Date.now() - new Date(firstSeen).getTime());
  let lo = 34, loMs = 0;
  for (const ring of RINGS) {
    if (age <= ring.ms) {
      const f = Math.log1p(age - loMs) / Math.log1p(ring.ms - loMs);
      return lo + (ring.r - lo) * Math.min(1, Math.max(0, f));
    }
    lo = ring.r; loMs = ring.ms;
  }
  return R_MAX;
}

const STYLE = [
  { selector: "node[type='ring']", style: { "shape": "ellipse", "width": "data(d)", "height": "data(d)", "background-opacity": 0,
    "border-width": 1.5, "border-color": TEAL, "border-opacity": 0.18, "events": "no", "label": "data(label)", "font-size": 15,
    "color": "#5d8598", "text-valign": "top", "text-margin-y": 22, "z-index": 0 } },
  { selector: "node[type='finding']", style: {
    "width": "data(size)", "height": "data(size)", "background-color": SUSP, "border-width": 0,
    "underlay-color": SUSP, "underlay-opacity": 0.18, "underlay-padding": 6, "underlay-shape": "ellipse",
    "label": "data(label)", "font-size": 15, "color": "#c7d6df", "text-valign": "bottom", "text-margin-y": 4,
    "min-zoomed-font-size": 34, "text-max-width": 160, "text-wrap": "ellipsis", "z-index": 10,
    "text-background-color": "#081621", "text-background-opacity": 0.7, "text-background-padding": 2, "text-background-shape": "roundrectangle",
    "transition-property": "opacity, overlay-opacity, background-color", "transition-duration": "250ms" } },
  { selector: "node[status='confirmed']", style: { "background-color": CONF, "underlay-color": CONF } },
  { selector: "node[?warned]", style: { "border-color": TEAL, "border-width": 2 } },
  { selector: "node[type='campaign']", style: { "shape": "round-rectangle", "width": "label", "height": 22, "padding": 7,
    "background-color": "#0b1f2e", "background-opacity": 0.85, "border-width": 1, "border-color": TEAL, "border-opacity": 0.35,
    "label": "data(label)", "font-size": 15, "font-weight": 600, "color": TEAL, "text-valign": "center", "text-halign": "center", "z-index": 5,
    "transition-property": "opacity", "transition-duration": "250ms" } },
  { selector: "node[type='campaign'][status='confirmed']", style: { "border-color": CONF, "color": "#fda4af" } },
  { selector: "node[type='sector']", style: { "background-opacity": 0, "width": 1, "height": 1, "label": "data(label)", "font-size": 15,
    "color": "#6f8796", "events": "no", "text-valign": "center", "text-halign": "center" } },
  // Links point from the site MIRGAB saw first to the one seen later; the flowing dashes show that direction.
  { selector: "edge", style: { "width": 2, "line-color": TEAL, "opacity": 0.55, "curve-style": "unbundled-bezier",
    "control-point-distances": 26, "control-point-weights": 0.5, "z-index": 8,
    "line-style": "dashed", "line-dash-pattern": [7, 5], "target-arrow-shape": "triangle", "target-arrow-color": TEAL,
    "arrow-scale": 0.6, "transition-property": "opacity, width", "transition-duration": "250ms" } },
  { selector: "edge[strength='strong']", style: { "width": 3, "opacity": 0.9, "line-dash-pattern": [12, 5] } },
  { selector: "edge[strength='weak']", style: { "width": 1.5, "opacity": 0.45, "line-dash-pattern": [3, 7] } },
  { selector: "node[?recent]", style: { "underlay-color": TEAL, "underlay-opacity": 0.35, "underlay-padding": 6 } },
  { selector: "node.blip", style: { "underlay-opacity": 0.6, "underlay-padding": 13 } },
  { selector: "node.hover", style: { "border-color": "#ffffff", "border-width": 2, "min-zoomed-font-size": 0, "z-index": 30 } },
  { selector: "edge.hover", style: { "opacity": 1, "line-color": "#99f6e4", "target-arrow-color": "#99f6e4" } },
  { selector: ".dim", style: { "opacity": 0.12 } },
  { selector: ".hit", style: { "overlay-color": "#facc15", "overlay-opacity": 0.45, "overlay-padding": 9, "opacity": 1 } },
  { selector: "node.hl", style: { "border-color": "#ffffff", "border-width": 2, "opacity": 1, "min-zoomed-font-size": 0, "z-index": 25 } },
  { selector: "edge.hl", style: { "line-color": "#ffffff", "target-arrow-color": "#ffffff", "opacity": 1, "width": 2.4 } },
  { selector: ".fresh", style: { "overlay-color": TEAL, "overlay-opacity": 0.35, "overlay-padding": 8 } },
  { selector: ".step", style: { "overlay-color": "#fde68a", "overlay-opacity": 0.45, "overlay-padding": 8 } },
];

function elementsFor(d) {
  const els = RINGS.map((ring, i) => ({ data: { id: `ring${i}`, type: "ring", d: ring.r * 2, label: t(ring.key) }, position: { x: 0, y: 0 }, locked: true, selectable: false }));
  const shown = new Set(d.campaigns.map(c => c.id));
  for (const c of d.campaigns) els.push({ data: { id: `c:${c.id}`, type: "campaign", status: c.status, label: `${c.id} · ${c.size}` } });
  for (const n of d.nodes) {
    els.push({ data: { id: `n${n.id}`, type: "finding", status: n.status, label: short(n.host), warned: n.alert_status === "published",
      recent: Date.now() - new Date(n.first_seen).getTime() < RECENT_MS, host: n.host, first_seen: n.first_seen,
      camp: n.campaign_id && shown.has(n.campaign_id) ? n.campaign_id : null, brand: n.brand || "",
      size: 15 + Math.round(((n.score || 40) - 40) / 60 * 16) } });
  }
  const seen = Object.fromEntries(d.nodes.map(n => [n.id, n.first_seen]));
  for (const e of d.edges) {
    const [a, b] = (seen[e.source] || "") <= (seen[e.target] || "") ? [e.source, e.target] : [e.target, e.source];
    els.push({ data: { id: e.id, source: `n${a}`, target: `n${b}`, strength: e.strength } });
  }
  return els;
}

// Sectors: one per campaign (largest first), then one for findings with no explainable link.
// Sector width grows with member count; inside a sector sites are spread by detection order.
function layoutAll({ fit = true } = {}) {
  if (!cy) return;
  const finds = cy.nodes("[type='finding']");
  const groups = new Map();
  finds.forEach(n => { const k = n.data("camp") || "~"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n); });
  const keys = [...groups.keys()].sort((a, b) => a === "~" ? 1 : b === "~" ? -1 : groups.get(b).length - groups.get(a).length);
  const weight = (k) => 2.2 + Math.sqrt(groups.get(k).length) * 1.4;
  const total = keys.reduce((s, k) => s + weight(k), 0) || 1;
  const GAP = keys.length > 1 ? 0.05 : 0;
  const usable = 2 * Math.PI - GAP * keys.length;
  let ang = -Math.PI / 2;
  cy.batch(() => {
    cy.nodes("[type='sector']").remove();
    for (const k of keys) {
      const span = usable * weight(k) / total;
      const members = groups.get(k).sort((a, b) => a.data("first_seen").localeCompare(b.data("first_seen")));
      let outer = 0;
      members.forEach((n, i) => {
        const r = radiusFor(n.data("first_seen"));
        // spread along the arc; alternate small radial offsets so same-age sites don't overlap
        const a = ang + span * (members.length === 1 ? 0.5 : 0.08 + 0.84 * i / (members.length - 1));
        const rr = Math.min(R_MAX, r + ((i % 3) - 1) * Math.min(14, span * r / Math.max(members.length, 1) * 0.6));
        n.position({ x: rr * Math.cos(a), y: rr * Math.sin(a) });
        n.data("ang", a); outer = Math.max(outer, rr);
      });
      const mid = ang + span / 2, lr = Math.min(R_MAX + 40, outer + 85);
      if (k === "~") cy.add({ data: { id: "sector~", type: "sector", label: `${t("cst.unlinked")} · ${members.length}` }, position: { x: lr * Math.cos(mid), y: lr * Math.sin(mid) } });
      else cy.getElementById(`c:${k}`).position({ x: lr * Math.cos(mid), y: lr * Math.sin(mid) });
      ang += span + GAP;
    }
  });
  // Fit the data (sites and campaign labels), not the empty outer rings, so the radar fills the space.
  if (fit) {
    const content = cy.nodes("[type='finding'], [type='campaign'], [type='sector']");
    cy.fit(content.nonempty() ? content : cy.nodes("[type='ring']"), 28);
    if (cy.zoom() > 1.4) cy.zoom({ level: 1.4, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }
}
function runLayout(fit = true) { layoutAll({ fit }); }

// ---------------------------------------------------------------- motion (every movement encodes real data)
// The sweep makes one turn per refresh cycle (its position = time until the next real update). Sites light
// up as it passes them; flowing dashes show the direction a campaign spread; new sites (< 1 h) pulse.
let raf = null;
const sweep = { el: null, start: 0 };
export function sweepSync() {
  if (!cy || !sweep.el) return;
  const p = cy.pan(), z = cy.zoom(), size = 2 * R_MAX * z;
  Object.assign(sweep.el.style, { width: `${size}px`, height: `${size}px`, left: `${p.x - size / 2}px`, top: `${p.y - size / 2}px` });
}
function startMotion() {
  stopMotion();
  sweepSync();
  if (REDUCED || !cy) return;
  const owner = cy;
  let last = 0, offset = 0;
  const flow = cy.edges().length <= 80 ? cy.edges() : null;   // animating hundreds of dashes redraws everything each frame
  const finds = cy.nodes("[type='finding']");
  const recent = cy.nodes("[?recent]").slice(0, 25);
  const frame = (ts) => {
    if (cy !== owner) return;
    raf = requestAnimationFrame(frame);
    if (document.hidden || ts - last < 80) return;
    last = ts;
    offset = (offset - 0.7) % 1000;
    const phase = (ts % 2200) / 2200;
    const theta = (((Date.now() - sweep.start) % REFRESH_MS) / REFRESH_MS) * 2 * Math.PI;  // from 12 o'clock, clockwise
    if (sweep.el) sweep.el.style.transform = `rotate(${theta}rad)`;
    cy.batch(() => {
      if (flow) flow.style("line-dash-offset", offset);
      finds.forEach(n => {
        const lag = ((theta - (n.data("ang") + Math.PI / 2)) % (2 * Math.PI) + 2 * Math.PI) % (2 * Math.PI);
        const lit = lag < 0.6;
        if (lit !== n.hasClass("blip")) n.toggleClass("blip", lit);
      });
      if (recent.length) recent.style({ "underlay-padding": 5 + phase * 20, "underlay-opacity": 0.5 * (1 - phase) });
    });
  };
  raf = requestAnimationFrame(frame);
}
function stopMotion() { if (raf) cancelAnimationFrame(raf); raf = null; }

// Arrival: each site travels out from the centre to its ring — newer sites have the shortest trip.
function introAnimation() {
  if (REDUCED || !cy) return;
  const finds = cy.nodes("[type='finding']");
  const targets = new Map(finds.map(n => [n.id(), { ...n.position() }]));
  cy.batch(() => { finds.positions({ x: 0, y: 0 }); finds.style("opacity", 0); });
  finds.forEach((n, i) => n.delay(Math.min(i * 4, 700)).animate({ position: targets.get(n.id()), style: { opacity: 1 } },
    { duration: 900, easing: "ease-out-cubic" }));
}

function buildGraph(container, d, onSelect, tip, sweepEl) {
  destroyCy();
  cy = cytoscape({ container, elements: elementsFor(d), style: STYLE, layout: { name: "preset" },
    minZoom: 0.2, maxZoom: 4, wheelSensitivity: 0.35, boxSelectionEnabled: false, selectionType: "single", autoungrabify: true,
    pixelRatio: Math.min(window.devicePixelRatio || 1, 1.25), textureOnViewport: true, hideEdgesOnViewport: d.nodes.length > 120 });
  sweep.el = sweepEl || null;
  if (!sweep.start) sweep.start = Date.now();
  layoutAll({ fit: true });
  introAnimation();
  startMotion();
  cy.on("viewport resize", () => { tip.hidden = true; sweepSync(); });
  cy.on("mouseover", "node[type='finding']", (e) => {
    const n = e.target;
    n.addClass("hover"); n.connectedEdges().addClass("hover");
    const p = n.renderedPosition();
    tip.replaceChildren(h("code", {}, defang(n.data("host"))), h("div", {},
      `${n.data("status") === "confirmed" ? t("radar.confirmed_short") : t("radar.suspected_short")} · ${t("radar.first_seen")} ${ago(n.data("first_seen"))}`
      + (n.data("camp") ? ` · ${n.data("camp")}` : "")));
    tip.style.transform = `translate(${Math.round(p.x + 14)}px, ${Math.round(p.y - 10)}px)`;
    tip.hidden = false;
  });
  cy.on("mouseout", "node[type='finding']", (e) => { e.target.removeClass("hover"); e.target.connectedEdges().removeClass("hover"); tip.hidden = true; });
  cy.on("tap", "node", (e) => {
    const n = e.target;
    if (n.data("type") === "campaign") onSelect({ type: "campaign", id: n.id().slice(2) });
    else if (n.data("type") === "finding") onSelect({ type: "node", id: Number(n.id().slice(1)) });
  });
  cy.on("tap", (e) => { if (e.target === cy) onSelect(null); });
  // double-tap goes straight to the intelligence view
  cy.on("dbltap", "node[type='finding'], node[type='campaign']", (e) => {
    const n = e.target;
    openIntel(n.data("type") === "campaign" ? { campaign_id: n.id().slice(2) } : { item_id: Number(n.id().slice(1)) });
  });
}
export function restartSweepCycle() { sweep.start = Date.now(); }

// Incremental update: only real changes from the API are applied; new findings get a short highlight.
function updateGraph(d) {
  if (!cy) return 0;
  const want = new Map(elementsFor(d).map(e => [e.data.id, e]));
  let added = 0, structural = false;
  cy.batch(() => {
    cy.elements().forEach(el => { if (el.data("type") !== "sector" && !want.has(el.id())) { el.remove(); structural = true; } });
    for (const [id, el] of want) {
      const cur = cy.getElementById(id);
      if (cur.nonempty()) {
        if (el.data.type === "finding") {
          if (cur.data("camp") !== el.data.camp) structural = true;
          cur.data({ status: el.data.status, warned: el.data.warned, label: el.data.label, recent: el.data.recent, camp: el.data.camp });
        } else if (el.data.type === "campaign") cur.data({ status: el.data.status, label: el.data.label });
        continue;
      }
      if (el.data.source) continue;
      cy.add({ ...el, position: el.position || { x: 0, y: 0 } });
      structural = true;
      if (el.data.type === "finding") {
        added++;
        const node = cy.getElementById(id);
        node.addClass("fresh");
        const owner = cy;
        setTimeout(() => { if (cy === owner && !node.removed()) node.removeClass("fresh"); }, REDUCED ? 0 : 4000);
      }
    }
    for (const [id, el] of want) if (el.data.source && cy.getElementById(id).empty()) { cy.add(el); structural = true; }
  });
  // positions depend on age, so re-project every refresh (sites drift outward as they get older)
  layoutAll({ fit: false });
  return added;
}

function highlight(sel) {
  if (!cy) return;
  cy.elements().removeClass("dim hl");
  if (!sel) return;
  let focus;
  if (sel.type === "campaign") {
    const members = cy.nodes(`[type='finding']`).filter(n => n.data("camp") === sel.id);
    focus = cy.getElementById(`c:${sel.id}`).union(members).union(members.connectedEdges());
  } else {
    const n = cy.getElementById(`n${sel.id}`);
    focus = n.closedNeighborhood();
    if (n.data("camp")) focus = focus.union(cy.getElementById(`c:${n.data("camp")}`));
  }
  if (focus.empty()) return;
  cy.elements().not(focus).not("[type='ring']").addClass("dim");
  focus.addClass("hl");
  cy.animate({ fit: { eles: focus, padding: 60 } }, { duration: REDUCED ? 0 : 350 });
}

// ---------------------------------------------------------------- explore (full intelligence opens in context)
function exploreRow(target, node, refresh) {
  const row = h("div", { class: "row actions" },
    h("button", { class: "btn sm", type: "button", onclick: () => openIntel(target, { refresh }) }, `◎ ${t("iv.open")}`));
  if (node) row.append(h("button", { class: "btn secondary sm", type: "button", onclick: () => {
    sessionStorage.setItem("mirqab.prefill", JSON.stringify({ kind: "url", content: node.url || `https://${node.host}`, autorun: true }));
    location.hash = "#/home";
  } }, t("cst.check")));
  return row;
}

const kv = (rows) => h("dl", { class: "kv small" }, rows.filter(Boolean).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
const statusBadge = (s, compact = false) => h("span", { class: `badge ${s === "confirmed" ? "critical" : "inference"}` },
  compact ? t(s === "confirmed" ? "radar.confirmed_short" : "radar.suspected_short") : t(`warn.${s}`));


function nodePanel(n, d, select, refresh) {
  const ev = n.evidence || {};
  const source = n.status === "confirmed"
    ? [`${t("cst.src_feed")}: ${(n.sources || []).filter(k => k !== "ct").map(k => t(`feed.${k}`)).join(", ")}`, n.active ? t("radar.listed") : t("radar.not_listed"), ev.fetched_at ? fmtTime(ev.fetched_at) : null].filter(Boolean).join(" · ")
    : [t("cst.src_ct"), ev.log, ev.issuer ? `${t("cst.issuer")} ${ev.issuer}` : null, ev.certificate_time ? `${t("radar.cert_issued")} ${fmtTime(ev.certificate_time)}` : null].filter(Boolean).join(" · ");
  const byId = Object.fromEntries(d.nodes.map(x => [x.id, x]));
  const rel = d.edges.filter(e => e.source === n.id || e.target === n.id);
  const camp = d.campaigns.find(c => c.id === n.campaign_id);
  return h("div", { class: "cst-panel-body" },
    h("div", { class: "row" }, statusBadge(n.status), h("span", { class: `badge ${n.risk_level}` }, t(`res.level.${n.risk_level}`)),
      n.alert_status === "published" ? h("span", { class: "badge verified" }, t("cst.warned_public")) : null),
    h("h3", { class: "cst-title" }, h("code", {}, defang(n.host))),
    kv([[t("cst.source"), source], [t("cst.detected"), `${fmtTime(n.first_seen)} (${ago(n.first_seen)})`],
        [t("radar.last_seen"), ago(n.last_seen)], [t("cst.risk"), `${t(`res.level.${n.risk_level}`)} · ${n.score ?? "—"}/100`],
        n.brand ? [t("cst.target"), n.brand] : null]),
    n.reasons?.length ? h("p", { class: "small" }, h("b", {}, `${t("cst.why_flagged")}: `), n.reasons.map(r => L(r)).join(" · ")) : null,
    h("h4", {}, `${t("cst.relationships")} (${rel.length})`),
    rel.length ? h("ul", { class: "list-plain small" }, rel.slice(0, 12).map(e => {
      const other = byId[e.source === n.id ? e.target : e.source];
      return h("li", {}, h("span", { class: `badge ${e.strength === "strong" ? "high" : e.strength === "moderate" ? "medium" : ""}` }, t(`radar.strength.${e.strength}`)), " ",
        h("button", { class: "linkish", type: "button", onclick: () => select({ type: "node", id: other.id }) }, h("code", {}, defang(short(other.host, 34)))),
        h("div", { class: "muted" }, h("bdi", {}, L(e, "reason"))));
    })) : h("p", { class: "small muted" }, t("cst.no_relationships")),
    camp ? h("p", { class: "small" }, h("b", {}, `${t("cst.campaign")}: `),
      h("button", { class: "linkish", type: "button", onclick: () => select({ type: "campaign", id: camp.id }) }, `${camp.id} · ${L(camp, "name")}`)) : null,
    exploreRow({ item_id: n.id }, n, refresh));
}

function campaignPanel(c, d, select, refresh) {
  const byId = Object.fromEntries(d.nodes.map(x => [x.id, x]));
  const members = c.members.map(id => byId[id]).filter(Boolean).sort((a, b) => a.first_seen.localeCompare(b.first_seen));
  const playBtn = h("button", { class: "btn ghost sm", type: "button", onclick: () => play(members) }, `▶ ${t("cst.replay")}`);
  return h("div", { class: "cst-panel-body" },
    h("div", { class: "row" }, statusBadge(c.status), h("span", { class: "small muted" }, `${c.id} · ${t("radar.conf")} ${t(`conf.${c.confidence}`)}`)),
    h("h3", { class: "cst-title" }, L(c, "name")),
    kv([[t("cst.indicators"), `${c.size} · ${c.confirmed} ${t("radar.confirmed_short")} / ${c.suspected} ${t("radar.suspected_short")}`],
        [t("radar.first_seen"), fmtTime(c.first_seen)], [t("radar.last_seen"), ago(c.last_seen)]]),
    h("div", { class: "row" }, h("h4", { style: { margin: 0 } }, t("cst.development")), view === "graph" && !REDUCED ? playBtn : null),
    h("ol", { class: "cst-timeline small" }, members.slice(0, 15).map((m, i) => h("li", {},
      h("span", { class: "mono muted" }, i === 0 ? fmtTime(m.first_seen) : dur(members[0].first_seen, m.first_seen)), " ",
      h("button", { class: "linkish", type: "button", onclick: () => select({ type: "node", id: m.id }) }, h("code", {}, defang(short(m.host, 30)))), " ",
      statusBadge(m.status, true)))),
    h("p", { class: "small muted" }, t("cst.dev_note")),
    exploreRow({ campaign_id: c.id }, null, refresh));
}

// Replays how a campaign appeared over time (real first-seen order); disabled for reduced motion.
function play(members) {
  if (!cy || REDUCED) return;
  clearTimeout(playing);
  const nodes = members.map(m => cy.getElementById(`n${m.id}`));
  nodes.forEach(n => n.addClass("dim"));
  let i = 0;
  const owner = cy;
  const step = () => {
    if (cy !== owner) return;  // graph was rebuilt or closed meanwhile
    if (i >= nodes.length) { nodes.forEach(n => n.removeClass("step dim")); return; }
    nodes[i].removeClass("dim").addClass("step");
    if (i > 0) nodes[i - 1].removeClass("step");
    i++;
    playing = setTimeout(step, 650);
  };
  step();
}

function overview(d, select) {
  return h("div", { class: "cst-panel-body" },
    h("p", { class: "small muted" }, t("cst.hint")),
    kv([[t("cst.indicators"), `${fmtN(d.totals.shown_nodes)} / ${fmtN(d.totals.findings)}`], [t("cst.links"), fmtN(d.totals.shown_links)],
        [t("radar.c.campaigns"), fmtN(d.campaigns.length)]]),
    d.campaigns.length ? h("div", { class: "cst-camps" }, d.campaigns.slice(0, 8).map(c => h("button", { class: `cst-camp ${c.status}`, type: "button",
      onclick: () => select({ type: "campaign", id: c.id }) },
      h("span", { class: "cst-camp-bar", style: { "--n": Math.min(1, c.size / 10) } }),
      h("span", { class: "cst-camp-name" }, L(c, "name")), h("span", { class: "cst-camp-n" }, c.size)))) : h("p", { class: "small muted" }, t("radar.no_campaigns")));
}

// ---------------------------------------------------------------- accessible list view (same data, same panel)
function listView(d, select) {
  const byCamp = new Map();
  for (const n of d.nodes.filter(n => !searchTerm || n.host.includes(searchTerm))) {
    const k = n.campaign_id || "";
    if (!byCamp.has(k)) byCamp.set(k, []);
    byCamp.get(k).push(n);
  }
  const rows = [];
  for (const c of d.campaigns) {
    rows.push(h("tr", { class: "grp" }, h("th", { colspan: "4", scope: "rowgroup" },
      h("button", { class: "linkish", type: "button", onclick: () => select({ type: "campaign", id: c.id }) }, `${c.id} · ${L(c, "name")}`), " ", statusBadge(c.status))));
    for (const n of byCamp.get(c.id) || []) rows.push(row(n));
    byCamp.delete(c.id);
  }
  const rest = [...byCamp.values()].flat();
  if (rest.length) rows.push(h("tr", { class: "grp" }, h("th", { colspan: "4", scope: "rowgroup" }, t("cst.unconnected"))), ...rest.map(row));
  function row(n) {
    return h("tr", {},
      h("td", {}, h("button", { class: "linkish", type: "button", onclick: () => select({ type: "node", id: n.id }) }, h("code", {}, defang(short(n.host, 40))))),
      h("td", {}, statusBadge(n.status, true)), h("td", {}, t(`res.level.${n.risk_level}`)), h("td", { class: "muted" }, ago(n.first_seen)));
  }
  return h("div", { class: "cst-list" }, h("table", {},
    h("caption", { class: "sr-only" }, t("cst.list_caption")),
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, t("cst.indicator")), h("th", { scope: "col" }, t("inv.status")),
      h("th", { scope: "col" }, t("cst.risk")), h("th", { scope: "col" }, t("cst.detected")))),
    h("tbody", {}, rows)));
}

// ---------------------------------------------------------------- page
export async function radarPage(root, focus) {
  stopRadar();
  data = null;
  openedAt = Date.now();
  selected = focus?.startsWith("C-") ? { type: "campaign", id: focus } : focus?.startsWith("i-") ? { type: "node", id: Number(focus.slice(2)) } : null;
  const pipe = pipeline();
  const liveBadge = h("span", { class: "live-badge" });
  const fresh = h("span", { class: "badge medium", hidden: true, role: "status" });
  const stage = h("div", { class: "cst-stage" });
  const graphBox = h("div", { class: "cst-graph", role: "img", tabindex: "-1" });
  const panel = h("aside", { class: "cst-panel", "aria-live": "polite" });
  const toolbar = h("div", { class: "cst-toolbar" });
  const brandSel = h("select", { "aria-label": t("cst.target"), class: "cst-select" });
  const filtersBox = h("details", { class: "cst-filters" });
  const chips = h("div", { class: "cst-chips" });
  let lookup = null;           // last link lookup result (shown in the side panel)
  const sInput = h("input", { type: "search", class: "rs-input", dir: "ltr", autocomplete: "off", spellcheck: "false",
    placeholder: t("rs.ph"), "aria-label": t("rs.label") });
  const sHint = h("span", { class: "rs-hint", role: "status" });
  const sForm = h("form", { class: "rs", role: "search" }, h("span", { class: "rs-i", "aria-hidden": "true" }, "⌕"), sInput, sHint,
    h("button", { class: "btn sm", type: "submit" }, t("rs.check")));
  // typing narrows what is shown (graph highlight / list rows); submitting checks the link against everything stored
  let sTimer;
  sInput.addEventListener("input", () => { clearTimeout(sTimer); sTimer = setTimeout(() => applySearch(sInput.value), 160); });
  sForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearTimeout(sTimer);
    const q = sInput.value.trim();
    if (q.length < 3) { sHint.textContent = t("rs.too_short"); return; }
    sHint.textContent = t("rs.checking");
    try {
      lookup = await api(`/radar/lookup?q=${encodeURIComponent(q)}`);
      sHint.textContent = "";
      selected = { type: "lookup" };
      renderPanel();
      if (lookup.found && view === "graph") highlight({ type: "node", id: lookup.found.id });
      if (window.innerWidth < 861) panel.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
    } catch (err) { sHint.textContent = err.message || t("rs.invalid"); }
  });
  function hostTerm(v) {
    return v.trim().toLowerCase().replace(/\[\.\]/g, ".").replace(/^h[tx]{2}ps?:\/\//, "").replace(/^www\./, "").split(/[/?#]/)[0];
  }
  function applySearch(v) {
    searchTerm = hostTerm(v);
    if (!data) return;
    const n = searchTerm ? data.nodes.filter(x => x.host.includes(searchTerm)).length : 0;
    sHint.textContent = searchTerm ? `${fmtN(n)} ${t("rs.in_view")}` : "";
    if (view === "graph" && cy) {
      cy.elements().removeClass("hit");
      if (!searchTerm) { highlight(selected?.type === "node" || selected?.type === "campaign" ? selected : null); return; }
      const hits = cy.nodes("[type='finding']").filter(x => x.data("host").includes(searchTerm));
      cy.elements().addClass("dim"); hits.removeClass("dim").addClass("hit");
      if (hits.length && hits.length <= 30) cy.animate({ fit: { eles: hits, padding: 120 }, duration: REDUCED ? 0 : 400 });
    } else drawStage();
  }
  async function showNode(id) {
    if (!data?.nodes.some(n => n.id === id)) { filter = { ...FILTER0, connectedOnly: false }; await load(true); }
    if (view !== "graph" && !data.nodes.some(n => n.id === id)) return;
    select({ type: "node", id });
  }
  function lookupPanel(r) {
    const a = r.analysis, f = r.found;
    const item = (x) => h("li", {}, h("button", { class: "linkish", type: "button", onclick: () => showNode(x.id) }, h("code", {}, defang(x.host))),
      " ", statusBadge(x.status, true), h("span", { class: "muted small" }, ` · ${ago(x.first_seen)}`));
    let verdict;
    if (f) verdict = h("div", { class: `rs-v ${f.status === "confirmed" ? "bad" : "warn"}` },
      h("b", {}, t(f.status === "confirmed" ? (f.listed_now ? "rs.v_listed" : "rs.v_was_listed") : "rs.v_suspected")),
      h("p", { class: "small" }, [`${t("radar.first_seen")} ${ago(f.first_seen)}`, f.brand ? `${t("rs.imitates")} ${f.brand}` : null,
        f.sources.map(k => k === "ct" ? t("cst.src_ct") : t(`feed.${k}`)).join(" · ")].filter(Boolean).join(" — ")),
      f.campaign ? h("button", { class: "linkish small", type: "button", onclick: () => select({ type: "campaign", id: f.campaign.id }) },
        `${t("rs.part_of")} ${f.campaign.id} · ${L(f.campaign, "name")} (${f.campaign.size})`) : null,
      h("div", { class: "rs-actions" }, h("button", { class: "btn sm", type: "button", onclick: () => showNode(f.id) }, t("rs.show")),
        h("button", { class: "btn ghost sm", type: "button", onclick: () => openIntel({ item_id: f.id }) }, t("rs.intel"))));
    else if (a.official_domain) verdict = h("div", { class: "rs-v ok" }, h("b", {}, t("rs.v_official")), h("p", { class: "small" }, t("rs.v_official_note")));
    else verdict = h("div", { class: `rs-v ${["high", "critical"].includes(a.level) ? "warn" : "none"}` },
      h("b", {}, t("rs.v_not_seen")),
      h("p", { class: "small" }, `${t("rs.engine_says")} ${t(`res.level.${a.level}`)}${a.impersonated_brand ? ` — ${t("rs.imitates")} ${a.impersonated_brand}` : ""}`));
    return h("div", { class: "cst-panel-body rs-panel" },
      h("div", { class: "sh-label" }, t("rs.result")),
      h("code", { class: "rs-host" }, defang(r.query_host)),
      verdict,
      a.signals.length ? h("div", {}, h("div", { class: "small muted" }, t("rs.signals")),
        h("ul", { class: "rs-sig small" }, ...a.signals.map(x => h("li", {}, L(x, ""))))) : null,
      r.same_domain.length ? h("div", {}, h("div", { class: "small muted" }, `${t("rs.same_domain")} ${r.registrable_domain}`), h("ul", { class: "rs-list" }, ...r.same_domain.map(item))) : null,
      r.same_brand && r.same_brand.count ? h("div", {}, h("div", { class: "small muted" }, `${t("rs.same_brand_a")} ${fmtN(r.same_brand.count)} ${t("rs.same_brand_b")} ${r.same_brand.brand}`),
        h("ul", { class: "rs-list" }, ...r.same_brand.recent.map(item)),
        h("button", { class: "btn ghost sm", type: "button", onclick: async () => { filter = { ...FILTER0, brand: r.same_brand.brand, connectedOnly: false }; selected = null; await load(true); } },
          `${t("rs.filter_brand")} ${r.same_brand.brand}`)) : null,
      h("div", { class: "rs-actions" }, h("a", { class: "btn secondary sm", href: "#/home" }, t("rs.full_check"))),
      h("p", { class: "small muted" }, L(r, "limits")));
  }
  // Motion that reports real state: the sweep turns once per refresh cycle; the countdown says when
  // the next one is; the ticker replays real detections; counters roll to the real values.
  const sweep = h("div", { class: "cst-sweep", "aria-hidden": "true" });
  const countdown = h("span", { class: "cst-count" });
  const hud = h("div", { class: "cst-hud" }, h("span", { class: "dot running" }), countdown);
  const tip = h("div", { class: "cst-tip", hidden: true, role: "tooltip" });
  const ticker = h("div", { class: "cst-ticker", "aria-live": "off" });
  let nextAt = Date.now() + REFRESH_MS;
  let events = [];          // real events only: detections and re-sightings from stored data
  let tickIdx = 0;
  let prevSeen = null;

  const select = (sel) => {
    selected = sel;
    renderPanel();
    if (view === "graph") highlight(sel);
    if (sel && window.innerWidth < 861) panel.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "start" });
  };
  const renderPanel = () => {
    if (!data) return;
    if (selected?.type === "lookup" && lookup) {
      panel.replaceChildren(h("button", { class: "btn ghost sm cst-close", type: "button", onclick: () => { lookup = null; select(null); } }, `× ${t("common.close")}`), lookupPanel(lookup));
      return;
    }
    const n = selected?.type === "node" ? data.nodes.find(x => x.id === selected.id) : null;
    const c = selected?.type === "campaign" ? data.campaigns.find(x => x.id === selected.id) : null;
    panel.replaceChildren(...[
      selected ? h("button", { class: "btn ghost sm cst-close", type: "button", onclick: () => select(null) }, `× ${t("common.close")}`) : null,
      n ? nodePanel(n, data, select, load) : c ? campaignPanel(c, data, select, load) : overview(data, select)].filter(Boolean));
  };
  const drawStage = () => {
    if (view === "graph") {
      stage.replaceChildren(graphBox, sweep, hud, tip, h("div", { class: "cst-zoom" },
        h("button", { type: "button", "aria-label": t("cst.zoom_in"), onclick: () => cy?.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: graphBox.clientWidth / 2, y: graphBox.clientHeight / 2 } }) }, "+"),
        h("button", { type: "button", "aria-label": t("cst.zoom_out"), onclick: () => cy?.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: graphBox.clientWidth / 2, y: graphBox.clientHeight / 2 } }) }, "−"),
        h("button", { type: "button", "aria-label": t("cst.fit"), onclick: () => layoutAll({ fit: true }) }, "⤢"),
        h("button", { type: "button", "aria-label": t("cst.rearrange"), title: t("cst.rearrange"), onclick: () => runLayout(true) }, "↻"),
        expandBtn),
        ticker, legend());
      buildGraph(graphBox, data, select, tip, sweep);
      graphBox.setAttribute("aria-label", `${t("cst.graph_label")}: ${data.nodes.length} ${t("cst.indicators")}, ${data.edges.length} ${t("cst.links")}. ${t("cst.use_list")}`);
      if (selected) highlight(selected);
    } else {
      destroyCy();
      stage.replaceChildren(listView(data, select));
    }
  };
  const drawToolbar = () => {
    const brands = [...new Set(data?.nodes.map(n => n.brand).filter(Boolean))].sort();
    brandSel.replaceChildren(h("option", { value: "" }, t("cst.all_targets")), ...brands.map(b => h("option", { value: b, selected: b === filter.brand }, b)));
    const seg = (name, val, label) => h("button", { type: "button", "aria-pressed": String(name === "view" ? view === val : filter.status === val),
      onclick: async () => { if (name === "view") { view = val; drawToolbar(); drawStage(); } else { filter.status = val; drawToolbar(); await load(true); } } }, label);
    const set = async (k, v) => { filter[k] = v; selected = selected?.type === "lookup" ? selected : null; await load(true); };
    const select_ = (k, opts, label) => h("label", { class: "fl-field" }, h("span", {}, label),
      h("select", { class: "cst-select", onchange: (e) => set(k, e.target.value) }, ...opts.map(([v, l]) => h("option", { value: v, selected: String(filter[k]) === v }, l))));
    const check = (k, label, invert = false) => h("label", { class: "checkline small" },
      h("input", { type: "checkbox", checked: invert ? !filter[k] : !!filter[k], onchange: (e) => set(k, invert ? !e.target.checked : e.target.checked) }), label);
    const feeds = ["openphish", "certpl", "phishing_army", "phishing_db", "blocklist_project"];
    const labels = {
      brand: filter.brand, source: filter.source && t(filter.source === "ct" ? "fl.src_ct" : filter.source === "feeds" ? "fl.src_feeds" : `feed.${filter.source}`),
      since: filter.since && t(`fl.since_${filter.since}`), minRisk: filter.minRisk && `≥ ${t(`res.level.${filter.minRisk}`)}`,
      listedNow: filter.listedNow && t("fl.listed_now"), warned: filter.warned && t("fl.warned"), inCampaign: filter.inCampaign && t("fl.in_campaign"),
      connectedOnly: !filter.connectedOnly && t("fl.unconnected"),
    };
    const active = Object.entries(labels).filter(([, v]) => v);
    filtersBox.replaceChildren(h("summary", {}, `⚙ ${t("cst.filters")}`, active.length ? h("span", { class: "cst-fcount" }, active.length) : null),
      h("div", { class: "cst-filters-body fl" },
        h("div", { class: "fl-grid" },
          h("label", { class: "fl-field" }, h("span", {}, t("fl.target")), brandSel),
          select_("source", [["", t("fl.src_all")], ["ct", t("fl.src_ct")], ["feeds", t("fl.src_feeds")], ...feeds.map(k => [k, t(`feed.${k}`)])], t("fl.source")),
          select_("since", [["", t("fl.since_any")], ["1", t("fl.since_1")], ["24", t("fl.since_24")], ["168", t("fl.since_168")], ["720", t("fl.since_720")]], t("fl.detected")),
          select_("minRisk", [["", t("fl.risk_any")], ["medium", `≥ ${t("res.level.medium")}`], ["high", `≥ ${t("res.level.high")}`], ["critical", t("res.level.critical")]], t("fl.risk"))),
        h("div", { class: "fl-checks" }, check("listedNow", t("fl.listed_now")), check("warned", t("fl.warned")), check("inCampaign", t("fl.in_campaign")),
          check("connectedOnly", `${t("fl.unconnected")}${data ? ` (${fmtN(data.totals.unconnected)})` : ""}`, true)),
        h("div", { class: "fl-foot" }, h("span", { class: "small" }, data ? `${t("fl.showing")} ${fmtN(data.totals.shown_nodes)} / ${fmtN(data.totals.matched ?? data.totals.shown_nodes)} ${t("fl.matching")} · ${fmtN(data.totals.findings)} ${t("fl.stored")}` : ""),
          h("button", { class: "btn ghost sm", type: "button", disabled: !active.length, onclick: async () => { filter = { ...FILTER0 }; await load(true); } }, t("fl.reset")))));
    const chipKey = { brand: "", source: "", since: "", minRisk: "", listedNow: false, warned: false, inCampaign: false, connectedOnly: true };
    chips.replaceChildren(...active.map(([k, v]) => h("button", { type: "button", class: "cst-chip", "aria-label": `${t("fl.remove")} ${v}`,
      onclick: () => set(k, chipKey[k]) }, v, h("span", { "aria-hidden": "true" }, " ×"))));
    toolbar.replaceChildren(...[
      h("div", { class: "seg2", role: "group", "aria-label": t("cst.view") }, seg("view", "graph", t("cst.graph")), seg("view", "list", t("cst.list"))),
      h("div", { class: "seg2", role: "group", "aria-label": t("inv.status") }, seg("status", "all", t("radar.filter.all")),
        seg("status", "confirmed", t("radar.confirmed_short")), seg("status", "suspected", t("radar.suspected_short"))),
      filtersBox, chips,
      h("button", { class: "btn sm rp-open-btn", type: "button", onclick: () => openReport(filter,
        [...new Set([...(data?.nodes || []).map(n => n.brand), filter.brand].filter(Boolean))].sort()) }, t("rp.button")),
      fresh].filter(Boolean));
  };
  brandSel.addEventListener("change", async () => { filter.brand = brandSel.value; await load(true); });
  function legend() {
    const dot = (cls, label) => h("span", { class: "lg" }, h("i", { class: cls }), label);
    return h("div", { class: "cst-legend small" }, dot("lg-conf", t("radar.confirmed_short")), dot("lg-susp", t("radar.suspected_short")),
      dot("lg-strong", t("radar.strength.strong")), dot("lg-mod", t("radar.strength.moderate")), dot("lg-weak", t("radar.strength.weak")),
      h("span", { class: "muted" }, t("cst.rings_hint")), h("span", { class: "muted" }, t("cst.size_hint")));
  }

  root.replaceChildren(
    h("div", { class: "page-head" }, h("div", {}, h("div", { class: "row" }, h("h1", {}, t("radar.title")), liveBadge),
      h("p", { class: "muted", style: { margin: "4px 0 0" } }, t("cst.subtitle")))),
    pipe.node,
    h("section", { class: "cst" }, sForm, toolbar, h("div", { class: "cst-body" }, stage, panel)));

  async function load(rebuild = false) {
    if (!document.body.contains(panel)) return stopRadar();
    try {
      const q = new URLSearchParams({ status: filter.status, connected_only: String(filter.connectedOnly), limit: String(GRAPH_LIMIT) });
      if (filter.brand) q.set("brand", filter.brand);
      if (filter.source) q.set("source", filter.source);
      if (filter.since) q.set("since_hours", filter.since);
      if (filter.minRisk) q.set("min_risk", filter.minRisk);
      for (const [k, p] of [["listedNow", "listed_now"], ["warned", "warned"], ["inCampaign", "in_campaign"]]) if (filter[k]) q.set(p, "true");
      const [r, d] = await Promise.all([api("/radar?limit=1"), api(`/radar/graph?${q}`)]);
      const s = r.service;
      liveBadge.replaceChildren(h("span", { class: `dot ${s.enabled ? "running" : "idle"}` }), s.enabled ? t("radar.live") : t("radar.paused"));
      pipe.update(r, rollTo);
      nextAt = Date.now() + REFRESH_MS;
      restartSweep();
      const first = !data;
      collectEvents(d, first);
      data = d;
      // count only findings genuinely first seen after the page was opened
      const newer = d.nodes.filter(n => new Date(n.first_seen).getTime() > openedAt).length;
      fresh.hidden = !newer;
      fresh.textContent = `${newer} ${t("cst.new_since")}`;
      if (selected && selected.type !== "lookup" && !(selected.type === "node" ? d.nodes.some(n => n.id === selected.id) : d.campaigns.some(c => c.id === selected.id))) selected = null;
      if (first || rebuild) { drawToolbar(); drawStage(); }
      else if (view === "graph") {
        updateGraph(d);
        graphBox.setAttribute("aria-label", `${t("cst.graph_label")}: ${d.nodes.length} ${t("cst.indicators")}, ${d.edges.length} ${t("cst.links")}. ${t("cst.use_list")}`);
      }
      else drawStage();
      renderPanel();
      if (searchTerm && (first || rebuild)) applySearch(sInput.value);
    } catch (e) { panel.replaceChildren(errorBox(e)); }
  }
  function restartSweep() { restartSweepCycle(); }
  // Enlarge / restore: true fullscreen where the browser allows it, otherwise a full-window overlay.
  const expandBtn = h("button", { type: "button", class: "cst-expand", "aria-pressed": "false", onclick: () => setExpanded(!stage.classList.contains("max")) });
  function labelExpand(on) {
    expandBtn.textContent = on ? "✕" : "⛶";
    expandBtn.setAttribute("aria-label", t(on ? "cst.restore" : "cst.enlarge"));
    expandBtn.title = t(on ? "cst.restore" : "cst.enlarge");
    expandBtn.setAttribute("aria-pressed", String(on));
  }
  labelExpand(false);
  const placeholder = document.createComment("radar");
  function refit() {
    requestAnimationFrame(() => { if (!cy) return; cy.resize(); layoutAll({ fit: true }); sweepSync(); if (selected) highlight(selected); });
  }
  function setExpanded(on) {
    if (on === stage.classList.contains("max")) return;
    // lift the radar out of the page while enlarged so no parent layout can clip or shrink it
    if (on) { stage.before(placeholder); document.body.append(stage); } else if (placeholder.isConnected) placeholder.replaceWith(stage);
    stage.classList.toggle("max", on);
    document.body.classList.toggle("cst-locked", on);
    labelExpand(on);
    if (on && stage.requestFullscreen && !document.fullscreenElement) stage.requestFullscreen().catch(() => {});
    if (!on && document.fullscreenElement === stage) document.exitFullscreen().catch(() => {});
    refit();
    (on ? expandBtn : expandBtn).focus({ preventScroll: true });
  }
  const onFs = () => { if (!document.fullscreenElement && stage.classList.contains("max")) setExpanded(false); else refit(); };
  const onKey = (e) => { if (e.key === "Escape" && stage.classList.contains("max")) setExpanded(false); };
  document.addEventListener("fullscreenchange", onFs);
  document.addEventListener("keydown", onKey);
  const unbind = setInterval(() => {
    if (document.body.contains(panel)) return;
    if (stage.isConnected && !placeholder.isConnected) stage.remove();
    clearInterval(unbind); document.removeEventListener("fullscreenchange", onFs); document.removeEventListener("keydown", onKey);
    document.body.classList.remove("cst-locked");
    if (document.fullscreenElement === stage) document.exitFullscreen().catch(() => {});
  }, 1000);
  function collectEvents(d, first) {
    const now = Date.now();
    if (first) {
      events = [...d.nodes].sort((a, b) => b.first_seen.localeCompare(a.first_seen)).slice(0, 8)
        .map(n => ({ kind: "detected", node: n, at: n.first_seen, isNew: false }));
    } else {
      const known = new Set(data.nodes.map(n => n.id));
      for (const n of d.nodes) {
        if (!known.has(n.id)) events.unshift({ kind: "detected", node: n, at: n.first_seen, isNew: true });
        else if (prevSeen && (prevSeen.get(n.id) || 0) < (n.seen_count || 1) && n.status === "suspected")
          events.unshift({ kind: "reseen", node: n, at: n.last_seen, isNew: true });
      }
      events = events.slice(0, 12);
    }
    prevSeen = new Map(d.nodes.map(n => [n.id, n.seen_count || 1]));
    if (events.some(e => e.isNew)) tickIdx = 0;
    showTick();
  }
  function showTick() {
    if (!events.length) { ticker.replaceChildren(h("span", { class: "muted" }, t("cst.ticker_empty"))); return; }
    const e = events[tickIdx % events.length];
    const item = h("button", { class: `cst-tick ${e.isNew ? "new" : ""}`, type: "button", onclick: () => select({ type: "node", id: e.node.id }) },
      e.isNew ? h("span", { class: "badge medium" }, t("cst.new")) : null,
      h("span", { class: `dot ${e.node.status === "confirmed" ? "error" : "suspect"}` }),
      `${t(e.kind === "reseen" ? "cst.ev_reseen" : e.node.status === "confirmed" ? "cst.ev_listed" : "cst.ev_detected")} `,
      h("code", {}, defang(short(e.node.host, 40))), h("span", { class: "muted" }, ` · ${ago(e.at)}`));
    ticker.replaceChildren(item);
    if (e.isNew) setTimeout(() => { e.isNew = false; }, 30000);
  }
  function rollTo(el, target) {
    const from = Number(el.dataset.v || 0);
    el.dataset.v = target;
    if (REDUCED || from === target) { el.textContent = fmtN(target); return; }
    const t0 = performance.now(), D = 1200;
    const step = (now) => {
      const k = Math.min(1, (now - t0) / D), v = Math.round(from + (target - from) * (1 - (1 - k) ** 3));
      el.textContent = fmtN(v);
      if (k < 1 && document.body.contains(el)) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  const showCountdown = () => {
    const left = Math.max(0, Math.ceil((nextAt - Date.now()) / 1000));
    countdown.textContent = `${t("cst.next_update")} ${left} ${t("cst.sec")}`;
  };
  showCountdown();
  const clock = setInterval(() => {
    if (!document.body.contains(panel)) { clearInterval(clock); return; }
    showCountdown();
  }, 500);
  const rotate = setInterval(() => {
    if (!document.body.contains(panel)) { clearInterval(rotate); return; }
    if (events.length > 1 && !document.hidden) { tickIdx++; showTick(); }
  }, 4000);
  await load(true);
  const explore = takeExplore();   // arriving from Check / Family Shield / Home: reopen the same intelligence
  if (explore) openIntel(explore, { refresh: () => load(false) });
  timer = setInterval(() => load(false), REFRESH_MS);
}
