// MIRGAB intelligence report: choose filters (the same ones the radar uses) → a branded report document
// built only from GET /api/radar/report → print / save as PDF, or export every matching site as CSV.
import { api, errorBox, fmtTime, h, isRTL, L, locale, state, t } from "./core.js";

const SVGNS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}, ...kids) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); e.append(...kids); return e; };
const fmtN = (n) => Number(n || 0).toLocaleString(locale());
const fill = (tpl, vars) => tpl.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");
const day = (iso) => iso ? new Date(iso).toLocaleDateString(locale(), { day: "numeric", month: "short", year: "numeric" }) : "—";
const RISKS = ["critical", "high", "medium", "low"];
const FEEDS = ["openphish", "certpl", "phishing_army", "phishing_db", "blocklist_project"];
const srcLabel = (k) => k === "ct" ? t("cst.src_ct") : k === "feeds" ? t("fl.src_feeds") : t(`feed.${k}`);
const DEFAULTS = { status: "all", brand: "", source: "", since: "168", minRisk: "", listedNow: false, warned: false, inCampaign: false, kind: "exec", tlp: "clear" };

let overlay = null;
function close() {
  overlay?.remove(); overlay = null;
  document.body.classList.remove("rp-open");
  document.removeEventListener("keydown", onKey);
}
const onKey = (e) => { if (e.key === "Escape" && overlay) close(); };

function query(f) {
  const q = new URLSearchParams();
  if (f.status !== "all") q.set("status", f.status);
  if (f.brand) q.set("brand", f.brand);
  if (f.source) q.set("source", f.source);
  if (f.since) q.set("since_hours", f.since);
  if (f.minRisk) q.set("min_risk", f.minRisk);
  if (f.listedNow) q.set("listed_now", "true");
  if (f.warned) q.set("warned", "true");
  if (f.inCampaign) q.set("in_campaign", "true");
  return q.toString();
}

// ---------------------------------------------------------------------------- step 1: what the report covers
export function openReport(radarFilter = {}, brands = []) {
  close();
  const f = { ...DEFAULTS, ...Object.fromEntries(Object.entries(radarFilter).filter(([k]) => k in DEFAULTS)), kind: "exec", tlp: "clear" };
  if (!radarFilter.since) f.since = DEFAULTS.since;
  overlay = h("div", { class: "rp-overlay", role: "dialog", "aria-modal": "true", "aria-label": t("rp.title") });
  document.body.append(overlay);
  document.body.classList.add("rp-open");
  document.addEventListener("keydown", onKey);
  form(f, brands);
}

function form(f, brands) {
  const sel = (k, opts, label) => h("label", { class: "rp-field" }, h("span", {}, label),
    h("select", { class: "cst-select", onchange: (e) => { f[k] = e.target.value; } }, ...opts.map(([v, l]) => h("option", { value: v, selected: String(f[k]) === v }, l))));
  const check = (k, label) => h("label", { class: "checkline small" }, h("input", { type: "checkbox", checked: !!f[k], onchange: (e) => { f[k] = e.target.checked; } }), label);
  const kind = (v, title, sub) => h("label", { class: `rp-kind ${f.kind === v ? "on" : ""}` },
    h("input", { type: "radio", name: "rp-kind", value: v, checked: f.kind === v, onchange: () => { f.kind = v; overlay.querySelectorAll(".rp-kind").forEach(x => x.classList.toggle("on", x.querySelector("input").checked)); } }),
    h("b", {}, title), h("small", {}, sub));
  const status = h("div", { class: "small muted", role: "status" });
  const go = h("button", { class: "btn", type: "submit" }, t("rp.generate"));
  const card = h("form", { class: "rp-form" },
    h("div", { class: "rp-form-head" }, h("img", { src: "assets/logo-mark.png", alt: "", width: "34", height: "34" }),
      h("div", {}, h("h2", {}, t("rp.title")), h("p", { class: "muted small" }, t("rp.sub")))),
    h("div", { class: "rp-section-label" }, t("rp.type")),
    h("div", { class: "rp-kinds" }, kind("exec", t("rp.exec"), t("rp.exec_sub")), kind("tech", t("rp.tech"), t("rp.tech_sub"))),
    h("div", { class: "rp-section-label" }, t("cst.filters")),
    h("div", { class: "rp-grid" },
      sel("since", [["1", t("fl.since_1")], ["24", t("fl.since_24")], ["168", t("fl.since_168")], ["720", t("fl.since_720")], ["", t("fl.since_any")]], t("rp.period")),
      sel("status", [["all", t("radar.filter.all")], ["confirmed", t("radar.confirmed_short")], ["suspected", t("radar.suspected_short")]], t("inv.status")),
      sel("brand", [["", t("cst.all_targets")], ...brands.map(b => [b, b])], t("fl.target")),
      sel("source", [["", t("fl.src_all")], ["ct", t("fl.src_ct")], ["feeds", t("fl.src_feeds")], ...FEEDS.map(k => [k, t(`feed.${k}`)])], t("fl.source")),
      sel("minRisk", [["", t("fl.risk_any")], ["medium", `≥ ${t("res.level.medium")}`], ["high", `≥ ${t("res.level.high")}`], ["critical", t("res.level.critical")]], t("fl.risk"))),
    h("div", { class: "rp-checks" }, check("listedNow", t("fl.listed_now")), check("warned", t("fl.warned")), check("inCampaign", t("fl.in_campaign"))),
    h("div", { class: "rp-section-label" }, t("rp.sharing")),
    h("div", { class: "rp-grid" }, sel("tlp", [["clear", "TLP:CLEAR"], ["green", "TLP:GREEN"], ["amber", "TLP:AMBER"]], t("rp.tlp")),
      h("p", { class: "small", style: { color: "#8aa2b1", margin: "auto 0 6px", "grid-column": "span 2" } }, t("rp.tlp_help"))),
    h("div", { class: "rp-form-foot" }, status, h("button", { class: "btn ghost", type: "button", onclick: close }, t("rp.cancel")), go));
  card.addEventListener("submit", async (e) => {
    e.preventDefault();
    go.disabled = true; status.textContent = t("rp.generating");
    try {
      const d = await api(`/radar/report?${query(f)}`);
      documentView(d, f, brands);
    } catch (err) { status.replaceChildren(errorBox(err)); go.disabled = false; }
  });
  overlay.replaceChildren(card);
  card.querySelector("select")?.focus();
}

// ---------------------------------------------------------------------------- step 2: the report
const C = { teal: "#0f766e", red: "#e11d48", violet: "#7c3aed", sky: "#0369a1", amber: "#b45309", slate: "#334155" };
const RISK_C = { critical: "#be123c", high: "#ea580c", medium: "#ca8a04", low: "#15803d" };
const SRC_C = ["#0f766e", "#0369a1", "#7c3aed", "#b45309", "#be123c", "#334155", "#0891b2"];
const signed = (p) => p == null ? null : `${p > 0 ? "+" : ""}${fmtN(p)}%`;
const pctOf = (n, total) => total ? `${fmtN(Math.round(n / total * 100))}%` : "0%";
const daysTxt = (v) => v == null ? "—" : v < 1 ? `${fmtN(Math.max(1, Math.round(v * 24)))} ${t("rp.hours")}` : `${fmtN(Math.round(v * 10) / 10)} ${t("rp.days")}`;
const hourLbl = (iso) => new Date(iso).toLocaleString(locale(), { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function delta(p) {
  if (p == null) return h("span", { class: "rp-delta none" }, t("rp.new_label"));
  return h("span", { class: `rp-delta ${p > 0 ? "up" : p < 0 ? "down" : ""}` }, `${p > 0 ? "▲" : p < 0 ? "▼" : "■"} ${signed(p)}`);
}
function bars(rows, { max, color = C.teal, label = (r) => r.label, value = (r) => r.count, extra = null, total = null }) {
  const m = max || Math.max(1, ...rows.map(value));
  return h("div", { class: "rp-bars" }, ...rows.map(r => h("div", { class: "rp-bar" },
    h("span", { class: "rp-bar-l", title: label(r) }, label(r)),
    h("span", { class: "rp-bar-t" }, h("i", { style: { width: `${Math.max(2, value(r) / m * 100)}%`, background: color } })),
    h("b", {}, fmtN(value(r)), total ? h("small", {}, ` · ${pctOf(value(r), total)}`) : null, extra ? h("small", {}, extra(r)) : null))));
}
function donut(parts, centerTop, centerSub) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1, R = 54, W = 16, L = 2 * Math.PI * R;
  const g = svg("svg", { viewBox: "0 0 140 140", class: "rp-donut", role: "img", "aria-label": parts.map(p => `${p.label}: ${fmtN(p.value)}`).join(", ") });
  g.append(svg("circle", { cx: 70, cy: 70, r: R, fill: "none", stroke: "#eef2f6", "stroke-width": W }));
  let off = 0;
  for (const p of parts.filter(p => p.value)) {
    const len = p.value / total * L;
    g.append(svg("circle", { cx: 70, cy: 70, r: R, fill: "none", stroke: p.color, "stroke-width": W, "stroke-dasharray": `${len} ${L - len}`,
      "stroke-dashoffset": String(-off), transform: "rotate(-90 70 70)" }));
    off += len;
  }
  g.append(svg("text", { x: 70, y: 70, "text-anchor": "middle", "font-size": 20, "font-weight": 800, fill: "#0f172a" }, centerTop));
  g.append(svg("text", { x: 70, y: 88, "text-anchor": "middle", "font-size": 9.5, fill: "#64748b" }, centerSub));
  return h("div", { class: "rp-donut-w" }, g, h("ul", { class: "rp-donut-l" }, ...parts.map(p => h("li", {},
    h("i", { style: { background: p.color } }), h("span", {}, p.label), h("b", {}, fmtN(p.value)), h("small", {}, pctOf(p.value, total))))));
}
function timeline(rows, keyFn, lblFn, unitKey) {
  if (!rows.length) return h("p", { class: "muted small" }, t("rp.empty"));
  const W = 700, H = 200, pl = 44, pr = 12, pt = 14, pb = 30, n = rows.length;
  const max = Math.max(1, ...rows.map(d => d.confirmed + d.suspected));
  const step = (W - pl - pr) / n, bw = Math.max(2, Math.min(28, step * 0.72));
  const x = (i) => pl + i * step + (step - bw) / 2, y = (v) => H - pb - v / max * (H - pt - pb);
  const g = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "rp-chart", role: "img", "aria-label": `${t("rp.s_timeline")} (${t(unitKey)})` });
  for (const f of [0, 0.5, 1]) {
    const yy = y(max * f);
    g.append(svg("line", { x1: pl, x2: W - pr, y1: yy, y2: yy, stroke: f ? "#eef2f6" : "#cbd5e1", "stroke-dasharray": f ? "3 4" : "" }));
    g.append(svg("text", { x: pl - 8, y: yy + 4, "font-size": 10, fill: "#64748b", "text-anchor": "end" }, fmtN(Math.round(max * f))));
  }
  rows.forEach((d, i) => {
    const yc = y(d.confirmed), ys = y(d.confirmed + d.suspected);
    const tip = `${lblFn(keyFn(d))} — ${fmtN(d.confirmed)} ${t("radar.confirmed_short")}, ${fmtN(d.suspected)} ${t("radar.suspected_short")}`;
    if (d.confirmed) g.append(svg("rect", { x: x(i), y: yc, width: bw, height: H - pb - yc, fill: C.red, rx: 2 }, svg("title", {}, tip)));
    if (d.suspected) g.append(svg("rect", { x: x(i), y: ys, width: bw, height: Math.max(1, yc - ys), fill: C.violet, rx: 2 }, svg("title", {}, tip)));
  });
  const peak = rows.reduce((a, d, i) => (d.confirmed + d.suspected > a.v ? { v: d.confirmed + d.suspected, i } : a), { v: -1, i: 0 });
  const ticks = [...new Set([0, Math.floor((n - 1) / 2), n - 1])];
  ticks.forEach(i => g.append(svg("text", { x: x(i) + bw / 2, y: H - 10, "font-size": 10, fill: "#64748b", "text-anchor": i === 0 && n > 1 ? "start" : i === n - 1 && n > 1 ? "end" : "middle" }, lblFn(keyFn(rows[i])))));
  return h("div", {}, g, h("div", { class: "rp-legend small" },
    h("span", {}, h("i", { style: { background: C.red } }), t("radar.confirmed_short")),
    h("span", {}, h("i", { style: { background: C.violet } }), t("radar.suspected_short")),
    h("span", { class: "rp-peak" }, `${t("rp.peak")}: ${lblFn(keyFn(rows[peak.i]))} · ${fmtN(peak.v)}`)));
}
function actionText(a, b) {
  return fill(t(`rp.pr_${a.key}`), { n: fmtN(a.n), pct: `${fmtN(a.pct)}%`, platform: a.platform, tld: a.tld, brand: b });
}
function filterChips(f) {
  const chips = [];
  if (f.since) chips.push(t(`fl.since_${f.since}`));
  if (f.status !== "all") chips.push(t(f.status === "confirmed" ? "radar.confirmed_short" : "radar.suspected_short"));
  if (f.brand) chips.push(`${t("fl.target")}: ${f.brand}`);
  if (f.source) chips.push(srcLabel(f.source));
  if (f.minRisk) chips.push(`≥ ${t(`res.level.${f.minRisk}`)}`);
  if (f.listedNow) chips.push(t("fl.listed_now"));
  if (f.warned) chips.push(t("fl.warned"));
  if (f.inCampaign) chips.push(t("fl.in_campaign"));
  return chips.length ? chips : [t("rp.no_filters")];
}
function keyFindings(d) {
  const T = d.totals, A = d.analysis, out = [];
  const top = d.by_brand[0];
  if (top) out.push(fill(t("rp.kf_brand"), { brand: top.brand, n: fmtN(top.count), pct: pctOf(top.count, T.sites) }));
  if (T.listed_now) out.push(fill(t("rp.kf_listed"), { n: fmtN(T.listed_now) }));
  const plat = A.infrastructure.platforms[0];
  if (plat && A.infrastructure.platform_share_pct >= 10) out.push(fill(t("rp.kf_platform"), { pct: `${fmtN(A.infrastructure.platform_share_pct)}%`, platform: plat.label, n: fmtN(plat.count) }));
  const rising = A.priorities.find(p => p.rising);
  if (rising) out.push(fill(t("rp.kf_rising"), { brand: rising.brand, pct: signed(rising.change_pct) }));
  const g = A.growth[0];
  if (g) out.push(fill(t("rp.kf_campaign"), { n: fmtN(g.new), name: `${g.id} · ${L(g, "name")}` }));
  if (A.lifetime.delisted >= 20 && A.lifetime.p90_days != null) out.push(fill(t("rp.kf_life"), { d: daysTxt(A.lifetime.p90_days) }));
  return out.slice(0, 5);
}

function documentView(d, f, brands) {
  const T = d.totals, A = d.analysis, tech = f.kind === "tech";
  const ref = `MQ-${d.generated_at.slice(0, 16).replace(/[-:T]/g, "")}`;
  const tlp = { clear: "TLP:CLEAR", green: "TLP:GREEN", amber: "TLP:AMBER" }[f.tlp || "clear"];
  const sections = [];
  const sec = (key, ...kids) => { sections.push(key); return h("section", { class: `rp-sec ${key === "rp.s_sites" ? "rp-long" : ""}`, id: `rp-${sections.length}` },
    h("h2", {}, h("span", {}, String(sections.length).padStart(2, "0")), t(key)), ...kids); };
  const kpi = (n, key, sub, cls = "") => h("div", { class: `rp-kpi ${cls}` }, h("b", {}, n), h("span", {}, t(key)), sub ? h("small", {}, sub) : null);
  const findings = T.sites ? keyFindings(d) : [];
  const prevention = [...new Map(d.top_campaigns.flatMap(c => c.prevention || []).map(p => [L(p), p])).values()].slice(0, 4);
  const sites = tech ? d.sites : d.sites.slice(0, 15);
  const useHours = d.by_hour && d.by_hour.length > 1;
  const srcParts = d.by_source.map((r, i) => ({ label: srcLabel(r.source), value: r.count, color: SRC_C[i % SRC_C.length] }));
  const riskParts = RISKS.map(l => ({ label: t(`res.level.${l}`), value: d.by_risk[l] || 0, color: RISK_C[l] }));
  const listedPct = pctOf(T.listed_now, T.sites);

  const body = [];
  if (!T.sites) body.push(h("p", { class: "rp-empty" }, t("rp.empty")));
  else {
    body.push(sec("rp.s_summary",
      h("div", { class: "rp-kpis" },
        kpi(fmtN(T.sites), "rp.k_sites", `${fmtN(T.stored_total)} ${t("fl.stored")}`),
        kpi(fmtN(T.confirmed), "rp.k_confirmed", pctOf(T.confirmed, T.sites), "bad"),
        kpi(fmtN(T.listed_now), "rp.k_listed", listedPct, "bad"),
        kpi(fmtN(T.suspected), "rp.k_suspected", pctOf(T.suspected, T.sites), "susp"),
        kpi(fmtN(T.campaigns), "rp.k_campaigns", null),
        kpi(fmtN(T.brands), "rp.k_brands", null)),
      h("p", { class: "rp-lead" }, [fill(t("rp.summary_tpl"), { sites: fmtN(T.sites), brands: fmtN(T.brands), confirmed: fmtN(T.confirmed), suspected: fmtN(T.suspected) }),
        d.by_brand[0] ? fill(t("rp.summary_top"), { brand: d.by_brand[0].brand, n: fmtN(d.by_brand[0].count) }) : "",
        d.top_campaigns[0] ? fill(t("rp.summary_camp"), { c: fmtN(T.campaigns), n: fmtN(d.top_campaigns[0].in_report) }) : "",
        A.comparison && A.comparison.change_pct.sites != null ? fill(t("rp.summary_change"), { pct: signed(A.comparison.change_pct.sites) }) : ""].join(" ").trim())));
    if (A.priorities.length) body.push(sec("rp.s_priority", h("ol", { class: "rp-pri" }, ...A.priorities.map((p, i) => {
      const lvl = i === 0 || p.rising ? 1 : i < 3 ? 2 : 3;
      return h("li", { class: `rp-pri-i p${lvl}` },
        h("div", { class: "rp-pri-h" }, h("span", { class: `rp-pri-badge p${lvl}` }, `P${lvl}`), h("b", {}, p.brand),
          p.rising ? h("span", { class: "rp-flag" }, fill(t("rp.pr_rising"), { pct: signed(p.change_pct) })) : null,
          h("span", { class: "rp-pri-facts" }, fill(t("rp.pr_facts"), { count: fmtN(p.count), listed: fmtN(p.listed_now), suspected: fmtN(p.suspected) }))),
        h("ul", { class: "rp-pri-a" }, ...p.actions.map(a => h("li", {}, actionText(a, p.brand)))));
    }))));
    body.push(sec("rp.s_timeline", useHours
      ? timeline(d.by_hour, r => r.hour, hourLbl, "rp.per_hour")
      : timeline(d.by_day, r => r.day, day, "rp.per_day")));
    body.push(sec("rp.s_change", !A.comparison ? h("p", { class: "rp-note" }, t("rp.no_compare")) : h("div", {},
      h("div", { class: "rp-cmp" },
        h("div", {}, h("span", {}, t("rp.col_now")), h("b", {}, fmtN(T.sites))),
        h("div", {}, h("span", {}, t("rp.col_before")), h("b", {}, fmtN(A.comparison.previous.sites))),
        h("div", {}, h("span", {}, t("rp.col_change")), delta(A.comparison.change_pct.sites))),
      !A.comparison.previous.sites ? h("p", { class: "rp-note" }, t("rp.prev_none")) : null,
      h("table", { class: "rp-table" }, h("thead", {}, h("tr", {}, ...["col_brand", "col_now", "col_before", "col_change"].map(k => h("th", { scope: "col" }, t(`rp.${k}`))))),
        h("tbody", {}, ...A.comparison.by_brand.map(r => h("tr", {}, h("td", {}, h("b", {}, r.brand)), h("td", {}, fmtN(r.now)), h("td", {}, fmtN(r.before)), h("td", {}, delta(r.change_pct)))))),
      h("p", { class: "small rp-muted" }, t("rp.compare_note")))));
    body.push(sec("rp.s_brands", bars(d.by_brand, { label: r => r.brand, total: T.sites, color: C.teal })));
    body.push(sec("rp.s_sources_risk", h("div", { class: "rp-two" },
      h("div", {}, h("h3", {}, t("rp.s_sources")), donut(srcParts, fmtN(d.by_source.length), t("rp.sources_n"))),
      h("div", {}, h("h3", {}, t("rp.s_risk")), donut(riskParts, pctOf((d.by_risk.critical || 0) + (d.by_risk.high || 0), T.sites), t("rp.high_or_critical"))))));
    body.push(sec("rp.s_infra",
      h("div", { class: "rp-callout" }, h("b", {}, `${fmtN(A.infrastructure.platform_share_pct)}%`), h("span", {}, fill(t("rp.platform_share"), { pct: `${fmtN(A.infrastructure.platform_share_pct)}%` }))),
      h("div", { class: "rp-three" },
        h("div", {}, h("h3", {}, t("rp.infra_platform")), A.infrastructure.platforms.length ? bars(A.infrastructure.platforms, { color: C.violet }) : h("p", { class: "small rp-muted" }, "—")),
        h("div", {}, h("h3", {}, t("rp.infra_tld")), A.infrastructure.tlds.length ? bars(A.infrastructure.tlds, { color: C.sky }) : h("p", { class: "small rp-muted" }, "—")),
        h("div", {}, h("h3", {}, t("rp.infra_words")), A.infrastructure.words.length ? bars(A.infrastructure.words, { color: C.amber }) : h("p", { class: "small rp-muted" }, "—")))));
    if (A.growth.length) body.push(sec("rp.s_growth", h("p", { class: "small rp-muted" }, t("rp.growth_note")),
      h("table", { class: "rp-table" }, h("thead", {}, h("tr", {}, ...["col_campaign", "col_new", "col_existing", "col_total"].map(k => h("th", { scope: "col" }, t(`rp.${k}`))))),
        h("tbody", {}, ...A.growth.map(g => h("tr", {}, h("td", {}, h("code", { class: "rp-id" }, g.id), " ", L(g, "name")),
          h("td", {}, h("span", { class: "rp-up" }, `+${fmtN(g.new)}`)), h("td", {}, fmtN(g.before)), h("td", {}, h("b", {}, fmtN(g.size)))))))));
    if (T.confirmed) body.push(sec("rp.s_life",
      A.lifetime.delisted ? h("div", { class: "rp-kpis three" },
        kpi(fmtN(A.lifetime.delisted), "rp.life_delisted", null), kpi(daysTxt(A.lifetime.median_days), "rp.life_median", null), kpi(daysTxt(A.lifetime.p90_days), "rp.life_p90", null))
        : h("p", { class: "rp-note" }, t("rp.life_none")),
      A.lifetime.still_listed ? h("p", { class: "small" }, `${t("rp.life_active")}: `, h("b", {}, daysTxt(A.lifetime.median_age_days)), ` · ${fmtN(A.lifetime.still_listed)} ${t("radar.sites")}`) : null,
      h("p", { class: "small rp-muted" }, t("rp.life_note"))));
    if (d.top_campaigns.length) body.push(sec("rp.s_campaigns", h("div", { class: "rp-camps" }, ...d.top_campaigns.slice(0, tech ? 8 : 4).map(c => h("div", { class: `rp-camp ${c.status}` },
      h("div", { class: "rp-camp-h" }, h("code", { class: "rp-id" }, c.id), h("span", { class: `rp-tag ${c.status}` }, t(c.status === "confirmed" ? "radar.confirmed_short" : "radar.suspected_short"))),
      h("b", { class: "rp-camp-n" }, L(c, "name")),
      h("div", { class: "rp-camp-m" }, `${fmtN(c.in_report)} ${t("rp.in_report")} · ${day(c.first_seen)} → ${day(c.last_seen)}`),
      c.links.length ? h("div", { class: "small" }, h("b", {}, t("rp.why_linked"), ": "), c.links.map(l => L(l)).join(" · ")) : null,
      h("div", { class: "small" }, h("b", {}, t("rp.harm"), ": "), L(c, "harm")),
      c.prevention?.length ? h("div", { class: "small" }, h("b", {}, t("rp.protect"), ": "), c.prevention.slice(0, 2).map(p => L(p)).join(" · ")) : null)))));
    body.push(sec("rp.s_recs", h("div", { class: "rp-recs" },
      ...[T.confirmed ? ["🛡", "rp.aud_brand", t("rp.rec_takedown")] : null, ["🧱", "rp.aud_sec", t("rp.rec_block")], ["📣", "rp.aud_comm", t("rp.rec_warn")]].filter(Boolean)
        .map(([ic, who, txt]) => h("div", { class: "rp-rec" }, h("span", { class: "rp-rec-i", "aria-hidden": "true" }, ic), h("div", {}, h("b", {}, t(who)), h("p", {}, txt.replace(/^[^:：]+[:：]\s*/, ""))))),
      prevention.length ? h("div", { class: "rp-rec" }, h("span", { class: "rp-rec-i", "aria-hidden": "true" }, "👪"), h("div", {}, h("b", {}, t("rp.aud_public")),
        h("ul", {}, ...prevention.map(p => h("li", {}, L(p)))))) : null)));
    body.push(sec("rp.s_sites",
      h("p", { class: "small rp-muted" }, tech ? fill(t("rp.sites_note_tech"), { shown: fmtN(sites.length), total: fmtN(T.sites) }) : fill(t("rp.sites_note_exec"), { n: fmtN(sites.length) })),
      h("table", { class: "rp-table zebra" },
        h("thead", {}, h("tr", {}, ...["col_site", "col_status", "col_brand", "col_risk", ...(tech ? ["col_sources", "col_first", "col_campaign"] : ["col_first"])].map(k => h("th", { scope: "col" }, t(`rp.${k}`))))),
        h("tbody", {}, ...sites.map(s => h("tr", {},
          h("td", {}, h("code", {}, s.host)),
          h("td", {}, h("span", { class: `rp-tag ${s.status === "confirmed" ? (s.listed_now ? "confirmed" : "gone") : "suspected"}` },
            t(s.status === "confirmed" ? (s.listed_now ? "radar.listed" : "radar.not_listed") : "radar.suspected_short"))),
          h("td", {}, s.brand || "—"), h("td", {}, h("span", { class: "rp-dot", style: { background: RISK_C[s.risk_level] } }), t(`res.level.${s.risk_level}`)),
          ...(tech ? [h("td", {}, s.sources.map(srcLabel).join(", ")), h("td", {}, day(s.first_seen)), h("td", {}, s.campaign_id ? h("code", { class: "rp-id" }, s.campaign_id) : "—")]
            : [h("td", {}, day(s.first_seen))])))))));
  }
  body.push(sec("rp.s_method", h("ul", { class: "rp-limits small" }, ...(state.lang === "ar" ? d.limits_ar : d.limits_en).map(x => h("li", {}, x)))));

  const cover = h("header", { class: "rp-cover" },
    h("div", { class: "rp-cover-top" },
      h("div", { class: "rp-brand" }, h("img", { src: "assets/logo-mark.png", alt: "", width: "44", height: "44" }),
        h("div", {}, h("b", {}, "MIRGAB"), h("span", { lang: "ar" }, "مرقاب"))),
      h("div", { class: "rp-badges" }, h("span", { class: `rp-tlp ${f.tlp || "clear"}` }, tlp), h("span", { class: "rp-kind-b" }, t(tech ? "rp.tech" : "rp.exec")))),
    h("div", { class: "rp-cover-t" }, h("div", { class: "rp-kicker" }, t("rp.kicker")), h("h1", {}, t("rp.doc_title")),
      h("p", {}, d.period.from ? `${day(d.period.from)} — ${day(d.period.to)}` : "—")),
    h("dl", { class: "rp-meta" },
      h("div", {}, h("dt", {}, t("rp.generated")), h("dd", {}, fmtTime(d.generated_at))),
      h("div", {}, h("dt", {}, t("rp.ref")), h("dd", {}, ref)),
      h("div", {}, h("dt", {}, t("rp.k_sites")), h("dd", {}, fmtN(T.sites))),
      h("div", { class: "wide" }, h("dt", {}, t("cst.filters")), h("dd", {}, filterChips(f).join(" · ")))));

  const doc = h("article", { class: "rp-doc", lang: state.lang, dir: isRTL() ? "rtl" : "ltr" },
    cover,
    findings.length ? h("section", { class: "rp-findings" }, h("h2", {}, t("rp.key_findings")),
      h("ol", {}, ...findings.map(x => h("li", {}, x)))) : null,
    h("nav", { class: "rp-toc", "aria-label": t("rp.contents") }, h("b", {}, t("rp.contents")),
      h("ol", {}, ...sections.map((k, i) => h("li", {}, h("a", { href: `#rp-${i + 1}`, onclick: (e) => { e.preventDefault(); doc.querySelector(`#rp-${i + 1}`)?.scrollIntoView({ behavior: "smooth" }); } }, t(k)))))),
    ...body,
    h("footer", { class: "rp-foot small" }, h("span", {}, t("rp.footer")), h("code", {}, `${ref} · ${tlp}`)),
    h("div", { class: "rp-running", "aria-hidden": "true" }, h("span", {}, "MIRGAB · ", t("rp.doc_title")), h("span", {}, `${ref} · ${tlp}`)));

  const csvHref = `/api/radar/report.csv?${query(f)}`;
  const bar = h("div", { class: "rp-toolbar" },
    h("button", { class: "btn ghost sm", type: "button", onclick: () => form(f, brands) }, `← ${t("rp.back")}`),
    h("span", { class: "rp-spacer" }),
    h("a", { class: "btn secondary sm", href: csvHref, download: "mirqab-radar-report.csv" }, `⬇ ${t("rp.csv")}`),
    h("button", { class: "btn sm", type: "button", onclick: () => window.print() }, `🖨 ${t("rp.print")}`),
    h("button", { class: "btn ghost sm", type: "button", "aria-label": t("common.close"), onclick: close }, "✕"));
  overlay.replaceChildren(bar, h("div", { class: "rp-paper" }, doc));
  overlay.scrollTop = 0;
  bar.querySelector("button")?.focus();
}
