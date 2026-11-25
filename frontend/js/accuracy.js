// Detection accuracy page: measured results on held-out public data + live re-run on this server.
// Every number on this page comes from /api/accuracy (recorded) or /api/accuracy/run (computed now).
import { h, L, t, toast } from "./core.js";

const pct = (x, d = 1) => `${(x * 100).toFixed(d)}%`;
const num = (n) => n.toLocaleString();

function ring(value, label, cls = "") {
  const r = h("div", { class: `ac-ring ${cls}` }, h("b", {}, pct(value)), h("small", {}, label));
  r.style.setProperty("--p", String(Math.round(value * 100)));
  return r;
}

function matrix(s) {
  const cell = (n, k, cls) => h("div", { class: `ac-cell ${cls}` }, h("b", {}, num(n)), h("small", {}, t(`ac.${k}`)));
  return h("div", { class: "ac-matrix", role: "table", "aria-label": t("ac.matrix") },
    h("span", { class: "ac-ax" }), h("span", { class: "ac-ax" }, t("ac.pred_threat")), h("span", { class: "ac-ax" }, t("ac.pred_safe")),
    h("span", { class: "ac-ax side" }, t("ac.real_threat")), cell(s.tp, "tp", "good"), cell(s.fn, "fn", "bad"),
    h("span", { class: "ac-ax side" }, t("ac.real_safe")), cell(s.fp, "fp", "bad"), cell(s.tn, "tn", "good"));
}

function compare(s, base) {
  if (!base) return null;
  const row = (k, better) => {
    const now = s[k], was = base[k];
    const w = (x) => h("i", { style: { width: `${Math.max(2, x * 100)}%` } });
    return h("div", { class: "ac-cmp-row" }, h("span", {}, t(`ac.m_${k}`)),
      h("div", { class: "ac-bars" }, h("div", { class: "ac-bar was" }, w(was), h("em", {}, pct(was))), h("div", { class: "ac-bar now" }, w(now), h("em", {}, pct(now)))),
      h("small", { class: (better ? now >= was : now <= was) ? "up" : "down" }, `${now >= was ? "+" : ""}${((now - was) * 100).toFixed(1)} pt`));
  };
  return h("div", { class: "ac-cmp" }, h("div", { class: "ac-cmp-legend" }, h("span", { class: "was" }, t("ac.before")), h("span", { class: "now" }, t("ac.after"))),
    row("recall", true), row("precision", true), row("false_positive_rate", false));
}

function setCard(s, base) {
  const ex = (list, k) => list?.length ? h("details", { class: "ac-ex" }, h("summary", {}, t(`ac.ex_${k}`), ` (${list.length})`),
    h("ul", {}, ...list.map((x) => h("li", { dir: "auto" }, x)))) : null;
  return h("article", { class: `sh-card ac-set k-${s.key}` },
    h("div", { class: "cm-kicker" }, `${num(s.n)} ${t("ac.items")} · ${num(s.positives)} ${t("ac.threats")} · ${num(s.negatives)} ${t("ac.safe")}`),
    h("h2", {}, L(s.title)),
    h("p", { class: "small muted" }, t("ac.source"), ": ", L(s.source)),
    h("div", { class: "ac-rings" }, ring(s.accuracy, t("ac.m_accuracy")), ring(s.precision, t("ac.m_precision")), ring(s.recall, t("ac.m_recall")),
      ring(1 - s.false_positive_rate, t("ac.m_specificity"), "spec")),
    h("div", { class: "ac-grid2" }, matrix(s), compare(s, base)),
    h("p", { class: "small muted" }, `F1 ${s.f1.toFixed(3)} · ${t("ac.m_false_positive_rate")} ${pct(s.false_positive_rate, 2)} · ${s.ms_per_item} ms/${t("ac.item")}`),
    ex(s.examples_missed, "missed"), ex(s.examples_false_alarm, "false"));
}

// Where each judging criterion lives in MERQAB — every link opens the real feature.
const CRITERIA = [
  { k: "c1", w: 30, links: [["#/accuracy", "cj.l_bench"], ["#/home", "cj.l_check"]] },
  { k: "c2", w: 25, links: [["#/radar", "cj.l_radar"]] },
  { k: "c3", w: 20, links: [["#/home", "cj.l_pack"], ["#/radar", "cj.l_report"]] },
  { k: "c4", w: 15, links: [["#/community", "cj.l_community"], ["#/radar", "cj.l_dna"]] },
  { k: "c5", w: 10, links: [["#/shield", "cj.l_mobile"], ["#/shield/call", "cj.l_call"]] },
];
function criteriaMap() {
  return h("section", { class: "sh-card cj" },
    h("div", { class: "cm-kicker" }, t("cj.kicker")), h("h2", {}, t("cj.title")),
    h("ol", { class: "cj-list" }, ...CRITERIA.map((c) => h("li", {},
      h("div", { class: "cj-head" }, h("b", {}, t(`cj.${c.k}`)), h("span", { class: "cj-w" }, `${c.w}%`)),
      h("p", {}, t(`cj.${c.k}_have`)),
      h("p", { class: "small muted" }, h("span", { class: "cj-gap" }, t("cj.gap")), " ", t(`cj.${c.k}_gap`)),
      h("div", { class: "cj-links" }, ...c.links.map(([href, label]) => h("a", { href }, t(label))))))));
}

export async function accuracyPage(view) {
  let res;
  try { res = await (await fetch("/api/accuracy")).json(); } catch { view.replaceChildren(h("p", { class: "notice warn" }, t("err.network"))); return; }
  const base = res.baseline?.sets || {};
  const live = h("div", { class: "ac-live", role: "status" });
  const btn = h("button", { class: "btn", type: "button" }, t("ac.rerun"));
  btn.addEventListener("click", async () => {
    btn.disabled = true; live.textContent = t("ac.running");
    try {
      const r = await fetch("/api/accuracy/run", { method: "POST" });
      if (r.status === 429) { live.textContent = t("ac.wait"); return; }
      const j = await r.json();
      live.replaceChildren(h("b", {}, `${pct(j.overall.accuracy, 2)} · ${num(j.overall.n)} ${t("ac.items")} · ${j.seconds}s`), " — ",
        j.matches_recorded ? t("ac.match") : t("ac.nomatch"));
    } catch { live.textContent = t("err.network"); } finally { setTimeout(() => (btn.disabled = false), 5000); }
  });
  const o = res.overall;
  view.replaceChildren(h("div", { class: "ac" },
    h("section", { class: "ac-hero" },
      h("div", { class: "cm-kicker" }, t("ac.kicker")),
      h("h1", {}, t("ac.title")),
      h("div", { class: "ac-big" }, h("b", {}, pct(o.accuracy)), h("span", {}, t("ac.overall").replace("{n}", num(o.n)))),
      h("p", { class: "muted" }, t("ac.lead")),
      h("div", { class: "sh-row" }, btn, live)),
    criteriaMap(),
    ...res.sets.map((s) => setCard(s, base[s.key])),
    h("section", { class: "sh-card" },
      h("div", { class: "cm-kicker" }, t("ac.method_kicker")), h("h2", {}, t("ac.method_title")),
      h("ul", { class: "ac-method" }, ...["1", "2", "3", "4", "5"].map((k) => h("li", {}, t(`ac.method_${k}`)))),
      h("p", { class: "small muted" }, L(res.baseline || {}, "note"), res.baseline ? ` (${res.baseline.commit})` : ""),
      h("p", { class: "small muted" }, t("ac.reproduce"), " ", h("code", { dir: "ltr" }, "python -m ai.eval.run")))));
}
