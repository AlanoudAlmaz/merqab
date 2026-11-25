// Renders an explainable risk result: verdict → action → why → details.
import { api, h, L, locale, state, t, toast, download } from "./core.js";
import { getJourney, goExplore } from "./journey.js";

const STAGES = ["contact", "pretext", "pressure", "extraction"];

// Measured reliability for this kind of check, from the held-out benchmark (/api/accuracy).
let accP = null;
const accuracy = () => (accP ||= fetch("/api/accuracy").then((x) => (x.ok ? x.json() : null)).catch(() => null));
function reliability(r) {
  const el = h("a", { class: "rx-acc", href: "#/accuracy", hidden: true });
  accuracy().then((acc) => {
    if (!acc) return;
    const arabic = /[\u0600-\u06FF]/.test(r._src || r.observed?.map((o) => o.quote).join(" ") || "");
    const key = r.input.kind === "url" ? "urls" : arabic ? "uae" : "sms";
    const s = acc.sets.find((x) => x.key === key) || acc.sets[0];
    if (!s) return;
    const flagged = ["medium", "high", "critical"].includes(r.risk.level);
    const val = flagged ? s.tp / Math.max(1, s.tp + s.fp) : s.tn / Math.max(1, s.tn + s.fn);
    const n = flagged ? s.tp + s.fp : s.tn + s.fn;
    el.replaceChildren(h("strong", { class: "rx-acc-k" }, t("rx.acc_label")), h("b", {}, `${(val * 100).toFixed(1)}%`), " ",
      t(flagged ? "rx.acc_flag" : "rx.acc_safe").replace("{n}", n.toLocaleString()), " · ", h("span", {}, L(s.title)));
    el.hidden = false;
  });
  return el;
}

function riskHeader(r) {
  const lvl = r.risk.level;
  const gauge = h("div", { class: "gauge", style: { "--p": String(Math.max(3, r.risk.score)) } },
    h("span", { "aria-hidden": "true" }, r.risk.score));
  const engine = r.engine.llm.status === "used" ? t("res.engine_ai") : t("res.engine_rules");
  return h("section", { class: `risk ${lvl}`, "aria-label": t("res.score") },
    gauge,
    h("h2", {}, t(`res.level.${lvl}`)),
    h("p", {}, t(`res.verdict.${lvl}`)),
    h("div", { class: "meta-line" },
      h("span", {}, `${t("res.score")}: ${r.risk.score}/100`),
      h("span", {}, `${t("res.confidence")}: ${t(`conf.${r.risk.confidence}`)}`),
      h("span", { class: "advanced" }, engine)),
    reliability(r));
}

function actionCard(iv) {
  const p = iv.primary;
  const card = h("section", { class: "action-card" },
    h("h3", {}, p.anticipated ? t("res.predicted") : t("res.do_now")),
    h("div", { class: "big" }, L(p)),
    p.anticipated ? h("p", { class: "small", style: { color: "#9fb3c0" } }, t("res.predicted_hint")) : null,
    h("ul", {}, p.do_now.map(x => h("li", {}, L(x)))));
  if (p.if_already?.length) {
    card.append(h("details", {}, h("summary", {}, t("res.already")),
      h("ul", {}, p.if_already.map(x => h("li", {}, L(x))))));
  }
  if (iv.additional?.length) {
    card.append(h("details", { open: iv.urgent && iv.additional.length <= 2 },
      h("summary", {}, t("res.also")),
      h("ul", {}, iv.additional.map(a => h("li", {}, h("b", {}, L(a)), " — ", a.do_now.map(L).join(" "))))));
  }
  return card;
}

function predicted(iv) {
  const p = iv.predicted_next;
  if (!p) return null;
  return h("section", { class: "predict" },
    h("div", { class: "row" }, h("b", {}, t("res.predicted")), h("span", { class: "badge ai" }, t("res.unverified"))),
    h("div", { class: "big" }, L(p)),
    h("p", { class: "small muted" }, p.do_now.map(L).join(" ")),
    h("p", { class: "small muted" }, t("res.predicted_hint")));
}

function indicatorList(r) {
  if (r.input.kind === "url" && !r.indicators.length) return null;
  const box = h("section", { class: "card" }, h("h2", {}, t("res.why")));
  if (!r.indicators.length && !r.risk.inconsistencies.length) {
    box.append(h("p", { class: "muted" }, t("res.no_indicators")));
  }
  for (const ind of r.indicators) {
    const quotes = ind.evidence_refs.map(i => r.observed[i]?.quote).filter(Boolean);
    if (ind.quote) quotes.push(ind.quote);
    box.append(h("div", { class: "ind" },
      h("div", { class: "ind-head" },
        h("b", {}, L(ind, "label")),
        h("span", { class: `badge ${ind.source === "rule" ? "rule" : "ai"}` },
          t(`res.source.${ind.source}`), h("span", { class: "advanced" }, ` · +${ind.points}`))),
      h("p", { class: "small muted" }, L(ind, "explain")),
      quotes.length ? h("div", { class: "q-row" }, [...new Set(quotes)].slice(0, 3).map(q => h("span", { class: "quote", dir: "auto" }, `«${q}»`))) : null));
  }
  if (r.risk.inconsistencies.length) {
    box.append(h("h3", { class: "advanced", style: { "margin-top": "12px" } }, t("res.inconsistencies")));
    box.append(h("ul", { class: "list-plain" }, r.risk.inconsistencies.map(c => h("li", {}, L(c)))));
  }
  return box;
}

function highlighted(text, observed) {
  const spans = observed.filter(o => o.span && o.message_index === undefined).map(o => o.span).sort((a, b) => a[0] - b[0]);
  if (!spans.length) return null;
  const out = h("div", { class: "hl", dir: "auto" });
  let pos = 0;
  for (const [s, e] of spans) {
    if (s < pos) continue;
    out.append(text.slice(pos, s), h("mark", {}, text.slice(s, e)));
    pos = e;
  }
  out.append(text.slice(pos));
  return h("section", { class: "card advanced" }, h("h2", {}, t("res.highlighted")), out);
}

function conversationView(c) {
  if (!c) return null;
  const reached = new Set(c.stages_reached);
  return h("section", { class: "card" },
    h("h2", {}, t("res.conversation")),
    h("div", { class: "stages" }, STAGES.map(s => h("div", { class: `stage ${reached.has(s) ? "on" : ""} ${s}` }, t(`stage.${s}`)))),
    h("p", { class: "small" }, c.escalation ? t("res.escalation_yes") : t("res.escalation_no")),
    h("details", { class: "tech advanced" }, h("summary", {}, `${t("res.messages")} (${c.message_count})`),
      c.messages.map(m => h("div", { class: `msg ${m.tactics.length ? "flag" : ""}` },
        h("div", { class: "who" }, h("span", {}, m.sender || "—"), m.timestamp ? h("span", { class: "mono" }, m.timestamp) : null,
          m.stage ? h("span", { class: "badge" }, t(`stage.${m.stage}`)) : null),
        h("div", { dir: "auto" }, m.text)))));
}

function linksView(urls) {
  if (!urls.length) return null;
  return h("section", { class: "card rx-links" }, h("h2", {}, t("res.links")),
    urls.map(u => h("div", { class: "url-item" },
      h("div", { class: "row" }, h("code", {}, u.defanged), h("span", { class: `badge ${u.level}` }, t(`res.level.${u.level}`)),
        u.official_domain ? h("span", { class: "badge verified" }, t("res.official")) : null),
      u.signals.length ? h("ul", {}, u.signals.map(s => h("li", {}, L(s)))) : h("p", { class: "small muted" }, t("res.no_signals")))));
}

// Live-intelligence matches, kept honest: confirmed listing, MERQAB's own unverified detection, or a
// naming-pattern prediction — each with its source, time and a path to the campaign's intelligence.
function radarView(matches) {
  if (!matches?.length) return null;
  const j = getJourney();
  return h("section", { class: "community-hit radar-hit" }, matches.map(m => {
    const c = m.campaign;
    const kind = m.predicted ? "predicted" : m.confirmed ? "confirmed" : "suspected";
    const what = m.predicted ? t("res.radar_predicted") : m.confirmed ? t("res.radar_confirmed") : t("res.radar_ct");
    const mine = j && c && j.campaign_id === c.campaign_id;
    return h("div", { class: `rh rh-${kind}` },
      h("div", { class: "rh-head" },
        h("span", { class: `badge ${kind === "confirmed" ? "critical" : "inference"}` }, t(`rh.${kind}`)),
        h("code", {}, m.host.replace(/\./g, "[.]")),
        m.first_seen ? h("span", { class: "small muted" }, `${t("radar.first_seen")} ${new Date(m.first_seen).toLocaleString(locale())}`) : null),
      h("p", { class: "small" }, what, kind !== "confirmed" ? ` ${t("rh.not_proven")}` : ""),
      mine ? h("p", { class: "small rh-mine" }, `◎ ${t("rh.same_campaign")}`) : null,
      c ? h("button", { class: "btn secondary sm", type: "button", onclick: () => goExplore({ campaign_id: c.campaign_id }) },
        `◎ ${t("rh.explore")} · ${L(c, "name")} · ${c.size} ${t("radar.sites")}`) : null);
  }));
}

function communityView(matches) {
  if (!matches.length) return null;
  return h("section", { class: "community-hit" }, matches.map(m => h("p", {},
    h("b", {}, m.type === "indicator" ? t("res.community_match") : t("res.community_resembles")), ": ",
    h("a", { href: "#/community" }, L(m, "title")))));
}

function inferencesView(r) {
  if (!r.inferences.length) return null;
  return h("section", { class: "card advanced" }, h("h2", {}, t("res.inferences")),
    r.inferences.map(i => h("div", { class: "ind" },
      h("div", { class: "ind-head" }, h("span", {}, L(i)),
        h("span", { class: `badge ${i.source === "ai_inference" ? "ai" : "rule"}` }, t("res.unverified"))))));
}

function uncertaintyView(r) {
  const items = [...r.risk.uncertainty, ...r.limitations];
  if (!items.length) return null;
  return h("section", { class: "notice advanced" }, h("b", {}, t("res.uncertainty")),
    h("ul", { class: "list-plain small" }, items.map(x => h("li", {}, L(x)))));
}

function feedbackView(r) {
  if (!r.analysis_id) return null;
  const box = h("div", { class: "feedback" }, h("span", { class: "small muted" }, t("res.feedback_q")));
  const send = async (verdict) => {
    try { await api(`/analyze/${r.analysis_id}/feedback`, { method: "POST", body: { verdict } }); }
    catch (e) { if (e.status !== 409) return toast(e.message); }
    box.replaceChildren(h("span", { class: "small muted" }, t("res.feedback_thanks")));
  };
  box.append(h("button", { class: "btn secondary sm", type: "button", onclick: () => send("helpful") }, t("res.feedback_yes")),
             h("button", { class: "btn secondary sm", type: "button", onclick: () => send("incorrect") }, t("res.feedback_no")),
             h("span", { class: "spacer" }),
             h("button", { class: "btn ghost sm", type: "button", onclick: () => download("mirqab-check.txt", summaryText(r)) }, t("res.download")));
  return box;
}

export function summaryText(r) {
  const lines = [`MERQAB — ${t(`res.level.${r.risk.level}`)} (${r.risk.score}/100)`, t(`res.verdict.${r.risk.level}`), "",
    `${t("res.do_now")}: ${L(r.intervention.primary)}`, ...r.intervention.primary.do_now.map(x => `- ${L(x)}`), "",
    `${t("res.why")}:`, ...r.indicators.map(i => `- ${L(i, "label")}`),
    ...r.urls.map(u => `- ${u.defanged} — ${t(`res.level.${u.level}`)}`), "",
    `${t("res.uncertainty")}:`, ...[...r.risk.uncertainty, ...r.limitations].map(x => `- ${L(x)}`)];
  return lines.join("\n");
}

// Evidence & takedown pack (registration, hosting, timestamps) for each link in the result.
function evidencePack(r) {
  const urls = (r.urls || []).filter((u) => !u.official_domain);
  if (!urls.length) return null;
  const out = h("div", { class: "ep-out" });
  const btn = h("button", { class: "btn", type: "button" }, t("ep.build"));
  btn.addEventListener("click", async () => {
    btn.disabled = true; out.replaceChildren(h("p", { class: "small muted" }, t("ep.building")));
    try { out.replaceChildren(packView(await api("/evidence/link", { method: "POST", body: { url: urls[0].url } }))); }
    catch (e) { out.replaceChildren(h("p", { class: "notice warn small" }, e.message)); btn.disabled = false; }
  });
  return h("section", { class: "card ep" }, h("h2", {}, t("ep.title")), h("p", { class: "small muted" }, t("ep.sub")),
    h("div", { class: "row" }, btn, h("span", { class: "small muted", dir: "ltr" }, urls[0].defanged)), out);
}

function packView(p) {
  const reg = p.registration || {}, host = p.hosting?.[0] || {};
  const row = (k, v, cls = "") => (v ? h("div", { class: `ep-row ${cls}` }, h("dt", {}, t(k)), h("dd", { dir: "auto" }, v)) : null);
  const age = reg.age_days != null ? `${reg.age_days} ${t("ep.days")}` : null;
  const listed = p.radar?.length ? p.radar.map((x) => `${x.sources} · ${t("ep.first_seen")} ${x.first_seen}`).join(" | ") : t("ep.not_listed");
  const letter = takedownLetter(p);
  return h("div", { class: "ep-pack" },
    h("div", { class: "ep-head" }, h("b", {}, p.pack_id), h("span", { class: "small muted", dir: "ltr" }, `${p.generated_at} · SHA-256 ${p.sha256.slice(0, 16)}…`)),
    reg.newly_registered ? h("p", { class: "ep-new" }, t("ep.new").replace("{d}", reg.age_days)) : null,
    h("dl", { class: "ep-grid" },
      row("ep.k_url", p.url.defanged), row("ep.k_domain", p.url.registrable_domain),
      row("ep.k_registered", reg.registered ? `${reg.registered.slice(0, 10)} (${age})` : t("ep.unavailable"), reg.newly_registered ? "warn" : ""),
      row("ep.k_registrar", reg.registrar ? `${reg.registrar}${reg.registrar_iana_id ? ` · IANA ${reg.registrar_iana_id}` : ""}` : null),
      row("ep.k_expires", reg.expires?.slice(0, 10)), row("ep.k_ns", reg.nameservers?.join(", ")),
      row("ep.k_ip", p.dns.resolved.join(", ") || t("ep.no_dns")),
      row("ep.k_host", host.status === "ok" ? [host.network, host.organisation, host.country, host.range].filter(Boolean).join(" · ") : null),
      row("ep.k_abuse", p.abuse_contacts.join(", ")), row("ep.k_radar", listed),
      row("ep.k_risk", `${p.analysis.score}/100 · ${t(`res.level.${p.analysis.level}`)}${p.analysis.impersonated_brand ? ` · ${p.analysis.impersonated_brand}` : ""}`)),
    h("p", { class: "small muted" }, L(p.method)),
    h("div", { class: "row" },
      h("button", { class: "btn secondary sm", type: "button", onclick: () => download(`${p.pack_id}-takedown.txt`, letter) }, t("ep.dl_letter")),
      h("button", { class: "btn secondary sm", type: "button", onclick: () => download(`${p.pack_id}.json`, JSON.stringify(p, null, 2)) }, t("ep.dl_json"))));
}

function takedownLetter(p) {
  const reg = p.registration || {}, host = p.hosting?.[0] || {};
  const lines = [
    `MERQAB — Phishing takedown request / طلب إزالة موقع تصيّد`, `Reference: ${p.pack_id}`, `Generated (UTC): ${p.generated_at}`, `SHA-256: ${p.sha256}`, "",
    `To: ${p.abuse_contacts.join(", ") || "(registrar / hosting abuse desk)"}`, "",
    "We report the following address as a phishing / fraud site and request its suspension.", "",
    `URL (defanged): ${p.url.defanged}`, `Domain: ${p.url.registrable_domain}`,
    `Registered: ${reg.registered || "n/a"}${reg.age_days != null ? ` (${reg.age_days} days ago)` : ""}`, `Registrar: ${reg.registrar || "n/a"}${reg.registrar_iana_id ? ` (IANA ${reg.registrar_iana_id})` : ""}`,
    `Name servers: ${(reg.nameservers || []).join(", ") || "n/a"}`, `Resolves to: ${p.dns.resolved.join(", ") || "n/a"}`,
    `Hosting network: ${[host.network, host.organisation, host.country].filter(Boolean).join(" / ") || "n/a"}`, "",
    `Assessment: ${p.analysis.score}/100 (${p.analysis.level})${p.analysis.impersonated_brand ? `, impersonating ${p.analysis.impersonated_brand}` : ""}`,
    "Indicators:", ...p.analysis.signals.map((s) => `- ${s.en}`),
    ...(p.radar?.length ? ["", "Threat-feed / radar record:", ...p.radar.map((x) => `- ${x.host} · ${x.sources} · first seen ${x.first_seen}`)] : []), "",
    p.method.en, "", "UAE: also report to Abu Dhabi Police Aman 800 2626 or via u.ae → Report cybercrimes online.",
  ];
  return lines.join("\n");
}

export function renderResult(r, { sourceText, extractedText, headerSignals } = {}) {
  state.lastCheck = r;
  r._src = sourceText || extractedText || "";
  // One continuous report panel: verdict → what to do → why → (collapsed) details → feedback.
  const details = [
    radarView(r.radar_matches), communityView(r.community_matches), predicted(r.intervention),
    linksView(r.urls),
    headerSignals?.length ? h("section", { class: "card" }, h("h2", {}, t("res.header_signals")),
      h("ul", { class: "list-plain" }, headerSignals.map(s => h("li", {}, L(s))))) : null,
    conversationView(r.conversation),
    sourceText && r.input.kind === "text" ? highlighted(sourceText, r.observed) : null,
    extractedText ? h("details", { class: "card tech advanced" }, h("summary", {}, t("res.extracted_text")), h("pre", { class: "box", dir: "auto" }, extractedText)) : null,
    inferencesView(r), uncertaintyView(r),
  ].filter(Boolean);
  // live-radar hits, and the link analysis of a link check, stay open; the rest folds away
  const open = details.filter(d => d.classList.contains("radar-hit") || (r.input.kind === "url" && d.classList.contains("rx-links")));
  const rest = details.filter(d => !open.includes(d));
  return h("article", { class: `rx lvl-${r.risk.level}`, id: "result" },
    ...[riskHeader(r), actionCard(r.intervention), indicatorList(r), ...open, evidencePack(r),
      rest.length ? h("details", { class: "rx-more" }, h("summary", {}, t("res.more_details"), h("span", { class: "rx-count" }, String(rest.length))), ...rest) : null,
      feedbackView(r)].filter(Boolean));
}
