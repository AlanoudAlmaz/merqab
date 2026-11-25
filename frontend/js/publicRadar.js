import { api, errorBox, h, L, locale, t } from "./core.js";

const fmt = (n) => Number(n || 0).toLocaleString(locale());
// plain-language headline numbers for the radar (all counted from stored data by /api/radar/public)
function summaryPanel(s) {
  if (!s) return null;
  const card = (value, label, sub, tone = "") => h("div", { class: `ps-card ${tone}` },
    h("b", { class: "ps-val" }, value), h("span", { class: "ps-lbl" }, label), sub ? h("span", { class: "ps-sub" }, sub) : null);
  const speed = s.speed_seconds == null ? t("ps.speed_wait")
    : s.speed_seconds < 120 ? `${t("ps.within")} ${fmt(s.speed_seconds)} ${t("ps.sec")}` : `${t("ps.within")} ${fmt(Math.round(s.speed_seconds / 60))} ${t("ps.min")}`;
  const acc = s.accuracy ? `${(s.accuracy.accuracy * 100).toFixed(1)}%` : "—";
  const total = Object.values(s.sectors || {}).reduce((a, b) => a + b, 0) || 1;
  const types = Object.entries(s.sectors || {}).map(([k, n]) => h("li", {},
    h("span", { class: "ps-tname" }, t(`pr.sector.${k}`)), h("span", { class: "ps-bar" }, h("i", { style: { width: `${Math.max(3, n / total * 100)}%` } })), h("b", {}, fmt(n))));
  return h("section", { class: "ps", "aria-label": t("ps.title") },
    h("div", { class: "ps-grid" },
      card(fmt(s.indicators), t("ps.indicators"), t("ps.indicators_sub").replace("{n}", fmt(s.new_24h))),
      card(acc, t("ps.accuracy"), s.accuracy ? t("ps.accuracy_sub").replace("{n}", fmt(s.accuracy.n)) : null, "good"),
      card(speed, t("ps.speed"), t("ps.speed_sub")),
      card(fmt(s.campaigns), t("ps.campaigns"), t("ps.campaigns_sub").replace("{n}", fmt(s.critical_campaigns)), "warn"),
      card(fmt(s.brands), t("ps.brands"), t("ps.brands_sub"))),
    types.length ? h("div", { class: "ps-types" }, h("h3", {}, t("ps.types")), h("ul", {}, types)) : null);
}
import { takeExplore } from "./journey.js";

let requestVersion = 0;
let timer;
export function stopRadar() { requestVersion++; clearTimeout(timer); }

export async function radarPage(root, focus) {
  const version = ++requestVersion;
  let selected = takeExplore()?.campaign_id || focus;
  const content = h("div", { class: "pr-body" }, h("p", { role: "status" }, t("common.loading")));
  root.replaceChildren(h("section", { class: "pr" },
    h("header", { class: "page-head" }, h("div", {}, h("h1", {}, t("radar.title")), h("p", { class: "muted" }, t("pr.subtitle")))),
    content));
  const stamp = h("p", { class: "pr-stamp small muted" });
  const payload = h("div");
  const summary = h("div");
  content.append(summary, stamp, payload);
  let signature;
  let snapshot;
  async function refresh() {
    try {
      const data = await api("/radar/public");
      if (version !== requestVersion) return;
      const sourceTime = data.source_updated_at
        ? new Date(data.source_updated_at).toLocaleString(locale(), { dateStyle: "medium", timeStyle: "medium" })
        : t("pr.awaiting_source");
      stamp.textContent = `${t("pr.updated")} ${sourceTime} · ${t("pr.refresh")}`;
      content.querySelector('[role="status"]')?.remove();
      summary.replaceChildren(...[summaryPanel(data.summary)].filter(Boolean));
      const nextSignature = JSON.stringify([data.enabled, data.total, data.campaigns]);
      if (nextSignature === signature) return;
      const campaigns = data.campaigns;
      const previous = new Map(snapshot?.campaigns.map(c => [c.id, c.last_seen]) || []);
      snapshot = data;
      signature = nextSignature;
      const map = h("div", { class: "pr-map", role: "group", "aria-label": t("pr.map") });
      const orbit = h("div", { class: "pr-orbit" });
      map.append(orbit);
      const legend = h("ul", { class: "pr-legend" }, ["critical", "high", "medium", "low"].map(level =>
        h("li", { class: `pr-risk ${level}` }, h("i"), t(`res.level.${level}`))));
      const list = h("ol", { class: "pr-list" });
      const details = h("div", { class: "pr-detail", "aria-live": "polite" });
      const controls = [];
      const date = value => new Date(value).toLocaleString(locale(), { dateStyle: "medium", timeStyle: "short" });
      const name = campaign => {
        const brand = L(campaign, "brand");
        return brand ? t("pr.target").replace("{brand}", brand) : t(`pr.sector.${campaign.sector}`);
      };
      const status = campaign => t(`pr.${campaign.status}`);
      function select(campaign) {
        selected = campaign.id;
        for (const [item, point, row] of controls) {
          for (const button of [point, row]) button.setAttribute("aria-pressed", String(item.id === selected));
        }
        details.replaceChildren(
          h("h2", {}, name(campaign)),
          h("p", { class: `pr-risk ${campaign.level}` }, h("i"), t(`res.level.${campaign.level}`)),
          h("p", { class: "small muted" }, status(campaign), " · ", t("radar.first_seen"), " ", date(campaign.first_seen)),
          h("p", { class: "small muted" }, t("pr.last_seen"), " ", date(campaign.last_seen)),
          h("p", {}, t("pr.description").replace("{total}", campaign.size).replace("{listed}", campaign.listed_now), " ", L(campaign, "harm")),
          campaign.sources.length ? h("p", { class: "small muted" }, t("pr.sources"), " · ", campaign.sources.map(source => L(source)).join(" · ")) : null,
          h("ul", {}, campaign.prevention.map(action => h("li", {}, L(action)))));
      }
      // rings are time bands: the closer to the centre, the more recently the campaign was first detected
      const BANDS = [[600e3, 5, 15], [3600e3, 18, 28], [86400e3, 32, 38], [Infinity, 42, 45]];
      const now = Date.now(), perBand = [0, 0, 0, 0];
      ["m10", "h1", "d1", "old"].forEach((k, i) => map.append(h("span", { class: `pr-ring r${i}`, "aria-hidden": "true" }, h("em", {}, t(`pr.ring.${k}`)))));
      campaigns.forEach((campaign, index) => {
        const age = Math.max(0, now - new Date(campaign.first_seen).getTime());
        const band = BANDS.findIndex(([limit]) => age < limit);
        const [limit, r0, r1] = BANDS[band];
        const lower = band ? BANDS[band - 1][0] : 0;
        const frac = Number.isFinite(limit) ? Math.min(1, (age - lower) / (limit - lower)) : Math.min(1, Math.log10(1 + (age - lower) / 86400e3) / 2);
        const radius = r0 + frac * (r1 - r0) + ((perBand[band] % 3) - 1) * .9;   // small stagger so neighbours never overlap
        const angle = perBand[band]++ * 2.39996 + band * .7;          // golden angle: spreads points evenly round the ring
        const point = h("button", { type: "button", class: `pr-point pr-risk ${campaign.level}${previous.size && previous.get(campaign.id) !== campaign.last_seen ? " fresh" : ""}`,
          title: name(campaign), "aria-label": `${name(campaign)} · ${t(`res.level.${campaign.level}`)} · ${status(campaign)} · ${date(campaign.first_seen)}`,
          style: { "--delay": `${index * -.17}s`, "--x": `${50 + Math.cos(angle) * radius}%`, "--y": `${50 + Math.sin(angle) * radius}%` },
          onclick: () => select(campaign) });
        const row = h("button", { type: "button", onclick: () => select(campaign) },
          h("b", { class: `pr-risk ${campaign.level}` }, h("i"), name(campaign)), h("span", {}, t(`res.level.${campaign.level}`), " · ", date(campaign.last_seen)));
        controls.push([campaign, point, row]);
        orbit.append(point);
        list.append(h("li", {}, row));
      });
      const state = h("p", { class: "small muted" }, data.enabled ? t("pr.enabled") : t("pr.paused"), " · ", data.total, " ", t("pr.campaigns"));
      if (!campaigns.length) {
        payload.replaceChildren(state, h("p", {}, t("pr.empty")));
        return;
      }
      const layouts = h("div", { class: "pr-layout" }, h("div", {}, map, legend, h("p", { class: "pr-ring-note small muted" }, t("pr.ring_note"))), h("div", { class: "pr-side" }, details, list));
      payload.replaceChildren(state, layouts);
      select(campaigns.find(c => c.id === selected) || campaigns[0]);
    } catch (error) {
      if (version === requestVersion) {
        if (snapshot) stamp.textContent = t("pr.retry");
        else payload.replaceChildren(errorBox(error));
        content.querySelector('[role="status"]')?.remove();
      }
    } finally {
      if (version === requestVersion) timer = setTimeout(refresh, 10000);
    }
  }
  await refresh();
}
