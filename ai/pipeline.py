"""Unified behavioural-intelligence pipeline shared by Prevention and Investigation."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ai import RULES_VERSION
from ai.behavioral_analysis.analyzer import Hit, analyze_text, match_patterns
from ai.behavioral_analysis.conversation import assess_conversation, parse_conversation
from ai.behavioral_analysis.tactics import TACTICS
from ai.behavioral_analysis.url_analyzer import analyze_url, brand_data, extract_urls, refang, registrable_domain
from ai.llm.provider import LLMProvider, LLMResult
from ai.risk_assessment.intervention import plan_intervention
from ai.risk_assessment.scoring import level_for, score

MAX_INPUT_CHARS = 20000


@dataclass
class CommunityIndex:
    """Indicators from *published* (human-validated) community alerts only."""
    domains: dict[str, int] = field(default_factory=dict)   # registrable domain -> alert id
    patterns: dict[str, list[int]] = field(default_factory=dict)  # pattern key -> alert ids
    titles: dict[int, dict] = field(default_factory=dict)
    radar_hosts: dict[str, dict] = field(default_factory=dict)  # exact host -> radar item
    radar_domains: dict[str, dict] = field(default_factory=dict)  # registrable domain (CT, non-shared) -> item
    campaign_templates: dict[tuple, dict] = field(default_factory=dict)  # (brand, naming template) -> campaign


def _brand_mismatches(brands: list[str], url_reports: list[dict]) -> list[dict]:
    data = brand_data()["brands"]
    out = []
    for b in brands:
        official = set(data[b]["domains"])
        for r in url_reports:
            d = r["registrable_domain"]
            if d and d not in official and not r["official_domain"] and r["signals"] is not None:
                if all(x["domain"] != d for x in out):
                    out.append({"brand": " ".join(w.upper() if len(w) <= 4 else w.capitalize() for w in data[b]["names"][0].split()), "domain": d})
    return out


def analyze(kind: str, content: str, llm: LLMProvider | None = None, community: CommunityIndex | None = None) -> dict:
    if kind not in ("text", "conversation", "url"):
        raise ValueError("kind must be text, conversation or url")
    content = (content or "")[:MAX_INPUT_CHARS]
    llm = llm or LLMProvider()
    community = community or CommunityIndex()

    conversation = None
    hits: list[Hit] = []
    negated = 0
    brands: list[str] = []
    if kind == "url":
        urls = extract_urls(content) or ([content.strip()] if content.strip() else [])
    elif kind == "conversation":
        msgs = parse_conversation(content)
        ca = assess_conversation(msgs)
        conversation = ca.to_dict()
        urls = []
        for m in msgs:
            hits += m.analysis.hits
            negated += len(m.analysis.negated)
            urls += [u for u in m.analysis.urls if u not in urls]
            brands += [b for b in m.analysis.brands_mentioned if b not in brands]
    else:
        ta = analyze_text(content)
        hits, negated, urls, brands = ta.hits, len(ta.negated), ta.urls, ta.brands_mentioned

    url_reports = [analyze_url(u).to_dict() for u in urls[:10]]
    tactics = {h.tactic for h in hits}

    # ---- optional AI inference (grounded) ----
    llm_res: LLMResult = llm.analyze(content) if (llm.available() and kind != "url" and content.strip()) else LLMResult(
        status="not_configured" if not llm.available() else "disabled", provider=llm.name)
    llm_extra = [g["key"] for g in llm_res.grounded_tactics if g["key"] not in tactics] if llm_res.status == "used" else []

    # ---- community intelligence (validated alerts only) ----
    community_matches = []
    for r in url_reports:
        aid = community.domains.get(r["registrable_domain"])
        if aid is not None:
            community_matches.append({"alert_id": aid, "type": "indicator", "value": r["registrable_domain"],
                                      **community.titles.get(aid, {})})

    radar_matches = []
    shared = set(brand_data().get("shared_hosting", []))
    for r in url_reports:
        h = r["host"]
        item = next((community.radar_hosts[x] for x in [h] + [h.split(".", i)[-1] for i in range(1, h.count("."))]
                     if x in community.radar_hosts), None)
        if not item and r["registrable_domain"] not in shared:
            item = community.radar_domains.get(r["registrable_domain"])
        if item and all(m["host"] != item["host"] for m in radar_matches):
            radar_matches.append(item)
        elif not item and community.campaign_templates:
            # Predictive: an unseen domain that follows a known campaign's naming DNA
            from ai.threat_intelligence.campaigns import genes
            ge = genes({"host": h, "registrable_domain": r["registrable_domain"], "brand": r["impersonated_brand"],
                        "first_seen": ""})
            camp = community.campaign_templates.get((ge["brand"], ge["template"])) if ge["template"] else None
            if camp:
                radar_matches.append({"host": h, "brand": ge["brand"], "confirmed": False, "predicted": True,
                                      "first_seen": None, "campaign": camp, "sources": []})

    mismatches = _brand_mismatches(brands, url_reports)
    patterns = match_patterns(tactics | set(llm_extra), content, bool(url_reports))
    risk = score(tactics, url_reports, mismatches, community_matches, len(content.strip()), negated, llm_extra, llm_res.status,
                 patterns[0] if patterns else None, radar_matches)

    resemblances = []
    if patterns:
        for aid in community.patterns.get(patterns[0]["key"], [])[:3]:
            resemblances.append({"alert_id": aid, "type": "pattern", "value": patterns[0]["key"], **community.titles.get(aid, {})})

    risky_url = any(r["score"] >= 20 for r in url_reports) or bool(mismatches) or bool(radar_matches)
    intervention = plan_intervention(tactics | set(llm_extra), patterns, risky_url, risk.level)

    # ---- assemble explainable result: observed / indicators / inferences ----
    observed = [h.to_dict() for h in hits]
    observed += [{"tactic": None, "type": "url", "quote": u, "context": None} for u in urls[:10]]
    indicators = []
    for t in sorted(tactics, key=lambda k: -TACTICS[k].weight):
        tac = TACTICS[t]
        refs = [i for i, h in enumerate(hits) if h.tactic == t]
        indicators.append({"key": t, "source": "rule", "label_en": tac.label_en, "label_ar": tac.label_ar,
                           "explain_en": tac.explain_en, "explain_ar": tac.explain_ar, "points": tac.weight,
                           "stage": tac.stage, "evidence_refs": refs})
    for g in llm_res.grounded_tactics if llm_res.status == "used" else []:
        if g["key"] in llm_extra:
            tac = TACTICS[g["key"]]
            indicators.append({"key": g["key"], "source": "ai_inference", "label_en": tac.label_en, "label_ar": tac.label_ar,
                               "explain_en": tac.explain_en, "explain_ar": tac.explain_ar, "points": tac.weight // 2,
                               "stage": tac.stage, "evidence_refs": [], "quote": g["quote"]})

    inferences = []
    if patterns:
        p = patterns[0]
        inferences.append({"source": "heuristic", "type": "pattern", "key": p["key"],
                           "en": f"Resembles a known fraud pattern: {p['name_en']}.",
                           "ar": f"يشبه نمط احتيال معروف: {p['name_ar']}.",
                           "basis": p["supporting_tactics"], "verified": False})
    pn = intervention.get("predicted_next") or (intervention["primary"] if intervention["primary"].get("anticipated") else None)
    if pn:
        inferences.append({"source": "heuristic", "type": "prediction", "key": pn["key"],
                           "en": f"Likely next step in this scam: a request to — {pn['en'].lower()}.",
                           "ar": f"الخطوة التالية المتوقعة في هذا الاحتيال: {pn['ar']}.", "verified": False})
    for m in radar_matches:
        c = m.get("campaign")
        if m.get("predicted") and c:
            inferences.append({"source": "heuristic", "type": "campaign_prediction", "key": c["campaign_id"],
                               "en": f"This new address follows the naming pattern of campaign {c['campaign_id']} ({c['name_en']}).",
                               "ar": f"هذا العنوان الجديد يتبع نمط تسمية الحملة {c['campaign_id']} ({c['name_ar']}).", "verified": False})
        elif c:
            inferences.append({"source": "heuristic", "type": "campaign", "key": c["campaign_id"],
                               "en": f"Linked to scam campaign {c['campaign_id']} — {c['size']} related sites share traits ({c['name_en']}). The link is inferred, not proven.",
                               "ar": f"مرتبط بحملة الاحتيال {c['campaign_id']} — {c['size']} مواقع تشترك في سمات ({c['name_ar']}). الارتباط مستنتج وغير مثبت.", "verified": False})
    if llm_res.status == "used" and (llm_res.summary_en or llm_res.summary_ar):
        inferences.append({"source": "ai_inference", "type": "summary", "en": llm_res.summary_en, "ar": llm_res.summary_ar,
                           "confidence": llm_res.confidence, "verified": False})

    if not url_reports:
        limitations = []
    elif community.radar_hosts:  # the Live Radar's stored OpenPhish list and look-alike detections
        limitations = [{"en": "Links are analysed offline; MIRGAB never opens them. They were checked against the OpenPhish list and MIRGAB's own look-alike detections stored by the Live Radar — a new site may not be listed yet.",
                        "ar": "تُحلَّل الروابط دون فتحها؛ مرقاب لا يزورها أبداً. فُحصت مقابل قائمة OpenPhish والمواقع المقلّدة التي رصدها مرقاب في الرادار المباشر — قد لا يكون الموقع الجديد مدرجاً بعد."}]
    else:
        limitations = [{"en": "Links are analysed offline; MIRGAB never opens them. No reputation data is available (the Live Radar is off or has no data yet).",
                        "ar": "تُحلَّل الروابط دون فتحها؛ مرقاب لا يزورها أبداً. لا تتوفر بيانات سمعة (الرادار المباشر متوقف أو بلا بيانات بعد)."}]
    if "identity_claim" in tactics:
        limitations.append({"en": "Voice/video deepfake detection requires a media-forensics model that is not configured; only text cues were assessed.",
                            "ar": "كشف التزييف العميق للصوت والفيديو يتطلب نموذج تحليل وسائط غير مفعّل؛ تم تقييم المؤشرات النصية فقط."})

    return {
        "engine": {"rules_version": RULES_VERSION, "llm": {k: v for k, v in llm_res.to_dict().items()
                                                           if k in ("status", "provider", "model", "rejected_claims", "error")}},
        "input": {"kind": kind, "length": len(content), "sha256": hashlib.sha256(content.encode()).hexdigest()},
        "risk": risk.to_dict(),
        "intervention": intervention,
        "observed": observed,
        "indicators": indicators,
        "inferences": inferences,
        "patterns": patterns[:3],
        "urls": url_reports,
        "brand_mismatches": mismatches,
        "conversation": conversation,
        "community_matches": community_matches + resemblances,
        "radar_matches": radar_matches,
        "protective_phrases": negated,
        "limitations": limitations,
    }


def indicator_domains(text: str) -> list[str]:
    return sorted({registrable_domain(analyze_url(u).host) for u in extract_urls(text) if analyze_url(u).host})


__all__ = ["analyze", "CommunityIndex", "indicator_domains", "level_for", "refang"]
