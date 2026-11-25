"""Live Threat Radar API — findings, Scam Campaign DNA and actions into existing workflows.

One action model for single findings and campaigns: a "target" is either an item id or a campaign id.
  warn        (reviewer)     → community-alert draft (a second reviewer must still publish it)
  investigate (investigator) → immutable snapshot evidence added to a new or existing case
  dismiss     (reviewer)     → false alarm; removed from prevention matching
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, model_validator

from ai.risk_assessment.intervention import ACTIONS
from ai.behavioral_analysis.url_analyzer import brand_data, extract_urls, refang, registrable_domain
from ai.pipeline import analyze
from ai.risk_assessment.scoring import level_for
from ai.threat_intelligence.campaigns import HARM, _sector
from ai.threat_intelligence.community import build_alert_draft
from backend.app import audit
from backend.app.api.cases import _insert_evidence
from backend.app.db import now
from backend.app.radar import FEED_SOURCES, SOURCE_LABELS
from backend.app.security import current_user, get_db, rate_limit, require
from backend.app.services import community_index, next_case_ref, radar_intel

router = APIRouter(prefix="/api", tags=["radar"])


class Target(BaseModel):
    item_id: int | None = None
    campaign_id: str | None = Field(default=None, max_length=12, pattern=r"^C-[0-9A-F]{6}$")

    @model_validator(mode="after")
    def one(self):
        if bool(self.item_id) == bool(self.campaign_id):
            raise ValueError("Give exactly one of item_id or campaign_id")
        return self


class InvestigateIn(Target):
    case_id: int | None = None
    title: str | None = Field(default=None, min_length=3, max_length=160)


class DismissIn(BaseModel):
    note: str | None = Field(default=None, max_length=500)


def _public_item(it: dict, camp: dict | None) -> dict:
    keep = ("id", "host", "registrable_domain", "url", "sources", "brand", "method", "score", "reasons", "first_seen",
            "last_seen", "seen_count", "status", "confirmed", "active", "last_listed", "evidence", "alert_id")
    d = {k: it.get(k) for k in keep}
    d["campaign"] = camp
    return d


def _resolve(intel: dict, t: Target) -> tuple[list[dict], dict | None]:
    if t.campaign_id:
        c = next((c for c in intel["campaigns"] if c["id"] == t.campaign_id), None)
        if not c:
            raise HTTPException(404, "Campaign not found (it may have changed after new findings)")
        ids = set(c["members"])
        return [i for i in intel["items"] if i["id"] in ids], c
    it = next((i for i in intel["items"] if i["id"] == t.item_id), None)
    if not it:
        raise HTTPException(404, "Radar item not found")
    return [it], None


def _public_summary(db, intel: dict, brands: dict) -> dict:
    """Plain-language headline numbers for the public radar — every figure is counted from stored data."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    total, day, impersonated = db.execute(
        "SELECT COUNT(*), SUM(first_seen >= ?), COUNT(DISTINCT brand) FROM radar_items WHERE status != 'dismissed'", (since,)).fetchone()
    sectors = Counter(c["sector"] if c["sector"] in HARM else "unknown" for c in intel["campaigns"])
    critical = 0
    items = {item["id"]: item for item in intel["items"]}
    for c in intel["campaigns"]:
        if level_for(max((items[m].get("score") or 0 for m in c["members"] if m in items), default=0)) == "critical":
            critical += 1
    # speed: how fresh the newest certificate the radar has seen is (Certificate Transparency stream)
    speed = None
    row = db.execute("SELECT state, detail FROM radar_sources WHERE name='ct'").fetchone()
    if row and row[0] == "ok" and row[1]:
        try:
            speed = json.loads(row[1]).get("newest_certificate_age_seconds")
        except ValueError:
            speed = None
    acc = None
    try:
        from backend.app.api.accuracy import RESULTS
        o = json.loads(RESULTS.read_text())["overall"]
        acc = {"accuracy": o["accuracy"], "n": o["n"], "fp_rate": round(o["fp"] / max(1, o["fp"] + o["tn"]), 4)}
    except Exception:
        pass
    return {"indicators": total or 0, "new_24h": day or 0, "brands": impersonated or 0, "campaigns": len(intel["campaigns"]),
            "critical_campaigns": critical, "sectors": dict(sectors.most_common()), "speed_seconds": speed, "accuracy": acc}


@router.get("/radar/public", dependencies=[rate_limit("radar_public")])
def public_radar(request: Request, db=Depends(get_db)):
    intel = radar_intel(db)
    items = {item["id"]: item for item in intel["items"]}
    brands = brand_data()["brands"]
    campaigns = []
    for campaign in sorted(intel["campaigns"], key=lambda c: c["last_seen"], reverse=True)[:30]:
        sector = campaign["sector"]
        harm_en, harm_ar, actions = HARM.get(sector, HARM["unknown"])
        members = [items[member] for member in campaign["members"] if member in items]
        known = Counter(item.get("brand") for item in members if item.get("brand") in brands)
        brand = known.most_common(1)[0][0] if known else None
        aliases = brands[brand]["names"] if brand else []
        sources = {source for item in members for source in item.get("sources", [])}
        campaigns.append({
            "id": campaign["id"], "sector": sector if sector in HARM else "unknown",
            "status": campaign["status"],
            "brand_en": aliases[0] if aliases else None,
            "brand_ar": next((alias for alias in aliases if any("\u0600" <= char <= "\u06ff" for char in alias)), aliases[0]) if aliases else None,
            "listed_now": sum(bool(item.get("active", 1) and set(item.get("sources", [])) & FEED_SOURCES) for item in members),
            "sources": [{"en": en, "ar": ar} for key, (en, ar) in SOURCE_LABELS.items() if key in sources],
            "level": level_for(max((item.get("score") or 0 for item in members), default=0)),
            "first_seen": campaign["first_seen"],
            "last_seen": campaign["last_seen"], "size": campaign["size"],
            "harm_en": harm_en, "harm_ar": harm_ar,
            "prevention": [{"en": en, "ar": ar} for key in actions for en, ar in ACTIONS[key]["do_now"]],
        })
    return {
        "enabled": request.app.state.radar.enabled, "campaigns": campaigns,
        "total": len(intel["campaigns"]),
        "summary": _public_summary(db, intel, brands),
        "source_updated_at": db.execute("SELECT MAX(last_success) FROM radar_sources").fetchone()[0],
    }


@router.get("/radar", dependencies=[require("investigator")])
def radar(request: Request, source: Literal["ct", "openphish", "certpl", "phishing_army", "phishing_db", "blocklist_project", "feeds"] | None = None, brand: str | None = None,
          limit: int = 100, db=Depends(get_db)):
    intel = radar_intel(db)
    items = intel["items"]
    if source:
        items = [i for i in items if (i["confirmed"] if source == "feeds" else source in i["sources"])]
    if brand:
        items = [i for i in items if i["brand"] == brand]
    items = sorted(items, key=lambda i: (i["first_seen"], i["id"]), reverse=True)[: max(1, min(limit, 300))]
    all_items = intel["items"]
    counts = {
        "confirmed_listed_now": sum(1 for i in all_items if i["confirmed"] and i.get("active", 1)),
        "confirmed_total": sum(1 for i in all_items if i["confirmed"]),
        "suspected": sum(1 for i in all_items if not i["confirmed"]),
        "campaigns": len(intel["campaigns"]),
    }
    return {"service": request.app.state.radar.snapshot(db), "counts": counts,
            # summaries only: the full member/link lists can be thousands of entries (see /radar/intel for detail)
            "campaigns": [{**c, "members": c["members"][:20], "hosts": c.get("hosts", [])[:20], "links": c.get("links", [])[:20],
                           "confirmed_flags": c.get("confirmed_flags", [])[:20]} for c in intel["campaigns"][:30]],
            "items": [_public_item(i, intel["campaign_of"].get(i["id"])) for i in items]}


LEVELS = {"low": 0, "medium": 20, "high": 45, "critical": 70}


def _since_ok(first_seen: str, since_hours: int | None) -> bool:
    if not since_hours:
        return True
    from datetime import datetime, timedelta, timezone
    try:
        t = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except ValueError:
        return True
    return t >= datetime.now(timezone.utc) - timedelta(hours=since_hours)


SourceKey = Literal["ct", "openphish", "certpl", "phishing_army", "phishing_db", "blocklist_project", "feeds"]
RiskKey = Literal["low", "medium", "high", "critical"]


class RadarFilter(BaseModel):
    """One filter model for the constellation, the report and its CSV export, so all three always agree."""
    status: Literal["all", "confirmed", "suspected"] = "all"
    brand: str | None = Field(default=None, max_length=60)
    connected_only: bool = False
    source: SourceKey | None = None
    since_hours: int | None = Field(default=None, ge=1, le=24 * 365)
    min_risk: RiskKey | None = None
    listed_now: bool = False
    warned: bool = False
    in_campaign: bool = False


def _select(intel: dict, db, f: RadarFilter) -> list[dict]:
    linked = {e["a"] for e in intel["edges"]} | {e["b"] for e in intel["edges"]}
    sel = [i for i in intel["items"]
           if (f.status == "all" or (f.status == "confirmed") == i["confirmed"])
           and (not f.brand or i["brand"] == f.brand)
           and (not f.connected_only or i["id"] in linked)
           and (not f.source or (i["confirmed"] if f.source == "feeds" else f.source in i["sources"]))
           and (not f.min_risk or (i["score"] or 0) >= LEVELS[f.min_risk])
           and (not f.listed_now or (i["confirmed"] and i.get("active", 1)))
           and (not f.in_campaign or i["id"] in intel["campaign_of"])
           and _since_ok(i["first_seen"], f.since_hours)]
    if f.warned:
        published = {r["id"] for r in db.execute("SELECT id FROM alerts WHERE status='published'")}
        sel = [i for i in sel if i.get("alert_id") in published]
    return sel


@router.get("/radar/graph", dependencies=[require("investigator")])
def graph(status: Literal["all", "confirmed", "suspected"] = "all", brand: str | None = None,
          connected_only: bool = True, limit: int = 400,
          source: SourceKey | None = None, since_hours: int | None = Query(default=None, ge=1, le=24 * 365),
          min_risk: RiskKey | None = None, listed_now: bool = False,
          warned: bool = False, in_campaign: bool = False, db=Depends(get_db)):
    """Threat Constellation data: every node is a stored radar finding, every edge a link produced by
    Scam Campaign DNA with its stated reason. Nothing is generated for display only."""
    intel = radar_intel(db)
    items = intel["items"]
    linked = {e["a"] for e in intel["edges"]} | {e["b"] for e in intel["edges"]}
    sel = _select(intel, db, RadarFilter(status=status, brand=brand, connected_only=connected_only, source=source,
                                         since_hours=since_hours, min_risk=min_risk, listed_now=listed_now,
                                         warned=warned, in_campaign=in_campaign))
    sel_all = sel
    sel = sorted(sel, key=lambda i: i["first_seen"], reverse=True)[: max(1, min(limit, 1000))]
    ids = {i["id"] for i in sel}
    alert_status = {r["id"]: r["status"] for r in db.execute("SELECT id, status FROM alerts")}
    camps = {c["id"]: c for c in intel["campaigns"]}
    nodes = []
    for i in sel:
        cid = intel["campaign_of"].get(i["id"], {}).get("campaign_id")
        c = camps.get(cid)
        lures = [w for w in i["host"].replace(".", "-").split("-")]
        sector = c["sector"] if c else _sector(i["brand"], lures)
        prevention = c["prevention"] if c else [{"en": ACTIONS[k]["en"], "ar": ACTIONS[k]["ar"]} for k in HARM[sector][2]]
        nodes.append({
            "id": i["id"], "host": i["host"], "url": i["url"], "brand": i["brand"], "seen_count": i.get("seen_count", 1),
            "status": "confirmed" if i["confirmed"] else "suspected", "score": i["score"],
            "risk_level": level_for(i["score"] or 0), "first_seen": i["first_seen"], "last_seen": i["last_seen"],
            "sources": i["sources"], "evidence": i["evidence"], "active": bool(i.get("active", 1)), "reasons": i["reasons"],
            "campaign_id": cid, "review_status": i["status"],
            "alert_status": alert_status.get(i.get("alert_id")) if i.get("alert_id") else None,
            "harm_en": HARM[sector][0], "harm_ar": HARM[sector][1], "prevention": prevention,
        })
    edges = [{"id": f"e{e['a']}-{e['b']}-{k}", "source": e["a"], "target": e["b"], "strength": e["strength"],
              "reason_en": e["en"], "reason_ar": e["ar"], "campaign_id": e["campaign_id"]}
             for k, e in enumerate(intel["edges"]) if e["a"] in ids and e["b"] in ids]
    shown_camps = []
    for c in intel["campaigns"]:
        members = [m for m in c["members"] if m in ids]
        if len(members) >= 2:
            shown_camps.append({k: c[k] for k in ("id", "name_en", "name_ar", "status", "confidence", "size", "confirmed", "suspected",
                                                  "first_seen", "last_seen", "brand", "sector", "harm_en", "harm_ar", "prevention",
                                                  "uncertainty_en", "uncertainty_ar", "genes")} | {"members": members})
    return {"generated_at": now(), "nodes": nodes, "edges": edges, "campaigns": shown_camps,
            "totals": {"findings": len(items), "links": len(intel["edges"]), "campaigns": len(intel["campaigns"]),
                       "shown_nodes": len(nodes), "shown_links": len(edges), "matched": len(sel_all), "unconnected": len(items) - len(linked & {i["id"] for i in items})}}


HOST_OK = __import__("re").compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@router.get("/radar/lookup", dependencies=[require("investigator"), rate_limit("radar_lookup")])
def lookup(q: str = Query(min_length=3, max_length=2048), db=Depends(get_db)):
    """Check one pasted link against everything MERQAB LIVE has stored, plus the rule engine's URL analysis.
    The link is never opened or fetched, and the query is not stored."""
    raw = refang(q.strip())
    urls = extract_urls(raw)
    url = urls[0] if urls else raw
    host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1].split(":", 1)[0].lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not HOST_OK.match(host):
        raise HTTPException(422, "Enter a link or a site name such as example.com")
    if "://" not in url:
        url = f"https://{url}"
    rd = registrable_domain(host)
    intel = radar_intel(db)
    items = intel["items"]
    cof = intel["campaign_of"]
    camps = {c["id"]: c for c in intel["campaigns"]}

    def brief(i):
        cid = cof.get(i["id"], {}).get("campaign_id")
        c = camps.get(cid)
        return {"id": i["id"], "host": i["host"], "status": "confirmed" if i["confirmed"] else "suspected",
                "listed_now": bool(i["confirmed"] and i.get("active", 1)), "sources": i["sources"], "brand": i["brand"],
                "score": i["score"], "risk_level": level_for(i["score"] or 0), "first_seen": i["first_seen"], "last_seen": i["last_seen"],
                "campaign": {"id": c["id"], "name_en": c["name_en"], "name_ar": c["name_ar"], "size": c["size"]} if c else None}

    exact = next((i for i in items if i["host"] in (host, f"www.{host}")), None)
    same_domain = [brief(i) for i in items if i["registrable_domain"] == rd and (not exact or i["id"] != exact["id"])][:10]
    res = analyze("url", url, None, community_index(db))
    uf = (res.get("urls") or [{}])[0]
    brand = (exact or {}).get("brand") or uf.get("impersonated_brand")
    same_brand = sorted([i for i in items if brand and i["brand"] == brand and i["registrable_domain"] != rd],
                        key=lambda i: i["first_seen"], reverse=True)
    return {
        "query_host": host, "registrable_domain": rd,
        "found": brief(exact) if exact else None,
        "same_domain": same_domain,
        "same_brand": {"brand": brand, "count": len(same_brand), "recent": [brief(i) for i in same_brand[:5]]} if brand else None,
        "analysis": {"level": res["risk"]["level"], "score": res["risk"]["score"], "official_domain": bool(uf.get("official_domain")),
                     "impersonated_brand": uf.get("impersonated_brand"), "defanged": uf.get("defanged"),
                     "signals": [{k: x[k] for k in ("key", "en", "ar")} for x in (uf.get("signals") or [])][:5],
                     "reputation": (uf.get("reputation") or {}).get("status")},
        "limits_en": "MERQAB never opens the link. Not being in the radar does not mean a site is safe.",
        "limits_ar": "مرقاب لا يفتح الرابط أبداً. عدم وجود الموقع في الرادار لا يعني أنه آمن.",
    }


@router.get("/radar/campaigns/{campaign_id}", dependencies=[require("investigator")])
def campaign_detail(campaign_id: str, request: Request, db=Depends(get_db)):
    intel = radar_intel(db)
    members, c = _resolve(intel, Target(campaign_id=campaign_id))
    out = dict(c)
    out["items"] = [_public_item(i, None) for i in members]
    user = current_user(request, db)
    if user:  # investigators also see which of their cases contain these domains
        regs = sorted({i["registrable_domain"] for i in members} | {i["host"] for i in members})
        q = ",".join("?" * len(regs))
        out["linked_cases"] = [dict(r) for r in db.execute(
            f"""SELECT DISTINCT c.id, c.ref, c.title FROM indicators x JOIN cases c ON c.id=x.case_id
                WHERE x.type='domain' AND x.value IN ({q})""", regs)]  # nosec B608 - only "?" placeholders
    return out


@router.post("/radar/warn", status_code=201)
def warn(body: Target, user=require("reviewer"), db=Depends(get_db)):
    """Turn a finding or a whole campaign into a community-alert draft (publishing needs a second reviewer)."""
    intel = radar_intel(db)
    candidates, c = _resolve(intel, body)
    # Only validated findings (confirmed by a third-party phishing feed) go into a public warning draft.
    members = [m for m in candidates if m["confirmed"]]
    excluded = [m["host"] for m in candidates if not m["confirmed"]]
    if not members:
        raise HTTPException(409, "No validated findings: these are unverified detections. Open a case to investigate them first.")
    if all(m["status"] == "promoted" for m in members):
        raise HTTPException(409, "Already turned into a warning")
    hosts = [m["host"] for m in members][:10]
    brand = (c or {}).get("brand") or members[0]["brand"]
    lures = sorted({w for m in members for w in m["host"].replace(".", "-").split("-")})
    sector = (c or {}).get("sector") or _sector(brand, lures)
    pattern = {"delivery": "parcel_fee", "jobs": "job_task", "banking": "bank_impersonation"}.get(sector, "account_phishing")
    tactics = {"parcel_fee": ["payment_instruction", "link_prompt", "authority_impersonation"],
               "job_task": ["job_task_scam", "payment_instruction", "link_prompt"],
               "bank_impersonation": ["credential_request", "authority_impersonation", "link_prompt"]}.get(pattern, ["link_prompt", "authority_impersonation"])
    d = build_alert_draft(pattern, tactics, hosts)
    harm_en, harm_ar, _ = HARM[sector]
    who_en = f"'{brand}'" if brand else "trusted services"
    who_ar = f"'{brand}'" if brand else "خدمات موثوقة"
    d["title_en"] = f"Warning: fake {who_en} websites" if c else f"Warning: fake {who_en} website"
    d["title_ar"] = f"تحذير: مواقع مزيّفة تقلّد {who_ar}" if c else f"تحذير: موقع مزيّف يقلّد {who_ar}"
    d["summary_en"] = (f"MERQAB's live radar found {len(members)} related site(s) such as {hosts[0].replace('.', '[.]')}. "
                       f"Risk: {harm_en.lower()}. Do not open these links or enter any details.")
    d["summary_ar"] = (f"رصد رادار مرقاب {len(members)} موقعاً مرتبطاً مثل {hosts[0].replace('.', '[.]')}. "
                       f"الخطر: {harm_ar}. لا تفتح هذه الروابط ولا تُدخل أي بيانات.")
    cur = db.execute("""INSERT INTO alerts (status, pattern_key, title_en, title_ar, summary_en, summary_ar, signs, actions, indicators,
                        created_by, created_at) VALUES ('draft',?,?,?,?,?,?,?,?,?,?)""",
                     (d["pattern_key"], d["title_en"], d["title_ar"], d["summary_en"], d["summary_ar"],
                      json.dumps(d["signs"], ensure_ascii=False), json.dumps(d["actions"], ensure_ascii=False),
                      json.dumps([{"type": "domain", "value": h} for h in hosts]), user["id"], now()))
    for m in members:
        db.execute("UPDATE radar_items SET status='promoted', reviewed_by=?, alert_id=? WHERE id=?", (user["id"], cur.lastrowid, m["id"]))
    db.commit()
    audit.record(db, user["username"], "radar.warn", f"radar/{body.campaign_id or body.item_id}",
                 {"alert": cur.lastrowid, "hosts": hosts, "excluded_unverified": excluded})
    return {"alert_id": cur.lastrowid, "included": hosts, "excluded_unverified": excluded}


@router.post("/radar/investigate", status_code=201)
def investigate(body: InvestigateIn, request: Request, user=require("investigator"), db=Depends(get_db)):
    """Add an immutable radar snapshot (members, sources, evidence, links) to a new or existing case."""
    intel = radar_intel(db)
    members, c = _resolve(intel, body)
    if body.case_id:
        case = db.execute("SELECT id, status FROM cases WHERE id=?", (body.case_id,)).fetchone()
        if not case:
            raise HTTPException(404, "Case not found")
        if case["status"] == "closed":
            raise HTTPException(409, "Case is closed")
        case_id = case["id"]
    else:
        ts = now()
        title = body.title or (f"Radar campaign {c['id']}: {c['name_en']}" if c else f"Radar finding: {members[0]['host']}")
        ref = next_case_ref(db)
        case_id = db.execute("INSERT INTO cases (ref, title, description, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                             (ref, title[:160], "Opened from MERQAB Live Threat Radar.", user["id"], ts, ts)).lastrowid
        db.commit()
        audit.record(db, user["username"], "case.create", f"case/{case_id}", {"ref": ref, "from": "radar"})
    lines = [f"MERQAB Live Threat Radar snapshot — {now()}"]
    if c:
        lines += [f"Campaign {c['id']}: {c['name_en']} ({c['status']}, confidence {c['confidence']})",
                  "Links:"] + [f"- [{l['strength']}] item {l['a']} ↔ {l['b']}: {l['en']}" for l in c["links"]] + [c["uncertainty_en"], ""]
    lines.append("Members:")
    for m in members:
        src = "confirmed by OpenPhish" if m["confirmed"] else "new certificate, unverified"
        lines.append(f"- {m['url'] or 'https://' + m['host']} | {src} | first seen {m['first_seen']} | evidence {json.dumps(m['evidence'])}")
    label = f"Radar {c['id']}" if c else f"Radar item {members[0]['id']}"
    res = _insert_evidence(request, db, user, case_id, "text", label, "\n".join(lines).encode("utf-8"), None, "text/plain", "txt",
                           "Generated by MERQAB radar from public sources (CT logs / OpenPhish)")
    audit.record(db, user["username"], "radar.investigate", f"radar/{body.campaign_id or body.item_id}", {"case": case_id})
    return {"case_id": case_id, "evidence_id": res["id"]}


@router.post("/radar/{item_id}/dismiss")
def dismiss(item_id: int, body: DismissIn, user=require("reviewer"), db=Depends(get_db)):
    if not db.execute("SELECT 1 FROM radar_items WHERE id=?", (item_id,)).fetchone():
        raise HTTPException(404, "Radar item not found")
    db.execute("UPDATE radar_items SET status='dismissed', reviewed_by=?, review_note=? WHERE id=?", (user["id"], body.note, item_id))
    db.commit()
    audit.record(db, user["username"], "radar.dismiss", f"radar/{item_id}", {"note": body.note})
    return {"ok": True}


# ------------------------------------------------------------------ contextual intelligence view
GENE_LABELS = {
    "brand": ("Imitated brand", "العلامة المقلَّدة"),
    "template": ("Naming template", "قالب التسمية"),
    "reg": ("Registered domain", "النطاق المسجَّل"),
    "shared_platform": ("Hosting platform", "منصة الاستضافة"),
    "stem": ("Name stem", "جذر الاسم"),
    "path": ("Phishing-kit path", "مسار أداة التصيّد"),
    "tld": ("Domain ending", "امتداد النطاق"),
    "lure": ("Lure word", "كلمة إغراء"),
    "cert": ("Same TLS certificate", "شهادة TLS واحدة"),
}


def _gene_pairs(g: dict) -> list[tuple[str, str]]:
    out = [(k, str(g[k])) for k in ("brand", "template", "reg", "shared_platform", "stem", "path", "tld", "cert") if g.get(k)]
    return out + [("lure", w) for w in g.get("lures", [])]


@router.get("/radar/intel", dependencies=[require("investigator")])
def intel_view(request: Request, campaign_id: str | None = None, item_id: int | None = None, db=Depends(get_db)):
    """Everything the LIVE intelligence view shows for one campaign (or one finding): a Scam Campaign DNA
    graph whose every edge is either 'site carries trait' or an explained link, the public evidence behind
    each site, scam patterns, harm and prevention, and published community warnings that cover these sites.
    Private case data is added only for signed-in users."""
    from ai.threat_intelligence.campaigns import genes
    intel = radar_intel(db)
    focus = None
    if item_id is not None and not campaign_id:
        cid = intel["campaign_of"].get(item_id, {}).get("campaign_id")
        if cid:
            campaign_id, focus = cid, item_id
    try:
        target = Target(campaign_id=campaign_id, item_id=None if campaign_id else item_id)
    except ValueError:
        raise HTTPException(422, "Give exactly one of item_id or campaign_id")
    members, c = _resolve(intel, target)
    focus = focus if focus is not None else (members[0]["id"] if not c else None)
    gmap = {m["id"]: genes(m) for m in members}
    # traits: in a campaign only those shared by 2+ sites (each edge = 'this site carries this trait');
    # for a single finding, its own traits with how many other stored findings carry them
    counts: dict[tuple, list[int]] = {}
    for mid, g in gmap.items():
        for pair in _gene_pairs(g):
            counts.setdefault(pair, []).append(mid)
    if c:
        traits = {p: ids for p, ids in counts.items() if len(ids) >= 2}
    else:
        traits = dict(counts)
    radar_wide: dict[tuple, int] = {}
    if traits:
        for it in intel["items"]:
            for pair in _gene_pairs(genes(it)):
                if pair in traits:
                    radar_wide[pair] = radar_wide.get(pair, 0) + 1
    gene_nodes = [{"id": f"g{k}", "key": p[0], "value": p[1], "label_en": GENE_LABELS[p[0]][0], "label_ar": GENE_LABELS[p[0]][1],
                   "members": ids, "radar_count": radar_wide.get(p, len(ids))}
                  for k, (p, ids) in enumerate(sorted(traits.items(), key=lambda kv: (-len(kv[1]), kv[0])))][:24]
    sites = []
    for m in members:
        sites.append({"id": m["id"], "host": m["host"], "url": m["url"], "status": "confirmed" if m["confirmed"] else "suspected",
                      "score": m["score"], "risk_level": level_for(m["score"] or 0), "first_seen": m["first_seen"],
                      "last_seen": m["last_seen"], "seen_count": m.get("seen_count", 1), "sources": m["sources"],
                      "evidence": m["evidence"], "active": bool(m.get("active", 1)), "reasons": m["reasons"],
                      "method": m.get("method"), "review_status": m["status"]})
    links = [{"a": l["a"], "b": l["b"], "strength": l["strength"], "reason_en": l["en"], "reason_ar": l["ar"]}
             for l in (c["links"] if c else [])]
    # published (two-reviewer) community warnings whose indicators cover these sites
    hosts = {m["host"] for m in members} | {m["registrable_domain"] for m in members}
    alert_ids = {m.get("alert_id") for m in members if m.get("alert_id")}
    warnings = []
    for a in db.execute("SELECT * FROM alerts WHERE status='published' ORDER BY published_at DESC"):
        inds = json.loads(a["indicators"] or "[]")
        covered = sorted({i["value"] for i in inds if i.get("value") in hosts})
        if covered or a["id"] in alert_ids:
            warnings.append({"id": a["id"], "title_en": a["title_en"], "title_ar": a["title_ar"], "summary_en": a["summary_en"],
                             "summary_ar": a["summary_ar"], "actions": json.loads(a["actions"] or "[]"),
                             "published_at": a["published_at"], "covers": covered})
    brand = (c or {}).get("brand") or members[0]["brand"]
    lures = sorted({w for g in gmap.values() for w in g["lures"]})
    sector = (c or {}).get("sector") or _sector(brand, lures)
    from ai.threat_intelligence.campaigns import SCRIPT
    from ai.threat_intelligence.playbook import tactic_view
    from ai.behavioral_analysis.tactics import TACTICS
    nxt_en, nxt_ar, tkeys = SCRIPT[sector]
    srcs: dict[str, int] = {}
    for m in members:
        for s_ in m["sources"]:
            srcs[s_] = srcs.get(s_, 0) + 1
    order = {"strong": 0, "moderate": 1, "weak": 2}
    strongest = min((l for l in links), key=lambda l: order[l["strength"]], default=None)
    out = {
        "kind": "campaign" if c else "finding", "focus": focus, "sector": sector,
        # what to expect next and which scam steps it uses (links prevention to Family Shield)
        "script": {"next_en": nxt_en, "next_ar": nxt_ar, "tactics": [tactic_view(k) for k in tkeys],
                   "learn_stage": next((TACTICS[k].stage for k in tkeys if TACTICS[k].stage == "extraction"), TACTICS[tkeys[0]].stage)},
        # evidence basis: what is confirmed vs suspected, from which sources, over what time
        "basis": {"confirmed": sum(1 for m in members if m["confirmed"]), "suspected": sum(1 for m in members if not m["confirmed"]),
                  "listed_now": sum(1 for m in members if m["confirmed"] and m.get("active", 1)), "sources": srcs,
                  "first_seen": min(m["first_seen"] for m in members), "last_seen": max(m["last_seen"] for m in members),
                  "strongest": strongest},
        "campaign": {k: c[k] for k in ("id", "name_en", "name_ar", "status", "confidence", "size", "confirmed", "suspected",
                                        "first_seen", "last_seen", "brand", "uncertainty_en", "uncertainty_ar")} if c else None,
        "sites": sites, "genes": gene_nodes, "links": links,
        "harm_en": HARM[sector][0], "harm_ar": HARM[sector][1],
        "prevention": c["prevention"] if c else [{"en": ACTIONS[k]["en"], "ar": ACTIONS[k]["ar"]} for k in HARM[sector][2]],
        "warnings": warnings,
    }
    user = current_user(request, db)
    if user:  # private: which of the user's cases already contain these domains
        regs = sorted(hosts)
        q = ",".join("?" * len(regs))
        out["linked_cases"] = [dict(r) for r in db.execute(
            f"""SELECT DISTINCT c.id, c.ref, c.title FROM indicators x JOIN cases c ON c.id=x.case_id
                WHERE x.type='domain' AND x.value IN ({q})""", regs)]  # nosec B608 - only "?" placeholders
    return out


# ---------------------------------------------------------------------------- reports
REPORT_SITES = 500


def _report_filter(status: Literal["all", "confirmed", "suspected"] = "all", brand: str | None = Query(default=None, max_length=60),
                   connected_only: bool = False, source: SourceKey | None = None,
                   since_hours: int | None = Query(default=None, ge=1, le=24 * 365), min_risk: RiskKey | None = None,
                   listed_now: bool = False, warned: bool = False, in_campaign: bool = False) -> RadarFilter:
    return RadarFilter(status=status, brand=brand, connected_only=connected_only, source=source, since_hours=since_hours,
                       min_risk=min_risk, listed_now=listed_now, warned=warned, in_campaign=in_campaign)


def _defang_host(h: str) -> str:
    return h.replace(".", "[.]")



# --- report analysis helpers: every value is computed from stored findings ---------------------------
FREE_PLATFORMS = ["pages.dev", "netlify.app", "vercel.app", "workers.dev", "github.io", "web.app", "firebaseapp.com",
                  "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "blogspot.com", "glitch.me", "framer.app",
                  "framer.website", "bolt.host", "square.site", "godaddysites.com", "webflow.io", "herokuapp.com", "repl.co",
                  "replit.app", "gitbook.io", "ipfs.io", "r2.dev", "netlify.com", "surge.sh", "onrender.com", "fly.dev",
                  "azurewebsites.net", "appspot.com", "mystrikingly.com", "jimdosite.com", "carrd.co", "tilda.ws", "wordpress.com"]
LURE_WORDS = ["login", "signin", "verify", "verification", "secure", "security", "account", "update", "support", "help",
              "wallet", "auth", "confirm", "recovery", "recover", "billing", "pay", "payment", "refund", "bank", "service",
              "customer", "reward", "gift", "claim", "unlock", "bonus", "prize", "delivery", "track", "invoice", "kyc"]


def _platform(host: str) -> str | None:
    return next((p for p in FREE_PLATFORMS if host == p or host.endswith("." + p)), None)


def _tld(i: dict) -> str:
    rd = i.get("registrable_domain") or i["host"]
    parts = rd.split(".")
    return "." + ".".join(parts[1:]) if len(parts) > 1 else "." + rd


def _words(host: str) -> set[str]:
    import re as _re
    toks = set(_re.split(r"[.\-_0-9]+", host.lower()))
    return {w for w in LURE_WORDS if w in toks}   # whole words only, so "pay" is not counted inside "paypal"


def _iso(s: str):
    from datetime import datetime
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _pct(cur: int, prev: int):
    return None if not prev else round((cur - prev) / prev * 100)


def _median(xs: list[float]):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2


def _analysis(intel: dict, db, f: RadarFilter, sel: list[dict]) -> dict:
    from collections import Counter
    from datetime import datetime, timedelta, timezone
    nowdt = datetime.now(timezone.utc)
    cof = intel["campaign_of"]
    camps = {c["id"]: c for c in intel["campaigns"]}
    n = len(sel) or 1

    # 1. comparison with the previous period of the same length (same filters, shifted window)
    comparison = None
    if f.since_hours:
        start, pstart = nowdt - timedelta(hours=f.since_hours), nowdt - timedelta(hours=2 * f.since_hours)
        prev = [i for i in _select(intel, db, f.model_copy(update={"since_hours": None})) if pstart <= _iso(i["first_seen"]) < start]
        cb, pb = Counter(i["brand"] for i in sel if i["brand"]), Counter(i["brand"] for i in prev if i["brand"])
        comparison = {
            "previous": {"sites": len(prev), "confirmed": sum(1 for i in prev if i["confirmed"]), "suspected": sum(1 for i in prev if not i["confirmed"])},
            "change_pct": {"sites": _pct(len(sel), len(prev)), "confirmed": _pct(sum(1 for i in sel if i["confirmed"]), sum(1 for i in prev if i["confirmed"]))},
            "by_brand": [{"brand": b, "now": cb[b], "before": pb[b], "change_pct": _pct(cb[b], pb[b])}
                         for b in sorted(set(cb) | set(pb), key=lambda b: -(cb[b] + pb[b]))[:8]],
            "window": {"from": start.isoformat(timespec="seconds"), "prev_from": pstart.isoformat(timespec="seconds")},
        }

    # 2. attacker infrastructure
    plat = Counter(p for p in (_platform(i["host"]) for i in sel) if p)
    tlds = Counter(_tld(i) for i in sel if not _platform(i["host"]))
    words = Counter(w for i in sel for w in _words(i["host"]))
    on_platform = sum(plat.values())
    infrastructure = {"tlds": [{"label": k, "count": v} for k, v in tlds.most_common(8)],
                      "platforms": [{"label": k, "count": v} for k, v in plat.most_common(8)],
                      "platform_share_pct": round(on_platform / n * 100) if sel else 0,
                      "words": [{"label": k, "count": v} for k, v in words.most_common(10)]}

    # 3. fastest-growing campaigns: members first seen in this period vs members already known before it
    cutoff = nowdt - timedelta(hours=f.since_hours or 24 * 7)
    in_sel = Counter(cof[i["id"]]["campaign_id"] for i in sel if i["id"] in cof)
    items_by_id = {i["id"]: i for i in intel["items"]}
    growth = []
    for cid, k in in_sel.items():
        c = camps.get(cid)
        if not c:
            continue
        new = sum(1 for m in c["members"] if m in items_by_id and _iso(items_by_id[m]["first_seen"]) >= cutoff)
        growth.append({"id": cid, "name_en": c["name_en"], "name_ar": c["name_ar"], "status": c["status"], "brand": c["brand"],
                       "new": new, "before": c["size"] - new, "size": c["size"]})
    growth = sorted([g for g in growth if g["new"]], key=lambda g: (-g["new"], -g["size"]))[:6]

    # 4. how long confirmed sites stay listed (first to last sighting on a feed) — a lower bound
    gone = [(_iso(i["last_seen"]) - _iso(i["first_seen"])).total_seconds() / 86400 for i in sel if i["confirmed"] and not i.get("active", 1)]
    live = [(nowdt - _iso(i["first_seen"])).total_seconds() / 86400 for i in sel if i["confirmed"] and i.get("active", 1)]
    q90 = sorted(gone)[max(0, int(len(gone) * 0.9) - 1)] if gone else None
    lifetime = {"delisted": len(gone), "median_days": _median(gone), "p90_days": q90, "still_listed": len(live), "median_age_days": _median(live)}

    # 5. priority actions per brand, ranked by volume, growth and what is live right now
    pri = []
    for b, cnt in Counter(i["brand"] for i in sel if i["brand"]).most_common(10):
        mine = [i for i in sel if i["brand"] == b]
        bp, bt = Counter(p for p in (_platform(i["host"]) for i in mine) if p), Counter(_tld(i) for i in mine if not _platform(i["host"]))
        listed = sum(1 for i in mine if i["confirmed"] and i.get("active", 1))
        susp = sum(1 for i in mine if not i["confirmed"])
        ch = next((x["change_pct"] for x in (comparison or {}).get("by_brand", []) if x["brand"] == b), None)
        top_p, top_t = (bp.most_common(1) or [(None, 0)])[0], (bt.most_common(1) or [(None, 0)])[0]
        actions = []
        if listed:
            actions.append({"key": "takedown", "n": listed})
        if top_p[0] and top_p[1] / cnt >= 0.3:
            actions.append({"key": "platform", "platform": top_p[0], "n": top_p[1], "pct": round(top_p[1] / cnt * 100)})
        if top_t[0] and top_t[1] / cnt >= 0.3 and top_t[1] >= 2:
            actions.append({"key": "tld", "tld": top_t[0], "pct": round(top_t[1] / cnt * 100)})
        if susp:
            actions.append({"key": "suspected", "n": susp})
        actions.append({"key": "warn"})
        score = cnt * (1 + max(ch or 0, 0) / 100) + listed
        pri.append({"brand": b, "count": cnt, "listed_now": listed, "suspected": susp, "change_pct": ch,
                    "rising": ch is not None and ch >= 25, "actions": actions, "score": round(score, 1)})
    pri = sorted(pri, key=lambda x: -x["score"])[:5]
    return {"comparison": comparison, "infrastructure": infrastructure, "growth": growth, "lifetime": lifetime, "priorities": pri}


def _by_hour(sel: list[dict]) -> list[dict]:
    """Hourly buckets when the detections span 3 days or less (a daily chart would be a single bar)."""
    if not sel or (_iso(sel[0]["first_seen"]) - _iso(sel[-1]["first_seen"])).total_seconds() > 72 * 3600:
        return []
    out: dict[str, dict] = {}
    for i in sel:
        k = i["first_seen"][:13]
        d = out.setdefault(k, {"hour": k + ":00:00+00:00", "confirmed": 0, "suspected": 0})
        d["confirmed" if i["confirmed"] else "suspected"] += 1
    return [out[k] for k in sorted(out)]


@router.get("/radar/report", dependencies=[require("investigator"), rate_limit("radar_report", 0.5)])
def report(f: RadarFilter = Depends(_report_filter), db=Depends(get_db)):
    """Intelligence report for a filter. Every number is counted from stored findings; nothing is estimated."""
    from collections import Counter
    intel = radar_intel(db)
    sel = sorted(_select(intel, db, f), key=lambda i: i["first_seen"], reverse=True)
    cof = intel["campaign_of"]
    camps = {c["id"]: c for c in intel["campaigns"]}
    day = lambda iso: iso[:10]
    by_day: dict[str, dict] = {}
    for i in sel:
        d = by_day.setdefault(day(i["first_seen"]), {"day": day(i["first_seen"]), "confirmed": 0, "suspected": 0})
        d["confirmed" if i["confirmed"] else "suspected"] += 1
    src = Counter(s for i in sel for s in i["sources"])
    brands = Counter(i["brand"] for i in sel if i["brand"])
    brand_conf = Counter(i["brand"] for i in sel if i["brand"] and i["confirmed"])
    risk = Counter(level_for(i["score"] or 0) for i in sel)
    in_camp = Counter(cof[i["id"]]["campaign_id"] for i in sel if i["id"] in cof)
    top_c = []
    for cid, n in in_camp.most_common(8):
        c = camps.get(cid)
        if not c:
            continue
        top_c.append({k: c[k] for k in ("id", "name_en", "name_ar", "status", "confidence", "size", "brand", "sector",
                                         "first_seen", "last_seen", "harm_en", "harm_ar", "prevention", "uncertainty_en", "uncertainty_ar")}
                     | {"in_report": n, "links": [{"en": l["en"], "ar": l["ar"], "strength": l["strength"]} for l in c.get("links", [])[:2]]})
    sites = [{"id": i["id"], "host": _defang_host(i["host"]), "status": "confirmed" if i["confirmed"] else "suspected",
              "listed_now": bool(i["confirmed"] and i.get("active", 1)), "brand": i["brand"], "sources": i["sources"],
              "risk_level": level_for(i["score"] or 0), "score": i["score"], "first_seen": i["first_seen"], "last_seen": i["last_seen"],
              "campaign_id": cof.get(i["id"], {}).get("campaign_id")} for i in sel[:REPORT_SITES]]
    return {
        "generated_at": now(), "filters": f.model_dump(exclude_defaults=True),
        "period": {"from": sel[-1]["first_seen"] if sel else None, "to": sel[0]["first_seen"] if sel else None},
        "totals": {"sites": len(sel), "confirmed": sum(1 for i in sel if i["confirmed"]),
                   "listed_now": sum(1 for i in sel if i["confirmed"] and i.get("active", 1)),
                   "suspected": sum(1 for i in sel if not i["confirmed"]), "campaigns": len(in_camp), "brands": len(brands),
                   "stored_total": len(intel["items"])},
        "by_day": [by_day[k] for k in sorted(by_day)][-60:],
        "by_hour": _by_hour(sel),
        "by_source": [{"source": k, "count": v} for k, v in src.most_common()],
        "by_brand": [{"brand": b, "count": n, "confirmed": brand_conf[b]} for b, n in brands.most_common(10)],
        "by_risk": {lvl: risk.get(lvl, 0) for lvl in ("critical", "high", "medium", "low")},
        "top_campaigns": top_c,
        "sites": sites, "sites_shown": len(sites),
        "analysis": _analysis(intel, db, f, sel),
        "limits_en": ["Counts cover findings stored by this MERQAB installation, filtered as shown; they are not a census of all phishing.",
                      "Public lists are scanned in full but only sites imitating monitored brands are stored; Certificate Transparency is sampled.",
                      "Suspected sites were detected by MERQAB's rules and are not confirmed by any list.",
                      "Links are written in defanged form (example[.]com) and were never opened by MERQAB.",
                      "Period comparisons use the time MERQAB first saw each site; adding a new source can make a period look higher.",
                      "Listing durations run from the first to the last time a feed listed a site while MERQAB was running, so they are lower bounds."],
        "limits_ar": ["الأرقام تشمل ما خزّنه مرقاب في هذا التثبيت وفق الفلاتر المعروضة، وليست حصراً لكل مواقع التصيّد.",
                      "تُفحص القوائم العامة كاملة لكن لا يُخزَّن إلا ما ينتحل العلامات المراقبة؛ وسجلات الشهادات تُفحص بالعيّنات.",
                      "المواقع المشتبه بها رصدتها قواعد مرقاب ولم تؤكدها أي قائمة.",
                      "الروابط مكتوبة بصيغة آمنة (example[.]com) ولم يفتحها مرقاب أبداً.",
                      "المقارنة بين الفترات تعتمد على وقت أول رصد لمرقاب لكل موقع؛ وإضافة مصدر جديد قد تُظهر فترة أعلى من حقيقتها.",
                      "مدة بقاء المواقع تُحسب من أول ظهور إلى آخر ظهور في القوائم أثناء عمل مرقاب، فهي حدّ أدنى وليست أوقات إغلاق دقيقة."],
    }


@router.get("/radar/report.csv", dependencies=[require("investigator"), rate_limit("radar_report", 0.5)])
def report_csv(f: RadarFilter = Depends(_report_filter), db=Depends(get_db)):
    import csv
    import io
    from fastapi.responses import Response
    intel = radar_intel(db)
    cof = intel["campaign_of"]
    sel = sorted(_select(intel, db, f), key=lambda i: i["first_seen"], reverse=True)[:20000]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host_defanged", "status", "listed_now", "imitated_brand", "sources", "risk_level", "score", "first_seen", "last_seen", "campaign_id"])
    for i in sel:
        # neutralise spreadsheet formulas in any text cell
        host = _defang_host(i["host"])
        w.writerow([("'" + host) if host[:1] in "=+-@" else host, "confirmed" if i["confirmed"] else "suspected",
                    "yes" if (i["confirmed"] and i.get("active", 1)) else "no", i["brand"] or "", ";".join(i["sources"]),
                    level_for(i["score"] or 0), i["score"] or 0, i["first_seen"], i["last_seen"], cof.get(i["id"], {}).get("campaign_id") or ""])
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="mirqab-radar-report.csv"', "Cache-Control": "no-store"})
