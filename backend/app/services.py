"""Orchestration between the API, the database and the AI layer."""
from __future__ import annotations

import json

from backend.app.radar import FEED_SOURCES
import re
import sqlite3
import threading
import time

from ai.behavioral_analysis.conversation import _LINE_PATTERNS
from ai.investigation.correlation import build_timeline, correlate
from ai.investigation.findings import generate_findings
from ai.investigation.indicators import STRONG_TYPES, extract_indicators
from ai.llm.provider import LLMProvider
from ai.pipeline import CommunityIndex, analyze
from ai.behavioral_analysis.url_analyzer import brand_data
from ai.threat_intelligence.campaigns import analyze_relationships, campaign_of, template_index
from backend.app.db import now


def looks_like_conversation(text: str) -> bool:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    structured = sum(1 for l in lines if any(p.match(l) for p in _LINE_PATTERNS[:3]))
    return structured >= 2


def community_index(db: sqlite3.Connection) -> CommunityIndex:
    idx = CommunityIndex()
    for r in db.execute("SELECT id, pattern_key, title_en, title_ar, indicators FROM alerts WHERE status='published'"):
        idx.titles[r["id"]] = {"title_en": r["title_en"], "title_ar": r["title_ar"]}
        for ind in json.loads(r["indicators"] or "[]"):
            if ind.get("type") == "domain" and ind.get("value"):
                idx.domains.setdefault(ind["value"].lower(), r["id"])
        if r["pattern_key"]:
            idx.patterns.setdefault(r["pattern_key"], []).append(r["id"])
    intel = radar_intel(db)
    for r in intel["items"]:
        item = {"radar_id": r["id"], "host": r["host"], "brand": r["brand"], "first_seen": r["first_seen"],
                "sources": r["sources"], "confirmed": r["confirmed"], "active": bool(r.get("active", 1)),
                "campaign": intel["campaign_of"].get(r["id"])}
        idx.radar_hosts[r["host"]] = item
        if r["method"] != "confirmed_feed":
            idx.radar_domains.setdefault(r["registrable_domain"], item)
    idx.campaign_templates = intel["templates"]
    return idx


# ---------------------------------------------------------------------------- radar intelligence (cached)
_intel_cache: dict = {"key": None, "value": None, "at": 0.0}
_intel_lock = threading.Lock()
_intel_compute = threading.Lock()   # one rebuild at a time; concurrent requests wait and reuse it
SOFT_REUSE_SECONDS = 15


def radar_intel(db: sqlite3.Connection) -> dict:
    """Radar findings + Scam Campaign DNA, recomputed only when findings change.

    Structural changes (new, dismissed, promoted or re-branded findings) rebuild at once. Re-sightings and
    listing-status changes, which the live sources produce every few seconds, rebuild at most every 15 s."""
    row = db.execute("""SELECT COUNT(*), MAX(id), SUM(status='dismissed'), SUM(status='promoted'), SUM(brand IS NOT NULL),
                               MAX(last_seen), SUM(active) FROM radar_items""").fetchone()
    hard = tuple(row[:5]) + (str(db.execute("PRAGMA database_list").fetchone()[2]),)
    key = (hard, tuple(row[5:]))

    def cached():
        c = _intel_cache
        if c["key"] == key or (c["key"] and c["key"][0] == hard and time.monotonic() - c["at"] < SOFT_REUSE_SECONDS):
            return c["value"]
        return None

    with _intel_lock:
        v = cached()
    if v is not None:
        return v
    with _intel_compute:
        with _intel_lock:
            v = cached()
        if v is not None:
            return v
        value = _build_intel(db)
        with _intel_lock:
            _intel_cache.update(key=key, value=value, at=time.monotonic())
        return value


def _build_intel(db: sqlite3.Connection) -> dict:
    rows = []
    for r in db.execute("SELECT * FROM radar_items WHERE status != 'dismissed'"):
        d = dict(r)
        d["sources"] = d["sources"].split(",")
        d["confirmed"] = bool(set(d["sources"]) & FEED_SOURCES)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        rows.append(d)
    campaigns, edges = analyze_relationships(rows)
    value = {"items": rows, "campaigns": campaigns, "edges": edges, "campaign_of": campaign_of(campaigns),
             "templates": template_index(campaigns, {r["id"]: r for r in rows})}
    return value


def analysis_kind_for(evidence_kind: str, text: str) -> str:
    if evidence_kind == "url":
        return "url"
    if evidence_kind == "conversation" or looks_like_conversation(text):
        return "conversation"
    return "text"


def analyze_case(db: sqlite3.Connection, case_id: int, llm: LLMProvider) -> dict:
    evs = db.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
    cidx = community_index(db)
    prepared = []
    for ev in evs:
        text = ev["extracted_text"] or ""
        meta = json.loads(ev["metadata"] or "{}")
        result = analyze(analysis_kind_for(ev["kind"], text), text, llm, cidx) if text.strip() else None
        inds = extract_indicators(text) if text.strip() else []
        db.execute("UPDATE evidence SET analysis=? WHERE id=?", (json.dumps(result, ensure_ascii=False) if result else None, ev["id"]))
        db.execute("DELETE FROM indicators WHERE evidence_id=?", (ev["id"],))
        db.executemany("INSERT INTO indicators (case_id, evidence_id, type, value, display) VALUES (?,?,?,?,?)",
                       [(case_id, ev["id"], i["type"], i["value"], i["display"]) for i in inds])
        label = f"E{ev['id']} · {ev['label']}"
        prepared.append({
            "id": ev["id"], "label": label, "submitted_at": ev["submitted_at"], "metadata": meta,
            "analysis": result, "indicators": inds,
            "tactics": sorted({i["key"] for i in (result or {}).get("indicators", [])}),
            "messages": ((result or {}).get("conversation") or {}).get("messages", []),
            "header_signals": meta.get("header_signals", []),
        })
    corr = correlate(prepared)
    tl = build_timeline(prepared)

    # Cross-incident correlation: same strong indicator in *other* cases (investigators only)
    cross = []
    for ev in prepared:
        for i in ev["indicators"]:
            if i["type"] not in STRONG_TYPES or i["type"] == "url":
                continue
            for r in db.execute("""SELECT DISTINCT c.ref, c.id FROM indicators x JOIN cases c ON c.id = x.case_id
                                   WHERE x.type=? AND x.value=? AND x.case_id != ?""", (i["type"], i["value"], case_id)):
                item = {"indicator_type": i["type"], "display": i["display"], "case_ref": r["ref"], "case_id": r["id"],
                        "evidence_id": ev["id"]}
                if item not in cross:
                    cross.append(item)

    # Live radar & campaign links: same domain seen in public threat sources
    intel = radar_intel(db)
    by_host = {i["host"]: i for i in intel["items"]}
    by_reg: dict[str, list] = {}
    for i in intel["items"]:
        by_reg.setdefault(i["registrable_domain"], []).append(i)
    shared = set(brand_data().get("shared_hosting", []))
    radar_links = []
    for ev in prepared:
        for u in (ev["analysis"] or {}).get("urls", []):
            hits = [by_host[u["host"]]] if u["host"] in by_host else ([] if u["registrable_domain"] in shared else by_reg.get(u["registrable_domain"], []))
            for it in hits[:3]:
                camp = intel["campaign_of"].get(it["id"])
                link = {"evidence_id": ev["id"], "host": it["host"], "radar_id": it["id"], "confirmed": it["confirmed"],
                        "first_seen": it["first_seen"], "campaign": camp}
                if all(not (x["evidence_id"] == ev["id"] and x["host"] == it["host"]) for x in radar_links):
                    radar_links.append(link)

    findings = generate_findings(prepared, corr, tl)
    for rl in radar_links:
        src_en = "listed by the OpenPhish feed" if rl["confirmed"] else "seen on a new certificate (unverified)"
        src_ar = "مُدرج في قائمة OpenPhish" if rl["confirmed"] else "ظهر في شهادة جديدة (غير مؤكد)"
        c = rl["campaign"]
        findings.append({"fingerprint": f"radar:{rl['evidence_id']}:{rl['host']}", "category": "observed", "source": "rule",
                         "evidence_ids": [rl["evidence_id"]],
                         "statement_en": f"E{rl['evidence_id']}: {rl['host']} was detected by MIRGAB's live radar on {rl['first_seen'][:16]} — {src_en}.",
                         "statement_ar": f"E{rl['evidence_id']}: رصد رادار مرقاب {rl['host']} في {rl['first_seen'][:16]} — {src_ar}."})
        if c:
            findings.append({"fingerprint": f"campaign:{rl['evidence_id']}:{c['campaign_id']}", "category": "inference", "source": "heuristic",
                             "evidence_ids": [rl["evidence_id"]],
                             "statement_en": f"E{rl['evidence_id']} links to suspected campaign {c['campaign_id']} ({c['name_en']}, {c['size']} related sites). Shared traits do not prove a common operator.",
                             "statement_ar": f"E{rl['evidence_id']} مرتبط بحملة مشتبه بها {c['campaign_id']} ({c['name_ar']}، {c['size']} مواقع مرتبطة). السمات المشتركة لا تثبت وجود جهة واحدة."})
    for x in {(c["indicator_type"], c["display"], c["case_ref"]) for c in cross}:
        findings.append({"fingerprint": f"cross:{x[0]}:{x[1]}:{x[2]}", "category": "observed", "source": "rule",
                         "evidence_ids": [c["evidence_id"] for c in cross if c["case_ref"] == x[2] and c["display"] == x[1]],
                         "statement_en": f"The {x[0].replace('_', ' ')} {x[1]} also appears in case {x[2]}. This links the incidents; it does not identify a person.",
                         "statement_ar": f"يظهر {x[1]} أيضاً في القضية {x[2]}. هذا يربط الحوادث ولا يحدد هوية شخص."})
    new_fps = {f["fingerprint"] for f in findings}
    ts = now()
    for f in findings:
        db.execute("""INSERT INTO findings (case_id, fingerprint, category, source, evidence_ids, statement_en, statement_ar, created_at)
                      VALUES (?,?,?,?,?,?,?,?)
                      ON CONFLICT(case_id, fingerprint) DO UPDATE SET statement_en=excluded.statement_en,
                      statement_ar=excluded.statement_ar, evidence_ids=excluded.evidence_ids, stale=0""",
                   (case_id, f["fingerprint"], f["category"], f["source"], json.dumps(f["evidence_ids"]),
                    f["statement_en"], f["statement_ar"], ts))
    # findings no longer produced: delete if never reviewed, otherwise keep but mark stale
    for r in db.execute("SELECT id, fingerprint, status, category FROM findings WHERE case_id=?", (case_id,)).fetchall():
        if r["fingerprint"] not in new_fps and r["category"] != "investigator_note":
            if r["status"] == "unreviewed":
                db.execute("DELETE FROM findings WHERE id=?", (r["id"],))
            else:
                db.execute("UPDATE findings SET stale=1 WHERE id=?", (r["id"],))

    levels = [p["analysis"]["risk"]["level"] for p in prepared if p["analysis"]]
    order = ["low", "medium", "high", "critical"]
    patterns = []
    for p in prepared:
        for pt in (p["analysis"] or {}).get("patterns", [])[:1]:
            if pt["key"] not in [x["key"] for x in patterns]:
                patterns.append({"key": pt["key"], "name_en": pt["name_en"], "name_ar": pt["name_ar"]})
    summary = {
        "analyzed_at": ts, "evidence_count": len(prepared),
        "highest_risk": max(levels, key=order.index) if levels else None,
        "patterns": patterns,
        "tactics": sorted({t for p in prepared for t in p["tactics"]}),
        "unprocessed_evidence": [p["id"] for p in prepared if not p["analysis"]],
        "engine": (next((p["analysis"]["engine"] for p in prepared if p["analysis"]), None)),
    }
    payload = {"summary": summary, "correlation": corr, "timeline": tl, "cross_case": cross, "radar_links": radar_links}
    db.execute("UPDATE cases SET last_analysis=?, updated_at=? WHERE id=?", (json.dumps(payload, ensure_ascii=False), ts, case_id))
    db.commit()
    return payload


_REF_RE = re.compile(r"^MRQ-\d{4}-\d{4}$")


def next_case_ref(db: sqlite3.Connection) -> str:
    year = now()[:4]
    n = db.execute("SELECT COUNT(*) FROM cases WHERE ref LIKE ?", (f"MRQ-{year}-%",)).fetchone()[0] + 1
    return f"MRQ-{year}-{n:04d}"
