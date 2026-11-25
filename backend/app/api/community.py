"""Community protection: validated alerts, public reports, review workflow and impact metrics.

Lifecycle:  draft → pending_review → published | rejected → archived
* Drafts can only be created from a case with at least one investigator-verified finding.
* A reviewer different from the author must approve, complete the checklist, and pass the PII gate.
* Only *published* alerts are visible publicly and only they feed the prevention engine.
* Public reports are stored anonymised as 'unverified' and never published automatically.
"""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ai.pipeline import analyze
from ai.threat_intelligence.community import anonymize, build_alert_draft, residual_pii
from backend.app import audit
from backend.app.db import now, row, rows
from backend.app.security import ROLES, get_db, rate_limit, require

router = APIRouter(prefix="/api", tags=["community"])
_JSON = ("signs", "actions", "indicators")
AUDIENCES = ("everyone", "seniors", "students", "families", "businesses")


class Bilingual(BaseModel):
    en: str = Field(min_length=2, max_length=300)
    ar: str = Field(min_length=2, max_length=300)


class AlertPatch(BaseModel):
    title_en: str | None = Field(default=None, min_length=5, max_length=160)
    title_ar: str | None = Field(default=None, min_length=5, max_length=160)
    summary_en: str | None = Field(default=None, min_length=10, max_length=800)
    summary_ar: str | None = Field(default=None, min_length=10, max_length=800)
    actions: list[Bilingual] | None = Field(default=None, max_length=8)
    indicators: list[dict] | None = Field(default=None, max_length=20)
    audience: Literal["everyone", "seniors", "students", "families", "businesses"] | None = None


class Checklist(BaseModel):
    pii_removed: bool
    evidence_supported: bool
    guidance_accurate: bool


class ApproveIn(BaseModel):
    checklist: Checklist
    note: str | None = Field(default=None, max_length=1000)


class RejectIn(BaseModel):
    note: str = Field(min_length=3, max_length=1000)


class ReportIn(BaseModel):
    text: str = Field(min_length=10, max_length=5000)


class ReportTriage(BaseModel):
    status: Literal["linked", "dismissed"]
    alert_id: int | None = None


class AlertFeedback(BaseModel):
    helpful: bool


def _alert(db, alert_id: int) -> dict:
    a = row(db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone(), _JSON)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


def _public(a: dict) -> dict:
    keep = ("id", "pattern_key", "title_en", "title_ar", "summary_en", "summary_ar", "signs", "actions", "indicators",
            "audience", "published_at", "helpful", "not_helpful")
    return {k: a[k] for k in keep}


# ------------------------------------------------------------------ public
@router.get("/community/alerts")
def published_alerts(audience: str | None = None, db=Depends(get_db)):
    q = "SELECT * FROM alerts WHERE status='published'"
    args: tuple = ()
    if audience in AUDIENCES and audience != "everyone":
        q += " AND audience IN ('everyone', ?)"
        args = (audience,)
    return [_public(a) for a in rows(db.execute(q + " ORDER BY published_at DESC", args), _JSON)]


@router.post("/community/alerts/{alert_id}/feedback", dependencies=[rate_limit("alert_feedback")])
def alert_feedback(alert_id: int, body: AlertFeedback, db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] != "published":
        raise HTTPException(404, "Alert not found")
    col = "helpful" if body.helpful else "not_helpful"
    db.execute(f"UPDATE alerts SET {col} = {col} + 1 WHERE id=?", (alert_id,))  # nosec B608 - col is one of two literals
    db.commit()
    return {"ok": True}


@router.post("/community/reports", status_code=201, dependencies=[rate_limit("community_report", 0.3)])
def submit_report(body: ReportIn, request: Request, db=Depends(get_db)):
    anon = anonymize(body.text)
    res = analyze("text", body.text, None)  # rules only; nothing about the reporter is stored
    cur = db.execute("INSERT INTO community_reports (created_at, text_anonymized, risk_level, pattern) VALUES (?,?,?,?)",
                     (now(), anon, res["risk"]["level"], res["patterns"][0]["key"] if res["patterns"] else None))
    db.commit()
    return {"id": cur.lastrowid, "stored_text": anon, "status": "unverified",
            "message_en": "Thank you. Your report was stored without personal details and will be reviewed before any public use.",
            "message_ar": "شكراً لك. تم حفظ بلاغك دون بيانات شخصية وستتم مراجعته قبل أي استخدام عام."}


@router.get("/community/impact")
def impact(db=Depends(get_db)):
    """Real counts from this deployment's database — nothing is estimated or seeded."""
    q = lambda sql, *a: db.execute(sql, a).fetchone()[0]
    by_level = {r["risk_level"]: r["n"] for r in db.execute("SELECT risk_level, COUNT(*) n FROM analyses GROUP BY risk_level")}
    fb = {r["feedback"]: r["n"] for r in db.execute("SELECT feedback, COUNT(*) n FROM analyses WHERE feedback IS NOT NULL GROUP BY feedback")}
    return {
        "analyses_total": q("SELECT COUNT(*) FROM analyses"),
        "analyses_by_level": by_level,
        "high_risk_interventions": by_level.get("high", 0) + by_level.get("critical", 0),
        "community_warning_matches": q("SELECT COUNT(*) FROM analyses WHERE community_match=1"),
        "alerts_published": q("SELECT COUNT(*) FROM alerts WHERE status='published'"),
        "alert_views_in_results": q("SELECT COALESCE(SUM(shown),0) FROM alerts WHERE status='published'"),
        "alert_feedback": {"helpful": q("SELECT COALESCE(SUM(helpful),0) FROM alerts"),
                           "not_helpful": q("SELECT COALESCE(SUM(not_helpful),0) FROM alerts")},
        "analysis_feedback": {"helpful": fb.get("helpful", 0), "incorrect": fb.get("incorrect", 0)},
        "community_reports": q("SELECT COUNT(*) FROM community_reports"),
        "note_en": "Counts come from this installation only. 'Incorrect' feedback is tracked to measure false positives.",
        "note_ar": "الأرقام من هذا التثبيت فقط. يتم تتبع تقييمات 'غير صحيح' لقياس الإنذارات الخاطئة.",
    }


# ------------------------------------------------------------------ investigator: draft from case
@router.post("/cases/{case_id}/alert-draft", status_code=201)
def draft_from_case(case_id: int, user=require("investigator"), db=Depends(get_db)):
    c = row(db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(), ("last_analysis",))
    if not c:
        raise HTTPException(404, "Case not found")
    verified = db.execute("SELECT COUNT(*) FROM findings WHERE case_id=? AND status='verified' AND category!='investigator_note'",
                          (case_id,)).fetchone()[0]
    if not c.get("last_analysis") or verified == 0:
        raise HTTPException(409, "Analyse the case and verify at least one finding before proposing a community alert.")
    summ = c["last_analysis"]["summary"]
    domains = []
    for ev in db.execute("SELECT analysis FROM evidence WHERE case_id=? AND analysis IS NOT NULL", (case_id,)):
        for u in json.loads(ev["analysis"]).get("urls", []):
            if u["score"] >= 45 and not u["official_domain"] and u["registrable_domain"] not in domains:
                domains.append(u["registrable_domain"])
    pattern = summ["patterns"][0]["key"] if summ.get("patterns") else None
    d = build_alert_draft(pattern, summ.get("tactics", []), domains)
    cur = db.execute("""INSERT INTO alerts (status, pattern_key, title_en, title_ar, summary_en, summary_ar, signs, actions, indicators,
                        source_case_id, created_by, created_at) VALUES ('draft',?,?,?,?,?,?,?,?,?,?,?)""",
                     (d["pattern_key"], d["title_en"], d["title_ar"], d["summary_en"], d["summary_ar"],
                      json.dumps(d["signs"], ensure_ascii=False), json.dumps(d["actions"], ensure_ascii=False),
                      json.dumps(d["indicators"]), case_id, user["id"], now()))
    db.commit()
    audit.record(db, user["username"], "alert.draft", f"alert/{cur.lastrowid}", {"case": c["ref"]})
    return {"id": cur.lastrowid}


@router.get("/community/review")
def review_queue(user=require("investigator"), db=Depends(get_db)):
    alerts = rows(db.execute("""SELECT a.*, u.username AS author, r.username AS reviewer, c.ref AS case_ref FROM alerts a
                                JOIN users u ON u.id=a.created_by LEFT JOIN users r ON r.id=a.reviewed_by
                                LEFT JOIN cases c ON c.id=a.source_case_id
                                WHERE a.status IN ('draft','pending_review','rejected','published') ORDER BY a.id DESC"""), _JSON)
    for a in alerts:
        a["pii_check"] = residual_pii(" ".join([a["title_en"], a["summary_en"], a["summary_ar"],
                                                *[x["en"] + " " + x["ar"] for x in a["actions"]]]))
    reports_ = rows(db.execute("SELECT * FROM community_reports ORDER BY id DESC LIMIT 100")) if ROLES[user["role"]] >= ROLES["reviewer"] else []
    return {"alerts": alerts, "reports": reports_}


@router.patch("/community/alerts/{alert_id}")
def edit_alert(alert_id: int, body: AlertPatch, user=require("investigator"), db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] not in ("draft", "pending_review"):
        raise HTTPException(409, "Only drafts or alerts under review can be edited.")
    if a["created_by"] != user["id"] and ROLES[user["role"]] < ROLES["reviewer"]:
        raise HTTPException(403, "Only the author or a reviewer can edit this alert.")
    fields = body.model_dump(exclude_none=True)
    if "indicators" in fields:
        fields["indicators"] = [{"type": "domain", "value": str(i.get("value", "")).lower()[:120]}
                                for i in fields["indicators"] if i.get("type") == "domain" and i.get("value")]
    for k in ("actions", "indicators"):
        if k in fields:
            fields[k] = json.dumps(fields[k], ensure_ascii=False)
    if not fields:
        raise HTTPException(422, "Nothing to update")
    if not set(fields) <= set(AlertPatch.model_fields):   # column names only ever come from the model
        raise HTTPException(422, "Invalid field")
    db.execute(f"UPDATE alerts SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), alert_id))  # nosec B608
    db.commit()
    audit.record(db, user["username"], "alert.edit", f"alert/{alert_id}", {"fields": sorted(fields)})
    return _alert(db, alert_id)


@router.post("/community/alerts/{alert_id}/submit")
def submit_alert(alert_id: int, user=require("investigator"), db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] != "draft":
        raise HTTPException(409, "Only drafts can be submitted for review.")
    db.execute("UPDATE alerts SET status='pending_review' WHERE id=?", (alert_id,))
    db.commit()
    audit.record(db, user["username"], "alert.submit", f"alert/{alert_id}", {})
    return {"status": "pending_review"}


@router.post("/community/alerts/{alert_id}/approve")
def approve_alert(alert_id: int, body: ApproveIn, request: Request, user=require("reviewer"), db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] != "pending_review":
        raise HTTPException(409, "Alert is not pending review.")
    if a["created_by"] == user["id"]:
        raise HTTPException(403, "Two-person rule: the author cannot approve their own alert.")
    if not all(body.checklist.model_dump().values()):
        raise HTTPException(422, "All checklist items must be confirmed before publishing.")
    pii = residual_pii(" ".join([a["title_en"], a["title_ar"], a["summary_en"], a["summary_ar"],
                                 *[x["en"] + " " + x["ar"] for x in a["actions"]]]))
    if pii:
        raise HTTPException(422, f"Possible personal data detected ({', '.join(pii)}). Edit the alert before publishing.")
    db.execute("UPDATE alerts SET status='published', reviewed_by=?, review_note=?, published_at=? WHERE id=?",
               (user["id"], body.note, now(), alert_id))
    db.commit()
    audit.record(db, user["username"], "alert.publish", f"alert/{alert_id}", {"checklist": body.checklist.model_dump()})
    request.app.state.push.notify_alert_published(a)   # verified alert → subscribed phones
    return {"status": "published"}


@router.post("/community/alerts/{alert_id}/reject")
def reject_alert(alert_id: int, body: RejectIn, user=require("reviewer"), db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] not in ("pending_review", "draft"):
        raise HTTPException(409, "Alert cannot be rejected in its current state.")
    db.execute("UPDATE alerts SET status='rejected', reviewed_by=?, review_note=? WHERE id=?", (user["id"], body.note, alert_id))
    db.commit()
    audit.record(db, user["username"], "alert.reject", f"alert/{alert_id}", {"note": body.note})
    return {"status": "rejected"}


@router.post("/community/alerts/{alert_id}/archive")
def archive_alert(alert_id: int, user=require("reviewer"), db=Depends(get_db)):
    a = _alert(db, alert_id)
    if a["status"] != "published":
        raise HTTPException(409, "Only published alerts can be archived.")
    db.execute("UPDATE alerts SET status='archived' WHERE id=?", (alert_id,))
    db.commit()
    audit.record(db, user["username"], "alert.archive", f"alert/{alert_id}", {})
    return {"status": "archived"}


@router.patch("/community/reports/{report_id}")
def triage_report(report_id: int, body: ReportTriage, user=require("reviewer"), db=Depends(get_db)):
    if not db.execute("SELECT 1 FROM community_reports WHERE id=?", (report_id,)).fetchone():
        raise HTTPException(404, "Report not found")
    if body.status == "linked":
        if not body.alert_id:
            raise HTTPException(422, "alert_id is required to link a report")
        _alert(db, body.alert_id)
    db.execute("UPDATE community_reports SET status=?, linked_alert_id=?, triaged_by=? WHERE id=?",
               (body.status, body.alert_id, user["id"], report_id))
    db.commit()
    audit.record(db, user["username"], f"report.{body.status}", f"community_report/{report_id}", {"alert": body.alert_id})
    return {"ok": True}


# ------------------------------------------------------------------ public: Family Shield
_PRACTICE_CACHE: list | None = None


def _practice() -> list[dict]:
    """Training messages with the engine's real verdict and the exact phrases it flagged."""
    global _PRACTICE_CACHE
    if _PRACTICE_CACHE is None:
        from ai.behavioral_analysis.tactics import TACTICS
        from ai.threat_intelligence.playbook import PRACTICE
        out = []
        for p in PRACTICE:
            r = analyze("text", p["text"], None)
            hl = [{"span": o["span"], "tactic": o["tactic"], "label_en": TACTICS[o["tactic"]].label_en,
                   "label_ar": TACTICS[o["tactic"]].label_ar} for o in r["observed"] if o.get("span") and o.get("tactic") in TACTICS]
            out.append({**p, "engine": {"level": r["risk"]["level"], "score": r["risk"]["score"], "highlights": hl,
                                        "tactics": [{k: i[k] for k in ("key", "label_en", "label_ar", "explain_en", "explain_ar")}
                                                    for i in r["indicators"] if i.get("source") == "rule"]}})
        _PRACTICE_CACHE = out
    return _PRACTICE_CACHE


def _brand_names() -> dict:
    from pathlib import Path
    data = json.loads((Path(__file__).resolve().parents[3] / "ai" / "data" / "brands.json").read_text(encoding="utf-8"))["brands"]
    out = {}
    for key, b in data.items():
        ar = next((n for n in b.get("names", []) if any("\u0600" <= ch <= "\u06ff" for ch in n)), None)
        en = next((n for n in b.get("names", []) if n.isascii()), key)
        if en.islower():  # stored lower-case: title-case, keep short words such as UAE / NBD as acronyms
            en = " ".join(w.upper() if len(w) <= 3 else w.title() for w in en.split())
        out[key] = {"name_en": en, "name_ar": ar or en}
    return out


@router.get("/community/shield")
def family_shield(db=Depends(get_db)):
    """Everything the Family Shield page shows. Stages/tactics are the engine's own taxonomy; brands
    are counted from stored radar findings (last 7 days); alerts are published ones only."""
    import datetime as _dt
    from ai.threat_intelligence.playbook import AUDIENCE_TACTICS, stages, tactic_view
    cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=7)).isoformat()
    names = _brand_names()
    brands = [{"brand": r["brand"], "count": r["n"], **names.get(r["brand"], {"name_en": r["brand"].title(), "name_ar": r["brand"].title()})} for r in db.execute(
        "SELECT brand, COUNT(*) n FROM radar_items WHERE brand IS NOT NULL AND brand != '' AND status != 'dismissed' "
        "AND last_seen >= ? GROUP BY brand ORDER BY n DESC LIMIT 8", (cutoff,))]
    by_aud = {r["audience"]: r["n"] for r in db.execute(
        "SELECT audience, COUNT(*) n FROM alerts WHERE status='published' GROUP BY audience")}
    return {
        "stages": stages(),
        "practice": _practice(),
        "audiences": [{"key": a, "tactics": [tactic_view(k) for k in AUDIENCE_TACTICS[a]],
                       "published_alerts": by_aud.get(a, 0) + (by_aud.get("everyone", 0) if a != "everyone" else 0)}
                      for a in AUDIENCES],
        "brands_now": brands, "brands_window_days": 7,
    }
