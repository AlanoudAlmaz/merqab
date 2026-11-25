"""Solution B — investigation workspace API (investigator role required)."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from backend.app import audit, evidence as evidence_svc, reports
from backend.app.db import now, row, rows
from backend.app.security import UploadRejected, get_db, require, safe_filename, validate_upload
from backend.app.services import analyze_case, next_case_ref

router = APIRouter(prefix="/api", tags=["investigation"])


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=4000)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    status: Literal["open", "in_review", "closed"] | None = None


class TextEvidenceIn(BaseModel):
    kind: Literal["text", "conversation", "url"]
    label: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=50000)
    source_note: str | None = Field(default=None, max_length=500)


class FindingPatch(BaseModel):
    status: Literal["verified", "dismissed", "unreviewed"]
    note: str | None = Field(default=None, max_length=1000)


class NoteIn(BaseModel):
    text: str = Field(min_length=3, max_length=2000)
    evidence_ids: list[int] = Field(default_factory=list, max_length=50)


def _case(db, case_id: int) -> dict:
    c = row(db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(), ("last_analysis",))
    if not c:
        raise HTTPException(404, "Case not found")
    return c


def _writable(c: dict):
    if c["status"] == "closed":
        raise HTTPException(409, "Case is closed; reopen it to add evidence or analysis.")


@router.get("/cases")
def list_cases(user=require("investigator"), db=Depends(get_db)):
    rs = db.execute("""SELECT c.id, c.ref, c.title, c.status, c.created_at, c.updated_at,
                       (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) AS evidence_count,
                       json_extract(c.last_analysis, '$.summary.highest_risk') AS highest_risk
                       FROM cases c ORDER BY c.updated_at DESC""").fetchall()
    return rows(rs)


@router.post("/cases", status_code=201)
def create_case(body: CaseIn, user=require("investigator"), db=Depends(get_db)):
    ts = now()
    ref = next_case_ref(db)
    cur = db.execute("INSERT INTO cases (ref, title, description, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                     (ref, body.title.strip(), (body.description or "").strip() or None, user["id"], ts, ts))
    db.commit()
    audit.record(db, user["username"], "case.create", f"case/{cur.lastrowid}", {"ref": ref})
    return {"id": cur.lastrowid, "ref": ref}


@router.get("/cases/{case_id}")
def get_case(case_id: int, user=require("investigator"), db=Depends(get_db)):
    c = _case(db, case_id)
    c["evidence"] = rows(db.execute("""SELECT id, kind, label, filename, mime, size, sha256, submitted_at, extraction_note,
                                       source_note, json_extract(analysis, '$.risk.level') AS risk_level,
                                       json_extract(analysis, '$.risk.score') AS risk_score
                                       FROM evidence WHERE case_id=? ORDER BY id""", (case_id,)))
    c["findings_count"] = db.execute("SELECT status, COUNT(*) n FROM findings WHERE case_id=? GROUP BY status", (case_id,)).fetchall()
    c["findings_count"] = {r["status"]: r["n"] for r in c["findings_count"]}
    return c


@router.patch("/cases/{case_id}")
def patch_case(case_id: int, body: CasePatch, user=require("investigator"), db=Depends(get_db)):
    _case(db, case_id)
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(422, "Nothing to update")
    if not set(fields) <= set(CasePatch.model_fields):   # column names only ever come from the model
        raise HTTPException(422, "Invalid field")
    sets = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE cases SET {sets}, updated_at=? WHERE id=?", (*fields.values(), now(), case_id))  # nosec B608 - allow-listed columns
    db.commit()
    audit.record(db, user["username"], "case.update", f"case/{case_id}", fields)
    return _case(db, case_id)


def _insert_evidence(request, db, user, case_id, kind, label, data: bytes, filename, mime, ext, source_note):
    s = request.app.state.settings
    digest, rel = evidence_svc.store(s.evidence_dir, data)
    ex = evidence_svc.extract(ext, data, s.ocr_enabled) if kind == "file" else {
        "text": data.decode("utf-8"), "note": "Submitted as text.", "metadata": {}, "header_signals": []}
    meta = dict(ex.get("metadata") or {})
    if ex.get("header_signals"):
        meta["header_signals"] = ex["header_signals"]
    cur = db.execute("""INSERT INTO evidence (case_id, kind, label, filename, mime, size, sha256, storage_path, extracted_text,
                        extraction_note, source_note, metadata, submitted_by, submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (case_id, kind, label, filename, mime, len(data), digest, rel, ex["text"], ex["note"], source_note,
                      json.dumps(meta, ensure_ascii=False, default=str), user["id"], now()))
    db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now(), case_id))
    db.commit()
    audit.record(db, user["username"], "evidence.add", f"case/{case_id}/evidence/{cur.lastrowid}",
                 {"sha256": digest, "kind": kind, "size": len(data), "filename": filename})
    return {"id": cur.lastrowid, "sha256": digest, "extraction_note": ex["note"], "text_extracted": bool(ex["text"])}


@router.post("/cases/{case_id}/evidence/text", status_code=201)
def add_text_evidence(case_id: int, body: TextEvidenceIn, request: Request, user=require("investigator"), db=Depends(get_db)):
    _writable(_case(db, case_id))
    return _insert_evidence(request, db, user, case_id, body.kind, body.label.strip(), body.content.encode("utf-8"),
                            None, "text/plain", "txt", body.source_note)


@router.post("/cases/{case_id}/evidence/file", status_code=201)
async def add_file_evidence(case_id: int, request: Request, file: UploadFile = File(...),
                            label: str = Form(..., min_length=1, max_length=120), source_note: str | None = Form(None, max_length=500),
                            user=require("investigator"), db=Depends(get_db)):
    _writable(_case(db, case_id))
    s = request.app.state.settings
    data = await file.read(s.max_upload_mb * 1024 * 1024 + 1)
    try:
        ext, mime = validate_upload(file.filename or "", data, s.max_upload_mb * 1024 * 1024)
    except UploadRejected as e:
        audit.record(db, user["username"], "evidence.rejected", f"case/{case_id}", {"reason": str(e), "filename": safe_filename(file.filename or "")})
        raise HTTPException(415, str(e))
    return _insert_evidence(request, db, user, case_id, "file", label.strip(), data, safe_filename(file.filename or ""), mime, ext, source_note)


def _evidence(db, evidence_id: int) -> dict:
    e = row(db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone(), ("metadata", "analysis"))
    if not e:
        raise HTTPException(404, "Evidence not found")
    return e


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, user=require("investigator"), db=Depends(get_db)):
    e = _evidence(db, evidence_id)
    e.pop("storage_path", None)
    e["indicators"] = rows(db.execute("SELECT type, value, display FROM indicators WHERE evidence_id=?", (evidence_id,)))
    return e


@router.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, request: Request, user=require("investigator"), db=Depends(get_db)):
    e = _evidence(db, evidence_id)
    res = evidence_svc.verify(request.app.state.settings.evidence_dir, e["storage_path"], e["sha256"])
    audit.record(db, user["username"], "evidence.verify", f"case/{e['case_id']}/evidence/{evidence_id}", {"intact": res["intact"]})
    return res


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: int, request: Request, user=require("investigator"), db=Depends(get_db)):
    e = _evidence(db, evidence_id)
    p = request.app.state.settings.evidence_dir / e["storage_path"]
    audit.record(db, user["username"], "evidence.download", f"case/{e['case_id']}/evidence/{evidence_id}", {})
    name = e["filename"] or f"evidence-{evidence_id}.txt"
    # Always served as an opaque attachment: never rendered by the browser
    return FileResponse(p, media_type="application/octet-stream", filename=f"E{evidence_id}-{name}")


@router.post("/cases/{case_id}/analyze")
def run_analysis(case_id: int, request: Request, user=require("investigator"), db=Depends(get_db)):
    c = _case(db, case_id)
    _writable(c)
    if not db.execute("SELECT 1 FROM evidence WHERE case_id=?", (case_id,)).fetchone():
        raise HTTPException(409, "Add evidence before running analysis.")
    res = analyze_case(db, case_id, request.app.state.llm)
    audit.record(db, user["username"], "case.analyze", f"case/{case_id}", {"evidence": res["summary"]["evidence_count"]})
    return res


@router.get("/cases/{case_id}/analysis")
def get_analysis(case_id: int, user=require("investigator"), db=Depends(get_db)):
    return _case(db, case_id).get("last_analysis") or {}


@router.get("/cases/{case_id}/findings")
def list_findings(case_id: int, user=require("investigator"), db=Depends(get_db)):
    _case(db, case_id)
    return rows(db.execute("""SELECT f.*, u.username AS reviewer FROM findings f LEFT JOIN users u ON u.id = f.reviewed_by
                              WHERE case_id=? ORDER BY CASE category WHEN 'observed' THEN 0 WHEN 'indicator' THEN 1
                              WHEN 'inference' THEN 2 ELSE 3 END, id""", (case_id,)), ("evidence_ids",))


@router.patch("/findings/{finding_id}")
def review_finding(finding_id: int, body: FindingPatch, user=require("investigator"), db=Depends(get_db)):
    f = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not f:
        raise HTTPException(404, "Finding not found")
    if body.status == "verified" and f["category"] == "inference" and not (body.note and body.note.strip()):
        raise HTTPException(422, "Verifying an AI/heuristic inference requires a note explaining the supporting evidence.")
    db.execute("UPDATE findings SET status=?, review_note=?, reviewed_by=?, reviewed_at=? WHERE id=?",
               (body.status, body.note, user["id"], now(), finding_id))
    db.commit()
    audit.record(db, user["username"], f"finding.{body.status}", f"case/{f['case_id']}/finding/{finding_id}", {"note": body.note})
    return {"ok": True}


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteIn, user=require("investigator"), db=Depends(get_db)):
    _writable(_case(db, case_id))
    ts = now()
    cur = db.execute("""INSERT INTO findings (case_id, fingerprint, category, source, evidence_ids, statement_en, statement_ar,
                        status, reviewed_by, reviewed_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                     (case_id, f"note:{ts}:{user['id']}", "investigator_note", "investigator", json.dumps(body.evidence_ids),
                      body.text, body.text, "verified", user["id"], ts, ts))
    db.commit()
    audit.record(db, user["username"], "finding.note", f"case/{case_id}/finding/{cur.lastrowid}", {})
    return {"id": cur.lastrowid}


@router.get("/cases/{case_id}/report")
def export_report(case_id: int, request: Request, format: Literal["json", "md", "html"] = "md",
                  user=require("investigator"), db=Depends(get_db)):
    c = _case(db, case_id)
    rep = reports.build(db, case_id, request.app.state.settings.evidence_dir)
    audit.record(db, user["username"], "report.export", f"case/{case_id}", {"format": format})
    fname = f"{c['ref']}-report.{format}"
    disp = {"Content-Disposition": f'attachment; filename="{fname}"'}
    if format == "json":
        return Response(reports.to_json(rep), media_type="application/json", headers=disp)
    if format == "html":
        return Response(reports.to_html(rep), media_type="text/html; charset=utf-8",
                        headers={**disp, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return PlainTextResponse(reports.to_markdown(rep), media_type="text/markdown; charset=utf-8", headers=disp)
