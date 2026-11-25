"""Solution A — public Smart Protection API (no account needed)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from ai.pipeline import analyze
from backend.app import evidence as evidence_svc
from backend.app.db import now
from backend.app.security import UploadRejected, get_db, rate_limit, validate_upload
from backend.app.services import community_index, looks_like_conversation

router = APIRouter(prefix="/api", tags=["prevention"])


class AnalyzeIn(BaseModel):
    kind: Literal["text", "conversation", "url"]
    content: str = Field(min_length=1, max_length=20000)


class FeedbackIn(BaseModel):
    verdict: Literal["helpful", "incorrect"]


def _record(request: Request, db, kind: str, content: str, result: dict) -> int:
    s = request.app.state.settings
    matches = [m for m in result["community_matches"] if m["type"] == "indicator"]
    cur = db.execute(
        """INSERT INTO analyses (created_at, input_kind, input_sha256, input_text, risk_level, score, pattern, community_match, llm_status)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now(), kind, result["input"]["sha256"], content if s.store_analysis_text else None, result["risk"]["level"],
         result["risk"]["score"], (result["patterns"][0]["key"] if result["patterns"] else None), int(bool(matches)),
         result["engine"]["llm"]["status"]))
    for aid in {m["alert_id"] for m in result["community_matches"]}:
        db.execute("UPDATE alerts SET shown = shown + 1 WHERE id=? AND status='published'", (aid,))
    db.commit()
    return cur.lastrowid


def _public_result(result: dict) -> dict:
    # Keep campaign internals inside the radar and investigation APIs.
    result["radar_matches"] = [
        {key: match[key] for key in ("host", "confirmed", "predicted", "first_seen") if key in match}
        for match in result["radar_matches"]
    ]
    result["inferences"] = [
        inference for inference in result["inferences"]
        if inference.get("type") not in {"campaign", "campaign_prediction"}
    ]
    return result


@router.post("/analyze", dependencies=[rate_limit("analyze")])
def analyze_content(body: AnalyzeIn, request: Request, db=Depends(get_db)):
    if not body.content.strip():
        raise HTTPException(422, "Content is empty.")
    result = analyze(body.kind, body.content, request.app.state.llm, community_index(db))
    result["analysis_id"] = _record(request, db, body.kind, body.content, result)
    return _public_result(result)


@router.post("/analyze/file", dependencies=[rate_limit("analyze_file", 0.5)])
async def analyze_file(request: Request, file: UploadFile = File(...), db=Depends(get_db)):
    s = request.app.state.settings
    data = await file.read(s.max_upload_mb * 1024 * 1024 + 1)
    try:
        ext, _ = validate_upload(file.filename or "", data, s.max_upload_mb * 1024 * 1024)
    except UploadRejected as e:
        raise HTTPException(415, str(e))
    ex = evidence_svc.extract(ext, data, s.ocr_enabled)  # in memory only — the file is not stored
    text = ex["text"] or ""
    if not text.strip():
        return {"extracted": False, "note": ex["note"], "result": None}
    kind = "conversation" if looks_like_conversation(text) else "text"
    result = analyze(kind, text, request.app.state.llm, community_index(db))
    result["analysis_id"] = _record(request, db, f"file:{ext}", text, result)
    return {"extracted": True, "note": ex["note"], "text": text[:5000], "header_signals": ex.get("header_signals", []),
            "result": _public_result(result)}


@router.post("/analyze/{analysis_id}/feedback", dependencies=[rate_limit("feedback")])
def feedback(analysis_id: int, body: FeedbackIn, db=Depends(get_db)):
    r = db.execute("SELECT feedback FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    if not r:
        raise HTTPException(404, "Analysis not found")
    if r["feedback"]:
        raise HTTPException(409, "Feedback already recorded")
    db.execute("UPDATE analyses SET feedback=? WHERE id=?", (body.verdict, analysis_id))
    db.commit()
    return {"ok": True}
