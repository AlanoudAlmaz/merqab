"""Detection accuracy: recorded benchmark results and a live re-run on this server."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

from backend.app.security import rate_limit

router = APIRouter(prefix="/api", tags=["accuracy"])
RESULTS = Path(__file__).resolve().parents[3] / "ai" / "eval" / "results.json"
_lock = threading.Lock()
_last: dict = {}


@router.get("/accuracy")
def recorded():
    if not RESULTS.exists():
        raise HTTPException(404, "No benchmark results recorded")
    return json.loads(RESULTS.read_text(encoding="utf-8"))


@router.post("/accuracy/run", dependencies=[rate_limit("accuracy_run", 0.1)])
def rerun():
    """Re-run the whole held-out benchmark with the engine that is serving users right now (about 2 s)."""
    from ai.eval.run import run
    if not _lock.acquire(timeout=15):
        raise HTTPException(429, "A benchmark run is already in progress")
    try:
        if _last.get("at", 0) > time.time() - 30:
            return _last["res"]
        t0 = time.perf_counter()
        res = run("test")
        res["seconds"] = round(time.perf_counter() - t0, 2)
        res["live"] = True
        res["matches_recorded"] = RESULTS.exists() and json.loads(RESULTS.read_text(encoding="utf-8"))["overall"] == res["overall"]
        _last.update(at=time.time(), res=res)
        return res
    finally:
        _lock.release()
