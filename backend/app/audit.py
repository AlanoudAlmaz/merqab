"""Tamper-evident audit trail: every entry stores the hash of the previous one (hash chain)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from backend.app.db import now

_lock = threading.Lock()
GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, action: str, target: str | None, details: str) -> str:
    return hashlib.sha256("|".join([prev, ts, actor, action, target or "", details]).encode()).hexdigest()


def record(db: sqlite3.Connection, actor: str, action: str, target: str | None = None, details: dict | None = None) -> None:
    det = json.dumps(details or {}, ensure_ascii=False, sort_keys=True)
    with _lock:
        last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else GENESIS
        ts = now()
        h = _digest(prev, ts, actor, action, target, det)
        db.execute("INSERT INTO audit_log (ts, actor, action, target, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                   (ts, actor, action, target, det, prev, h))
        db.commit()


def verify_chain(db: sqlite3.Connection) -> dict:
    prev = GENESIS
    n = 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        n += 1
        if r["prev_hash"] != prev or _digest(prev, r["ts"], r["actor"], r["action"], r["target"], r["details"]) != r["hash"]:
            return {"valid": False, "entries": n, "broken_at": r["id"]}
        prev = r["hash"]
    return {"valid": True, "entries": n}


def entries_for(db: sqlite3.Connection, target_prefix: str) -> list[dict]:
    return [dict(r) | {"details": json.loads(r["details"] or "{}")} for r in db.execute(
        "SELECT id, ts, actor, action, target, details, hash FROM audit_log WHERE target = ? OR target LIKE ? ORDER BY id",
        (target_prefix, target_prefix + "/%"))]
