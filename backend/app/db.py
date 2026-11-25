"""SQLite persistence (standard library only). Schema is created on startup."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('investigator','reviewer','admin')),
  display_name TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, input_kind TEXT NOT NULL, input_sha256 TEXT NOT NULL,
  input_text TEXT, risk_level TEXT NOT NULL, score INTEGER NOT NULL, pattern TEXT,
  community_match INTEGER NOT NULL DEFAULT 0, llm_status TEXT, feedback TEXT
);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY, ref TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_review','closed')),
  created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  last_analysis TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), kind TEXT NOT NULL,
  label TEXT NOT NULL, filename TEXT, mime TEXT, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  storage_path TEXT NOT NULL, extracted_text TEXT, extraction_note TEXT, source_note TEXT,
  metadata TEXT, analysis TEXT, submitted_by INTEGER NOT NULL REFERENCES users(id), submitted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS indicators (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, evidence_id INTEGER NOT NULL,
  type TEXT NOT NULL, value TEXT NOT NULL, display TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ind_value ON indicators(type, value);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, fingerprint TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('observed','indicator','inference','investigator_note')),
  source TEXT NOT NULL, evidence_ids TEXT NOT NULL, statement_en TEXT NOT NULL, statement_ar TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unreviewed' CHECK (status IN ('unreviewed','verified','dismissed')),
  reviewed_by INTEGER, review_note TEXT, reviewed_at TEXT, stale INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, UNIQUE(case_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('draft','pending_review','published','rejected','archived')),
  pattern_key TEXT, title_en TEXT NOT NULL, title_ar TEXT NOT NULL, summary_en TEXT NOT NULL, summary_ar TEXT NOT NULL,
  signs TEXT NOT NULL, actions TEXT NOT NULL, indicators TEXT NOT NULL, audience TEXT NOT NULL DEFAULT 'everyone',
  source_case_id INTEGER, created_by INTEGER NOT NULL, reviewed_by INTEGER, review_note TEXT,
  created_at TEXT NOT NULL, published_at TEXT, helpful INTEGER NOT NULL DEFAULT 0, not_helpful INTEGER NOT NULL DEFAULT 0,
  shown INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS community_reports (
  id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, text_anonymized TEXT NOT NULL, risk_level TEXT, pattern TEXT,
  status TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','linked','dismissed')),
  linked_alert_id INTEGER, triaged_by INTEGER
);
CREATE TABLE IF NOT EXISTS radar_items (
  id INTEGER PRIMARY KEY, host TEXT UNIQUE NOT NULL, registrable_domain TEXT NOT NULL, url TEXT,
  sources TEXT NOT NULL, brand TEXT, method TEXT, score INTEGER, reasons TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','promoted','dismissed')),
  reviewed_by INTEGER, alert_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_radar_reg ON radar_items(registrable_domain);
CREATE TABLE IF NOT EXISTS radar_sources (
  name TEXT PRIMARY KEY, state TEXT NOT NULL, last_success TEXT, last_error TEXT, error_count INTEGER NOT NULL DEFAULT 0,
  detail TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT,
  details TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# Columns added after the first release: applied in place so existing data is preserved.
MIGRATIONS = {
    "radar_items": [("evidence", "TEXT"), ("active", "INTEGER NOT NULL DEFAULT 1"), ("last_listed", "TEXT"), ("review_note", "TEXT")],
}


def init(path: Path) -> None:
    with connect(path) as c:
        c.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            for name, decl in cols:
                if name not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def row(r: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for f in json_fields:
        if d.get(f):
            d[f] = json.loads(d[f])
    return d


def rows(rs, json_fields: tuple[str, ...] = ()) -> list[dict]:
    return [row(r, json_fields) for r in rs]
