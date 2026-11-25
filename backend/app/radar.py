"""Live Threat Radar background service.

Runs inside the MERQAB process (no extra infrastructure):
  * a thread follows the newest entries of several public Certificate Transparency logs;
  * a thread refreshes the OpenPhish community feed (conditional download, listing status);
  * a thread scans four large public phishing-domain lists (CERT Polska, Phishing Army, Phishing.Database,
    Block List Project). Every entry is scanned; entries that impersonate a monitored brand are stored.

Reliability: per-log exponential back-off, conditional HTTP requests, and source health persisted
in `radar_sources` so freshness survives restarts. Every finding keeps its evidence: CT log name,
entry index, certificate timestamp and issuer, or the feed URL and fetch time.

Coverage note (shown in the UI): CT logs publish thousands of certificates per second; this
prototype samples the newest entries of each log every cycle, so it does not see every certificate.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import sqlite3
import threading
import time

import httpx

from ai.threat_intelligence.ct_parser import entry_details
from ai.behavioral_analysis.url_analyzer import registrable_domain
from ai.threat_intelligence.radar import brand_in_url, classify_domain, parse_feed_line
from backend.app import db as dbm

log = logging.getLogger("mirqab.radar")
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
MAX_LOGS = 8
BATCH = 512
CYCLE_SECONDS = 6
FEED_REFRESH_SECONDS = 1200
# Large public phishing-domain lists: (url, label en, label ar). Checked reachable 2026-11; all free, no key.
DOMAIN_FEEDS = {
    "certpl": ("https://hole.cert.pl/domains/v2/domains.txt", "CERT Polska warning list", "قائمة تحذيرات CERT Polska"),
    "phishing_army": ("https://phishing.army/download/phishing_army_blocklist.txt", "Phishing Army blocklist", "قائمة Phishing Army"),
    "phishing_db": ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
                    "Phishing.Database (active)", "قاعدة Phishing.Database (النشطة)"),
    "blocklist_project": ("https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
                          "Block List Project — phishing", "قائمة Block List Project للتصيّد"),
}
DOMAIN_FEED_REFRESH_SECONDS = 3 * 3600
FEED_SOURCES = {"openphish", *DOMAIN_FEEDS}
SOURCE_LABELS = {"ct": ("Certificate Transparency logs", "سجلات شفافية الشهادات"),
                 "openphish": ("OpenPhish community feed", "قائمة OpenPhish العامة"),
                 **{k: (v[1], v[2]) for k, v in DOMAIN_FEEDS.items()}}


def _iso(ms: int | None) -> str | None:
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).isoformat(timespec="seconds") if ms else None


def upsert(db, item: dict, source: str, url: str | None = None, evidence: dict | None = None, commit: bool = True) -> bool:
    """Insert or refresh a finding; returns True if it is new."""
    now = dbm.now()
    r = db.execute("SELECT id, status FROM radar_items WHERE host=?", (item["host"],)).fetchone()
    if r:
        db.execute("""UPDATE radar_items SET last_seen=?, seen_count=seen_count+1, active=1,
                      last_listed=CASE WHEN ?!='ct' THEN ? ELSE last_listed END,
                      sources=CASE WHEN instr(sources, ?) THEN sources ELSE sources || ',' || ? END WHERE id=?""",
                   (now, source, now, source, source, r["id"]))
        if commit:
            db.commit()
        return False
    db.execute("""INSERT INTO radar_items (host, registrable_domain, url, sources, brand, method, score, reasons, first_seen,
                  last_seen, evidence, active, last_listed) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)""",
               (item["host"], item["registrable_domain"], url, source, item.get("brand"), item.get("method"),
                item.get("score"), json.dumps(item.get("reasons", []), ensure_ascii=False), now, now,
                json.dumps(evidence or {}, ensure_ascii=False), now if source != "ct" else None))
    if commit:
        db.commit()
    return True


LISTED: dict[str, set[str]] = {}   # what each feed lists right now (known after its latest refresh)


def _mark_unlisted(conn, source: str, listed: set[str]):
    """A finding stays 'listed now' while any feed currently lists it; history is never deleted.
    A feed whose current list is not known yet (e.g. just after a restart) is assumed to still list it."""
    LISTED[source] = set(listed)
    for r in conn.execute("SELECT id, host, sources FROM radar_items WHERE instr(sources, ?) AND active=1", (source,)).fetchall():
        if r["host"] in listed:
            continue
        others = (set(r["sources"].split(",")) & FEED_SOURCES) - {source}
        if not any(o not in LISTED or r["host"] in LISTED[o] for o in others):
            conn.execute("UPDATE radar_items SET active=0 WHERE id=?", (r["id"],))


def parse_domain_list(text: str):
    """Plain domain-per-line or hosts-file lists; comments and blank lines are skipped."""
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        host = line.split()[-1].strip(".")
        if "." in host and host not in ("localhost", "0.0.0.0") and not host.replace(".", "").isdigit():
            yield host


def maintain(db) -> dict:
    """Re-apply the current detection rules to stored findings (keeps history, never deletes).

    * CT findings that no longer match the rules are dismissed with an explanatory note.
    * Feed findings without a brand get one if the URL names it.
    """
    dismissed = branded = 0
    for r in db.execute("SELECT id, host, url, sources, brand, status FROM radar_items").fetchall():
        if r["status"] == "new" and not (set(r["sources"].split(",")) & FEED_SOURCES) and classify_domain(r["host"]) is None:
            db.execute("UPDATE radar_items SET status='dismissed', review_note=? WHERE id=?",
                       ("auto: no longer matches detection rules (rule update)", r["id"]))
            dismissed += 1
        elif not r["brand"] and r["url"]:
            b = brand_in_url(r["url"])
            if b:
                db.execute("UPDATE radar_items SET brand=? WHERE id=?", (b, r["id"]))
                branded += 1
    db.commit()
    return {"dismissed_by_rule_update": dismissed, "brand_added": branded}



class _Capped:
    """Minimal response wrapper for size-capped downloads (feeds are untrusted and must not exhaust memory)."""
    def __init__(self, status_code, headers, text):
        self.status_code, self.headers, self.text = status_code, headers, text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=None, response=None)


def capped_get(c: "httpx.Client", url: str, headers: dict | None = None, max_bytes: int = 64 * 1024 * 1024) -> _Capped:
    with c.stream("GET", url, headers=headers or {}) as r:
        if r.status_code == 304 or r.status_code >= 400:
            return _Capped(r.status_code, r.headers, "")
        if not str(r.url).startswith("https://"):
            raise ValueError("feed redirected off HTTPS")
        buf = bytearray()
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > max_bytes:
                raise ValueError("feed larger than cap")
        return _Capped(r.status_code, r.headers, buf.decode(r.encoding or "utf-8", errors="replace"))

class RadarService:
    def __init__(self, db_path, enabled: bool):
        self.db_path = db_path
        self.enabled = enabled
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.started_at = None
        self.stats = {"certificates_processed": 0, "domains_checked": 0, "ct_flagged": 0}
        self.threads: list[threading.Thread] = []

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        if not self.enabled or self.threads:
            return
        self.started_at = dbm.now()
        conn = dbm.connect(self.db_path)
        try:
            log.info("Radar maintenance: %s", maintain(conn))
        finally:
            conn.close()
        for target, name in ((self._ct_loop, "ct"), (self._feed_loop, "openphish"), (self._domain_feeds_loop, "lists")):
            t = threading.Thread(target=target, name=f"radar-{name}", daemon=True)
            t.start()
            self.threads.append(t)
        log.info("Live Threat Radar started")

    def shutdown(self):
        self.stop.set()

    def _status(self, db, name: str, ok: bool, detail: dict | None = None, error: str | None = None):
        now = dbm.now()
        r = db.execute("SELECT error_count FROM radar_sources WHERE name=?", (name,)).fetchone()
        errors = 0 if ok else ((r["error_count"] if r else 0) + 1)
        db.execute("""INSERT INTO radar_sources (name, state, last_success, last_error, error_count, detail, updated_at)
                      VALUES (?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET state=excluded.state,
                      last_success=COALESCE(excluded.last_success, radar_sources.last_success),
                      last_error=COALESCE(excluded.last_error, radar_sources.last_error),
                      error_count=excluded.error_count, detail=COALESCE(excluded.detail, radar_sources.detail),
                      updated_at=excluded.updated_at""",
                   (name, "ok" if ok else "degraded", now if ok else None, None if ok else f"{now} {error}", errors,
                    json.dumps(detail, ensure_ascii=False) if detail is not None else None, now))
        db.commit()

    def _record_failure(self, db, name: str, error: Exception):
        # Release any partial write before attempting to record source health.
        db.rollback()
        try:
            self._status(db, name, False, None, type(error).__name__)
        except sqlite3.Error:
            db.rollback()
            log.warning("Could not record radar source %s failure: %s", name, error, exc_info=True)

    def snapshot(self, db) -> dict:
        now = dt.datetime.now(dt.timezone.utc)
        sources = []
        for name, (en, ar) in SOURCE_LABELS.items():
            r = db.execute("SELECT * FROM radar_sources WHERE name=?", (name,)).fetchone()
            s = {"name": name, "label_en": en, "label_ar": ar, "state": "not_started", "last_success": None,
                 "age_seconds": None, "error_count": 0, "last_error": None, "detail": {}}
            if r:
                s.update(state=r["state"], last_success=r["last_success"], error_count=r["error_count"],
                         last_error=r["last_error"], detail=json.loads(r["detail"] or "{}"))
                if r["last_success"]:
                    s["age_seconds"] = int((now - dt.datetime.fromisoformat(r["last_success"])).total_seconds())
            if not self.enabled:
                s["state"] = "disabled"
            sources.append(s)
        with self.lock:
            stats = dict(self.stats)
        return {"enabled": self.enabled, "running_since": self.started_at, "session_stats": stats, "sources": sources,
                "coverage_note_en": "Certificate Transparency is sampled: the newest entries of each log are checked every few seconds, not every certificate.",
                "coverage_note_ar": "يتم أخذ عيّنات من سجلات الشهادات: تُفحص أحدث الإدخالات في كل سجل كل بضع ثوانٍ، وليس كل شهادة."}

    # ------------------------------------------------------------------ certificate transparency
    @staticmethod
    def _pick_logs(c: httpx.Client) -> list[dict]:
        data = c.get(LOG_LIST_URL).json()
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        logs = []
        for op in data.get("operators", []):
            for l in op.get("logs", []):
                ti = l.get("temporal_interval", {})
                if "usable" in l.get("state", {}) and ti.get("start_inclusive", "") <= now < ti.get("end_exclusive", "9999"):
                    logs.append({"name": l["description"], "url": l["url"].rstrip("/") + "/", "fail": 0, "retry_at": 0.0})
        return logs[:MAX_LOGS]

    def _ct_loop(self):
        conn = dbm.connect(self.db_path)
        positions: dict[str, int] = {}
        logs: list[dict] = []
        newest_cert_ms: dict[str, int] = {}
        with httpx.Client(timeout=20, headers={"User-Agent": "MIRQAB-radar/1.1"}) as c:
            while not self.stop.is_set():
                try:
                    if not logs:
                        logs = self._pick_logs(c)
                    healthy = 0
                    for l in logs:
                        if self.stop.is_set() or time.monotonic() < l["retry_at"]:
                            continue
                        try:
                            size = c.get(l["url"] + "ct/v1/get-sth").json()["tree_size"]
                            start = max(positions.get(l["url"], size - BATCH), size - BATCH * 4)
                            if start >= size - 1:
                                healthy += 1
                                continue
                            end = min(start + BATCH - 1, size - 1)
                            entries = c.get(l["url"] + "ct/v1/get-entries", params={"start": start, "end": end}).json().get("entries", [])
                            positions[l["url"]] = start + len(entries)
                            n_domains = flagged = 0
                            for k, e in enumerate(entries):
                                domains, ts, issuer = entry_details(e)
                                if ts:
                                    newest_cert_ms[l["name"]] = max(newest_cert_ms.get(l["name"], 0), ts)
                                n_domains += len(domains)
                                for d in domains:
                                    f = classify_domain(d)
                                    if f and upsert(conn, f, "ct", evidence={"log": l["name"], "entry_index": start + k,
                                                                             "certificate_time": _iso(ts), "issuer": issuer}):
                                        flagged += 1
                            with self.lock:
                                self.stats["certificates_processed"] += len(entries)
                                self.stats["domains_checked"] += n_domains
                                self.stats["ct_flagged"] += flagged
                            l["fail"] = 0
                            healthy += 1
                        except (httpx.HTTPError, ValueError, KeyError) as e:
                            l["fail"] += 1
                            l["retry_at"] = time.monotonic() + min(300, 15 * 2 ** (l["fail"] - 1))  # exponential back-off
                            log.debug("CT log %s failed: %s", l["name"], e)
                    lag = {n: int(time.time() - ms / 1000) for n, ms in newest_cert_ms.items()}
                    detail = {"logs": [{"name": l["name"], "ok": l["fail"] == 0} for l in logs], "healthy_logs": healthy,
                              "newest_certificate_age_seconds": min(lag.values()) if lag else None}
                    self._status(conn, "ct", healthy > 0, detail, None if healthy else "all logs unreachable")
                except Exception as e:  # network down, log list unavailable
                    self._record_failure(conn, "ct", e)
                    logs = []
                    self.stop.wait(30)
                self.stop.wait(CYCLE_SECONDS)
        conn.close()

    # ------------------------------------------------------------------ phishing feed
    def refresh_feed(self, conn, text: str, fetched_at: str) -> dict:
        new = total = 0
        listed = set()
        for line in text.splitlines()[:5000]:
            item = parse_feed_line(line)
            if not item:
                continue
            total += 1
            listed.add(item["host"])
            item.update({"method": "confirmed_feed", "score": 95,
                         "reasons": [{"en": "Listed as phishing by the OpenPhish community feed",
                                      "ar": "مُدرج كموقع تصيّد في قائمة OpenPhish العامة"}]})
            if upsert(conn, item, "openphish", item["url"], {"feed": OPENPHISH_URL, "fetched_at": fetched_at}):
                new += 1
        # entries that dropped out of the feed are kept for history but marked as no longer listed
        _mark_unlisted(conn, "openphish", listed)
        conn.commit()
        return {"listed_now": total, "new": new}

    def _feed_loop(self):
        conn = dbm.connect(self.db_path)
        etag = None
        fail = 0
        with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "MIRQAB-radar/1.1"}) as c:
            while not self.stop.is_set():
                wait = FEED_REFRESH_SECONDS
                try:
                    r = capped_get(c, OPENPHISH_URL, {"If-None-Match": etag} if etag else {}, 8 * 1024 * 1024)
                    if r.status_code == 304:
                        self._status(conn, "openphish", True, None)
                    else:
                        r.raise_for_status()
                        res = self.refresh_feed(conn, r.text, dbm.now())
                        self._status(conn, "openphish", True, res)
                        etag = r.headers.get("etag")
                    fail = 0
                except Exception as e:
                    fail += 1
                    wait = min(FEED_REFRESH_SECONDS, 30 * 2 ** (fail - 1))
                    self._record_failure(conn, "openphish", e)
                self.stop.wait(wait)
        conn.close()

    # ------------------------------------------------------------------ large public phishing-domain lists
    def refresh_domain_feed(self, conn, key: str, text: str, fetched_at: str) -> dict:
        """Scan every entry; keep those that impersonate a monitored brand (the graph stays meaningful and fast)."""
        url, en, ar = DOMAIN_FEEDS[key]
        scanned = new = 0
        listed: set[str] = set()
        matches = []
        for host in parse_domain_list(text):
            scanned += 1
            if scanned % 5000 == 0:
                time.sleep(0.02)   # let web requests run while a large list is scanned
            c = classify_domain(host)
            if not c:
                continue
            listed.add(host)
            item = {"host": host, "registrable_domain": c.get("registrable_domain") or registrable_domain(host), "brand": c["brand"],
                    "method": "confirmed_feed", "score": 90,
                    "reasons": [{"en": f"Listed as phishing by {en}", "ar": f"مُدرج كموقع تصيّد في {ar}"}] + c.get("reasons", [])[:2]}
            matches.append(item)
        # Classify the complete feed before opening a SQLite write transaction.
        for item in matches:
            if upsert(conn, item, key, None, {"feed": url, "fetched_at": fetched_at}, commit=False):
                new += 1
        _mark_unlisted(conn, key, listed)
        conn.commit()
        with self.lock:
            self.stats["domains_checked"] += scanned
        return {"scanned": scanned, "listed_now": len(listed), "new": new}

    def _domain_feeds_loop(self):
        conn = dbm.connect(self.db_path)
        etags: dict[str, str] = {}
        fails: dict[str, int] = {}
        next_at: dict[str, float] = {}
        # after a restart, don't re-scan lists that were refreshed recently (a full pass is ~850k entries)
        for key in DOMAIN_FEEDS:
            r = conn.execute("SELECT last_success, detail FROM radar_sources WHERE name=?", (key,)).fetchone()
            if r and r["last_success"]:
                age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(r["last_success"])).total_seconds()
                if age < DOMAIN_FEED_REFRESH_SECONDS:
                    next_at[key] = time.time() + DOMAIN_FEED_REFRESH_SECONDS - age
                    for row in conn.execute("SELECT host FROM radar_items WHERE instr(sources, ?) AND active=1", (key,)):
                        LISTED.setdefault(key, set()).add(row["host"])
        self.stop.wait(20)   # start after the web server and CT follower are up
        with httpx.Client(timeout=90, follow_redirects=True, headers={"User-Agent": "MIRQAB-radar/1.2"}) as c:
            while not self.stop.is_set():
                for key, (url, _, _) in DOMAIN_FEEDS.items():
                    if self.stop.is_set() or time.time() < next_at.get(key, 0):
                        continue
                    try:
                        r = capped_get(c, url, {"If-None-Match": etags[key]} if key in etags else {})
                        if r.status_code == 304:
                            self._status(conn, key, True, None)
                        else:
                            r.raise_for_status()
                            self._status(conn, key, True, self.refresh_domain_feed(conn, key, r.text, dbm.now()))
                            if r.headers.get("etag"):
                                etags[key] = r.headers["etag"]
                        fails[key] = 0
                        next_at[key] = time.time() + DOMAIN_FEED_REFRESH_SECONDS
                    except Exception as e:
                        fails[key] = fails.get(key, 0) + 1
                        next_at[key] = time.time() + min(DOMAIN_FEED_REFRESH_SECONDS, 60 * 2 ** (fails[key] - 1))
                        self._record_failure(conn, key, e)
                self.stop.wait(30)
        conn.close()
