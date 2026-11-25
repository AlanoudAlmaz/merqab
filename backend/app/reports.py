"""Structured investigation report export (JSON, Markdown, printable HTML)."""
from __future__ import annotations

import html
import json
import sqlite3

from ai import RULES_VERSION
from backend.app.audit import entries_for
from backend.app.db import now, row, rows

LIMITATIONS = [
    "Findings marked 'indicator' or 'inference' are generated automatically and are not proof. Only findings marked 'verified' were confirmed by an investigator.",
    "Timestamps labelled 'content' are as written inside the evidence and may be inaccurate or fabricated; 'metadata' times can be altered by the source.",
    "OCR text may contain recognition errors; the original file (identified by its SHA-256 hash) is authoritative.",
    "Links were analysed offline without visiting them; no external reputation service was queried unless stated.",
    "Voice and video deepfake analysis is not performed in this version; only textual cues were assessed.",
    "MIRGAB correlates indicators between incidents; it does not identify or accuse any individual.",
]


def build(db: sqlite3.Connection, case_id: int, evidence_dir) -> dict:
    case = row(db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone(), ("last_analysis",))
    evs = rows(db.execute("""SELECT e.id, e.kind, e.label, e.filename, e.mime, e.size, e.sha256, e.submitted_at,
                             e.extraction_note, e.source_note, e.analysis, u.username AS submitted_by
                             FROM evidence e JOIN users u ON u.id = e.submitted_by WHERE case_id=? ORDER BY e.id""", (case_id,)),
               ("analysis",))
    from backend.app.evidence import verify
    for e in evs:
        p = db.execute("SELECT storage_path FROM evidence WHERE id=?", (e["id"],)).fetchone()["storage_path"]
        e["integrity"] = verify(evidence_dir, p, e["sha256"])["intact"]
        a = e.pop("analysis") or {}
        e["risk"] = a.get("risk", {}).get("level")
    fnd = rows(db.execute("SELECT * FROM findings WHERE case_id=? ORDER BY category, id", (case_id,)), ("evidence_ids",))
    la = case.get("last_analysis") or {}
    return {
        "report_type": "MIRGAB investigation summary",
        "generated_at": now(), "rules_version": RULES_VERSION,
        "case": {k: case[k] for k in ("ref", "title", "description", "status", "created_at", "updated_at")},
        "analysis_summary": la.get("summary"),
        "evidence": evs,
        "findings": {
            "verified": [f for f in fnd if f["status"] == "verified"],
            "unreviewed": [f for f in fnd if f["status"] == "unreviewed"],
            "dismissed": [f for f in fnd if f["status"] == "dismissed"],
        },
        "timeline": la.get("timeline"),
        "correlation": la.get("correlation"),
        "cross_case": la.get("cross_case", []),
        "chain_of_custody": entries_for(db, f"case/{case_id}"),
        "limitations": LIMITATIONS,
    }


def to_markdown(rep: dict) -> str:
    c = rep["case"]
    s = rep.get("analysis_summary") or {}
    L = [f"# Investigation summary — {c['ref']}", "", f"**{c['title']}**", "",
         f"- Status: {c['status']}", f"- Generated: {rep['generated_at']} (rules {rep['rules_version']})",
         f"- Last analysis: {s.get('analyzed_at', 'not analysed')}", f"- Highest risk observed: {s.get('highest_risk') or 'n/a'}", ""]
    if c.get("description"):
        L += [c["description"], ""]
    L += ["## Evidence", "", "| ID | Label | Type | SHA-256 | Integrity | Risk |", "|---|---|---|---|---|---|"]
    for e in rep["evidence"]:
        L.append(f"| E{e['id']} | {e['label']} | {e['kind']} | `{e['sha256'][:16]}…` | {'intact' if e['integrity'] else 'FAILED'} | {e['risk'] or '—'} |")
    L.append("")
    for title, key in (("Verified findings (confirmed by an investigator)", "verified"),
                       ("Unreviewed findings (automated — not proof)", "unreviewed")):
        L += [f"## {title}", ""]
        items = rep["findings"][key]
        if not items:
            L.append("_None._")
        for f in items:
            ev = ", ".join(f"E{i}" for i in f["evidence_ids"])
            note = f" — note: {f['review_note']}" if f.get("review_note") else ""
            L.append(f"- [{f['category']} · {f['source']}] {f['statement_en']} ({ev}){note}")
        L.append("")
    tl = rep.get("timeline") or {}
    L += ["## Timeline", ""]
    for ev in tl.get("events", []):
        tac = ", ".join(ev.get("tactics", [])) or "—"
        L.append(f"- {ev['time']} [{ev['time_source']}] E{ev['evidence_id']} {ev.get('sender') or ''}: {ev.get('text', '')[:140]} _(tactics: {tac})_")
    if not tl.get("events"):
        L.append("_No dated events._")
    if tl.get("progression"):
        L += ["", "Progression: " + " → ".join(f"{p['stage']} ({p['first_seen']})" for p in tl["progression"])]
    L += ["", "## Connections", ""]
    corr = rep.get("correlation") or {}
    for si in corr.get("shared_indicators", []):
        L.append(f"- Shared {si['type']}: {si['display']} in " + ", ".join(f"E{i}" for i in si["evidence_ids"]))
    for x in rep.get("cross_case", []):
        L.append(f"- {x['indicator_type']} {x['display']} also appears in case {x['case_ref']}")
    if not corr.get("shared_indicators") and not rep.get("cross_case"):
        L.append("_No shared indicators._")
    L += ["", "## Chain of custody", ""]
    for a in rep["chain_of_custody"]:
        L.append(f"- {a['ts']} · {a['actor']} · {a['action']} · {a['target']} · `{a['hash'][:12]}`")
    L += ["", "## Limitations", ""] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(L) + "\n"


def to_html(rep: dict) -> str:
    md = to_markdown(rep)
    body = []
    in_table = False
    for line in md.splitlines():
        esc = html.escape(line)
        if line.startswith("|"):
            cells = [html.escape(x.strip()) for x in line.strip("|").split("|")]
            if set(line) <= set("|-"):
                continue
            if not in_table:
                body.append("<table><tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                body.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{esc[2:]}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{esc[3:]}</h2>")
        elif line.startswith("- "):
            body.append(f"<p class='li'>• {esc[2:]}</p>")
        elif line.strip():
            body.append(f"<p>{esc}</p>")
    if in_table:
        body.append("</table>")
    css = ("body{font-family:system-ui,'Segoe UI',Tahoma,sans-serif;max-width:900px;margin:32px auto;padding:0 16px;color:#0f1d2b}"
           "h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #d5dde5;padding-bottom:4px}"
           "table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #d5dde5;padding:6px;text-align:start}"
           "p{font-size:14px;line-height:1.5;margin:4px 0}.li{padding-inline-start:8px}")
    return (f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>{html.escape(rep['case']['ref'])}</title>"
            f"<style>{css}</style></head><body>{''.join(body)}</body></html>")


def to_json(rep: dict) -> str:
    return json.dumps(rep, ensure_ascii=False, indent=2)
