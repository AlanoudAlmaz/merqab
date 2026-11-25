"""Evidence correlation and incident reconstruction.

Correlation only uses *observable* overlaps: shared indicators (strong) and shared manipulation
tactics (weak, behavioural). It never asserts that two artefacts come from the same person.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from ai.behavioral_analysis.tactics import STAGE_ORDER, TACTICS
from ai.investigation.indicators import STRONG_TYPES


def correlate(evidence: list[dict]) -> dict:
    """evidence: [{id, label, indicators:[{type,value,display}], tactics:[...]}]"""
    by_value: dict[tuple, list[int]] = defaultdict(list)
    for ev in evidence:
        for ind in ev.get("indicators", []):
            key = (ind["type"], ind["value"])
            if ev["id"] not in by_value[key]:
                by_value[key].append(ev["id"])
    display = {(i["type"], i["value"]): i["display"] for ev in evidence for i in ev.get("indicators", [])}

    links: list[dict] = []
    shared_indicators = []
    for (t, v), ids in by_value.items():
        if len(ids) > 1:
            shared_indicators.append({"type": t, "value": v, "display": display[(t, v)], "evidence_ids": ids,
                                      "strength": "strong" if t in STRONG_TYPES else "weak"})
    pair_reasons: dict[tuple, dict] = {}
    for si in shared_indicators:
        for a, b in combinations(sorted(si["evidence_ids"]), 2):
            pr = pair_reasons.setdefault((a, b), {"indicators": [], "tactics": []})
            pr["indicators"].append({"type": si["type"], "display": si["display"]})
    tac = {ev["id"]: set(ev.get("tactics", [])) for ev in evidence}
    for a, b in combinations(sorted(tac), 2):
        common = sorted(tac[a] & tac[b])
        if len(common) >= 2:
            pr = pair_reasons.setdefault((a, b), {"indicators": [], "tactics": []})
            pr["tactics"] = common
    for (a, b), pr in sorted(pair_reasons.items()):
        strong = any(i["type"] in STRONG_TYPES for i in pr["indicators"])
        links.append({"a": a, "b": b, "strength": "strong" if strong else "behavioural",
                      "shared_indicators": pr["indicators"], "shared_tactics": pr["tactics"]})

    # Recurring tactics across the case
    counts: dict[str, list[int]] = defaultdict(list)
    for ev in evidence:
        for t in ev.get("tactics", []):
            counts[t].append(ev["id"])
    recurring = [{"tactic": t, "label_en": TACTICS[t].label_en, "label_ar": TACTICS[t].label_ar, "evidence_ids": ids}
                 for t, ids in sorted(counts.items(), key=lambda kv: -len(kv[1])) if len(ids) > 1]
    # Simple cluster detection (connected components over strong links)
    parent = {ev["id"]: ev["id"] for ev in evidence}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for l in links:
        if l["strength"] == "strong":
            parent[find(l["a"])] = find(l["b"])
    groups: dict[int, list[int]] = defaultdict(list)
    for ev in evidence:
        groups[find(ev["id"])].append(ev["id"])
    clusters = [sorted(g) for g in groups.values() if len(g) > 1]
    return {"links": links, "shared_indicators": shared_indicators, "recurring_tactics": recurring, "clusters": clusters}


def build_timeline(evidence: list[dict]) -> dict:
    """evidence: [{id, label, submitted_at, metadata:{...}, messages:[{index,sender,timestamp,text,tactics,stage}], tactics}]

    Each event records where its time came from:
      content  – timestamp written inside the evidence (as stated, unverified)
      metadata – file metadata such as EXIF or e-mail Date header (can be altered by the source)
      system   – time MIRGAB received the evidence (reliable, but not the time of the incident)
    """
    events, undated = [], []
    for ev in evidence:
        msgs = ev.get("messages") or []
        for m in msgs:
            item = {"evidence_id": ev["id"], "evidence_label": ev.get("label"), "message_index": m["index"],
                    "sender": m.get("sender"), "text": (m.get("text") or "")[:280], "tactics": m.get("tactics", []),
                    "stage": m.get("stage")}
            if m.get("timestamp"):
                events.append({**item, "time": m["timestamp"], "time_source": "content"})
            else:
                undated.append(item)
        meta_time = (ev.get("metadata") or {}).get("event_time")
        if meta_time:
            events.append({"evidence_id": ev["id"], "evidence_label": ev.get("label"), "time": meta_time,
                           "time_source": "metadata", "text": (ev.get("metadata") or {}).get("event_time_label", "File/e-mail timestamp"),
                           "tactics": [] if msgs else ev.get("tactics", []), "stage": None})
        if not msgs and not meta_time:
            undated.append({"evidence_id": ev["id"], "evidence_label": ev.get("label"),
                            "text": None, "tactics": ev.get("tactics", []),
                            "received_at": ev.get("submitted_at")})
    events.sort(key=lambda e: e["time"])
    # Reconstruct the progression of the incident across all evidence
    stage_first = {}
    for e in events:
        for t in e.get("tactics", []):
            st = TACTICS[t].stage
            stage_first.setdefault(st, e["time"])
    progression = [{"stage": s, "first_seen": stage_first[s]} for s in STAGE_ORDER if s in stage_first]
    span = {"start": events[0]["time"], "end": events[-1]["time"]} if events else None
    return {"events": events, "undated": undated, "progression": progression, "span": span}
