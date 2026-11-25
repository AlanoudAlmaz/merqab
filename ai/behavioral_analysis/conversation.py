"""Multi-stage conversation understanding.

Parses pasted chat transcripts (WhatsApp-style exports, "[time] Name: text", "Name: text" or
blank-line separated messages) and tracks how manipulation escalates across messages.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from ai.behavioral_analysis.analyzer import TextAnalysis, analyze_text
from ai.behavioral_analysis.tactics import STAGE_ORDER, TACTICS

_LINE_PATTERNS = [
    # [2026-11-01 10:23] Name: text   |  [01/11/2026, 10:23:11] Name: text
    re.compile(r"^\[(?P<ts>[^\]]{6,25})\]\s*(?P<sender>[^:]{1,40}):\s?(?P<text>.*)$"),
    # 01/11/2026, 10:23 - Name: text   (WhatsApp export)
    re.compile(r"^(?P<ts>\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?|ص|م)?)\s*[-–]\s*(?P<sender>[^:]{1,40}):\s?(?P<text>.*)$", re.I),
    # 2026-11-01 10:23 Name: text
    re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)\s+(?P<sender>[^:]{1,40}):\s?(?P<text>.*)$"),
    # Name: text
    re.compile(r"^(?P<sender>[^\s:][^:]{0,30}):\s(?P<text>.+)$"),
]

_TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
               "%d/%m/%Y, %H:%M:%S", "%d/%m/%Y, %H:%M", "%d/%m/%Y %H:%M", "%d/%m/%y, %H:%M", "%d/%m/%y %H:%M",
               "%d.%m.%Y, %H:%M", "%m/%d/%y, %I:%M %p", "%m/%d/%Y, %I:%M %p", "%d/%m/%Y, %I:%M %p"]


def parse_timestamp(raw: str) -> str | None:
    """Return ISO-8601 (no timezone: as stated in evidence) or None. Day-first is assumed for
    ambiguous numeric dates (common in the region); this assumption is reported as a limitation."""
    s = raw.strip().replace(" ", " ").replace("ص", "AM").replace("م", "PM")
    s = re.sub(r"\s+", " ", s).replace("a.m.", "AM").replace("p.m.", "PM")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s.upper() if "%p" in fmt else s, fmt).isoformat(timespec="minutes")
        except ValueError:
            continue
    return None


@dataclass
class Message:
    index: int
    sender: str | None
    text: str
    timestamp_raw: str | None = None
    timestamp: str | None = None
    analysis: TextAnalysis | None = None

    @property
    def stage(self) -> str | None:
        if not self.analysis or not self.analysis.hits:
            return None
        stages = {TACTICS[h.tactic].stage for h in self.analysis.hits}
        return max(stages, key=STAGE_ORDER.index)


def parse_conversation(raw: str) -> list[Message]:
    lines = [l.rstrip() for l in raw.replace("\r\n", "\n").split("\n")]
    structured = sum(1 for l in lines if l.strip() and any(p.match(l.strip()) for p in _LINE_PATTERNS))
    msgs: list[Message] = []
    if structured >= max(1, len([l for l in lines if l.strip()]) // 2):
        for line in lines:
            ls = line.strip()
            if not ls:
                continue
            m = next((p.match(ls) for p in _LINE_PATTERNS if p.match(ls)), None)
            if m:
                gd = m.groupdict()
                ts_raw = gd.get("ts")
                msgs.append(Message(len(msgs), gd["sender"].strip(), gd["text"].strip(), ts_raw,
                                    parse_timestamp(ts_raw) if ts_raw else None))
            elif msgs:  # continuation line
                msgs[-1].text += "\n" + ls
            else:
                msgs.append(Message(0, None, ls))
    else:
        blocks = [b.strip() for b in re.split(r"\n\s*\n", raw) if b.strip()]
        if len(blocks) <= 1:
            blocks = [l.strip() for l in lines if l.strip()]
        msgs = [Message(i, None, b) for i, b in enumerate(blocks)]
    for m in msgs:
        m.analysis = analyze_text(m.text, message_index=m.index)
    return msgs


@dataclass
class ConversationAssessment:
    messages: list[Message]
    stages_reached: list[str] = field(default_factory=list)
    current_stage: str | None = None
    escalation: bool = False
    escalation_path: list[dict] = field(default_factory=list)
    senders: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "message_count": len(self.messages),
            "stages_reached": self.stages_reached,
            "current_stage": self.current_stage,
            "escalation": self.escalation,
            "escalation_path": self.escalation_path,
            "tactics_by_sender": self.senders,
            "messages": [
                {"index": m.index, "sender": m.sender, "timestamp": m.timestamp, "timestamp_raw": m.timestamp_raw,
                 "text": m.text, "stage": m.stage, "tactics": sorted(m.analysis.tactics) if m.analysis else []}
                for m in self.messages
            ],
        }


def assess_conversation(messages: list[Message]) -> ConversationAssessment:
    ca = ConversationAssessment(messages)
    first_idx: dict[str, int] = {}
    for m in messages:
        for h in (m.analysis.hits if m.analysis else []):
            first_idx.setdefault(TACTICS[h.tactic].stage, m.index)
        if m.analysis and m.analysis.hits:
            key = m.sender or "unknown"
            ca.senders.setdefault(key, [])
            for t in sorted(m.analysis.tactics):
                if t not in ca.senders[key]:
                    ca.senders[key].append(t)
    ca.stages_reached = [s for s in STAGE_ORDER if s in first_idx]
    ca.escalation_path = [{"stage": s, "first_message": first_idx[s]} for s in ca.stages_reached]
    # Escalation: the conversation moves from story-building/pressure to an explicit harmful request later on.
    if "extraction" in first_idx:
        earlier = [first_idx[s] for s in ("pretext", "pressure") if s in first_idx]
        ca.escalation = bool(earlier) and min(earlier) < first_idx["extraction"]
    recent = [m.stage for m in messages[-3:] if m.stage]
    ca.current_stage = max(recent, key=STAGE_ORDER.index) if recent else (ca.stages_reached[-1] if ca.stages_reached else None)
    return ca
