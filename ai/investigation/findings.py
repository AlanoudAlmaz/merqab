"""Turn analysis output into reviewable investigation findings.

Categories (never mixed):
  observed  – literally present in the evidence (quotes, indicators, header facts)
  indicator – a rule matched a known risk signal
  inference – heuristic or AI interpretation; must be reviewed by a human
A finding only becomes *verified* when an investigator marks it so (handled by the API).
"""
from __future__ import annotations

import hashlib

from ai.behavioral_analysis.tactics import TACTICS

_TYPE_AR = {"domain": "نطاق", "url": "رابط", "email": "بريد إلكتروني", "phone": "رقم هاتف", "bank_account": "حساب بنكي",
            "wallet": "محفظة رقمية", "card": "بطاقة", "amount": "مبلغ"}


def _fp(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:24]


def generate_findings(evidence: list[dict], correlation: dict, timeline: dict) -> list[dict]:
    """evidence: [{id, label, analysis, indicators, header_signals}]"""
    out: list[dict] = []
    for ev in evidence:
        a = ev.get("analysis") or {}
        for ind in a.get("indicators", []):
            quotes = [a["observed"][i]["quote"] for i in ind.get("evidence_refs", []) if i < len(a.get("observed", []))]
            quote = quotes[0] if quotes else ind.get("quote")
            src = "rule" if ind["source"] == "rule" else "llm"
            cat = "indicator" if src == "rule" else "inference"
            out.append({
                "fingerprint": _fp(ev["id"], "tactic", ind["key"], src), "category": cat, "source": src,
                "evidence_ids": [ev["id"]],
                "statement_en": f"{ev['label']}: {ind['label_en']}" + (f' — "{quote[:120]}"' if quote else ""),
                "statement_ar": f"{ev['label']}: {ind['label_ar']}" + (f' — "{quote[:120]}"' if quote else ""),
            })
        for u in a.get("urls", []):
            if u["score"] >= 20:
                sig = "; ".join(s["en"] for s in u["signals"][:3])
                sig_ar = "؛ ".join(s["ar"] for s in u["signals"][:3])
                out.append({"fingerprint": _fp(ev["id"], "url", u["defanged"]), "category": "indicator", "source": "rule",
                            "evidence_ids": [ev["id"]],
                            "statement_en": f"{ev['label']}: link {u['defanged']} rated {u['level']} ({sig}).",
                            "statement_ar": f"{ev['label']}: الرابط {u['defanged']} بمستوى {u['level']} ({sig_ar})."})
        for s in ev.get("header_signals", []):
            out.append({"fingerprint": _fp(ev["id"], "hdr", s["key"]), "category": "observed", "source": "rule",
                        "evidence_ids": [ev["id"]], "statement_en": f"{ev['label']}: {s['en']}",
                        "statement_ar": f"{ev['label']}: {s['ar']}"})
        for inf in a.get("inferences", []):
            if inf["type"] == "pattern":
                out.append({"fingerprint": _fp(ev["id"], "pattern", inf["key"]), "category": "inference", "source": "heuristic",
                            "evidence_ids": [ev["id"]], "statement_en": f"{ev['label']}: {inf['en']}",
                            "statement_ar": f"{ev['label']}: {inf['ar']}"})
            elif inf["type"] == "summary" and inf.get("en"):
                out.append({"fingerprint": _fp(ev["id"], "llm_summary"), "category": "inference", "source": "llm",
                            "evidence_ids": [ev["id"]], "statement_en": f"{ev['label']} (AI summary): {inf['en']}",
                            "statement_ar": f"{ev['label']} (ملخص الذكاء الاصطناعي): {inf.get('ar') or inf['en']}"})
    for si in correlation.get("shared_indicators", []):
        if si["strength"] != "strong":
            continue
        ids = si["evidence_ids"]
        out.append({"fingerprint": _fp("shared", si["type"], si["value"]), "category": "observed", "source": "rule",
                    "evidence_ids": ids,
                    "statement_en": f"The same {si['type'].replace('_', ' ')} ({si['display']}) appears in {len(ids)} evidence items.",
                    "statement_ar": f"يظهر نفس {_TYPE_AR.get(si['type'], si['type'])} ({si['display']}) في {len(ids)} من عناصر الأدلة."})
    for rt in correlation.get("recurring_tactics", []):
        out.append({"fingerprint": _fp("recurring", rt["tactic"]), "category": "indicator", "source": "rule",
                    "evidence_ids": rt["evidence_ids"],
                    "statement_en": f"Recurring tactic across {len(rt['evidence_ids'])} items: {rt['label_en']}.",
                    "statement_ar": f"أسلوب متكرر عبر {len(rt['evidence_ids'])} عناصر: {rt['label_ar']}."})
    prog = timeline.get("progression", [])
    if len(prog) >= 2:
        path = " → ".join(p["stage"] for p in prog)
        out.append({"fingerprint": _fp("progression", path), "category": "inference", "source": "heuristic",
                    "evidence_ids": sorted({e["evidence_id"] for e in timeline.get("events", [])}),
                    "statement_en": f"Timestamps (as stated in evidence) suggest the incident escalated: {path}.",
                    "statement_ar": f"تشير الطوابع الزمنية (كما وردت في الأدلة) إلى تصاعد الحادثة: {path}."})
    return out


def tactic_label(key: str, lang: str = "en") -> str:
    t = TACTICS.get(key)
    return (t.label_ar if lang == "ar" else t.label_en) if t else key
