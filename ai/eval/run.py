"""Reproducible detection-accuracy benchmark for MIRQAB.

    python -m ai.eval.run            # prints results and writes ai/eval/results.json

Datasets (ai/eval/datasets):
* urls_test.tsv — 150 live phishing URLs from the OpenPhish community feed (captured 24 Nov 2026) and 1,000 legitimate
  sites (every 5th domain of a public top-10,000 popularity list). Independent of MIRQAB.
* uci_sms_test.tsv — 2,787 SMS from the UCI SMS Spam Collection (Almeida & Hidalgo, CC BY 4.0). "spam" there includes
  plain marketing, which MIRQAB does not try to flag, so recall on this set understates fraud recall.
* uae_scenarios.tsv — 70 UAE messages (Arabic, Emirati dialect, English) written by the MIRQAB team from publicly
  reported UAE scam types, plus look-alike legitimate messages (real OTP texts, bank and delivery notices). It is
  team-authored, so treat it as indicative.

Each public dataset was split 50/50 with a fixed seed. Engine changes were tuned only on the *_dev files; the numbers
published in the app come from the *_test files and the UAE set, which were never used for tuning.
A message or link counts as "flagged" when MIRQAB's risk level is medium or higher (what the app shows as a warning).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ai.pipeline import analyze  # noqa: E402

DS = Path(__file__).resolve().parent / "datasets"
FLAG = {"medium", "high", "critical"}


def _read(name):
    out = []
    for line in (DS / name).read_text(encoding="utf-8").splitlines():
        if "\t" in line:
            lab, txt = line.split("\t", 1)
            out.append((lab.strip(), txt))
    return out


def _metrics(rows, kind, positive):
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    t0 = time.perf_counter()
    for lab, txt in rows:
        k = kind(txt) if callable(kind) else kind
        flagged = analyze(k, txt)["risk"]["level"] in FLAG
        pos = lab == positive
        if pos and flagged:
            tp += 1
        elif pos:
            fn += 1
            misses.append(txt[:140])
        elif flagged:
            fp += 1
            false_alarms.append(txt[:140])
        else:
            tn += 1
    ms = (time.perf_counter() - t0) * 1000 / max(1, len(rows))
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"n": len(rows), "positives": tp + fn, "negatives": tn + fp, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": round((tp + tn) / max(1, len(rows)), 4), "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0, "false_positive_rate": round(fp / max(1, tn + fp), 4),
            "ms_per_item": round(ms, 2), "examples_missed": misses[:5], "examples_false_alarm": false_alarms[:5]}


def _uae_kind(txt):
    return "text"


SETS = [
    ("urls", "urls_{split}.tsv", "url", "phish",
     {"en": "Live phishing links vs popular legitimate sites", "ar": "روابط تصيّد حيّة مقابل مواقع مشروعة شائعة"},
     {"en": "OpenPhish community feed (24 Nov 2026) + public top-10,000 domain list", "ar": "قائمة OpenPhish المجتمعية (24 نوفمبر 2026) + قائمة أشهر 10,000 نطاق"}),
    ("uae", "uae_scenarios.tsv", "text", "scam",
     {"en": "UAE scam scenarios (Arabic, Emirati, English)", "ar": "سيناريوهات احتيال إماراتية (عربي، إماراتي، إنجليزي)"},
     {"en": "Written by the MIRQAB team from publicly reported UAE scam types — indicative", "ar": "كتبها فريق مِرقاب من أنواع احتيال إماراتية مُبلّغ عنها علناً — مؤشر تقريبي"}),
    ("sms", "uci_sms_{split}.tsv", "text", "spam",
     {"en": "Public SMS spam benchmark (English)", "ar": "معيار رسائل SMS المزعجة العام (إنجليزي)"},
     {"en": "UCI SMS Spam Collection, CC BY 4.0 — 'spam' includes plain marketing", "ar": "مجموعة UCI لرسائل SMS المزعجة، CC BY 4.0 — تشمل إعلانات عادية"}),
]


def _evasion_rows(split: str):
    """Held-out phishing links disguised the way attackers do, plus legitimate links wrapped in a redirect
    (to measure false alarms). Built deterministically from the same test file — nothing new is fetched."""
    from urllib.parse import quote, urlsplit
    rows = []
    for lab, u in _read(f"urls_{split}.tsv"):
        if lab == "phish":
            p = urlsplit(u)
            rows.append(("phish", "https://www.google.com/url?q=" + quote(u, safe="")))                  # redirect wrapper
            rows.append(("phish", u.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(p.hostname or "", (p.hostname or "").replace(".", "[.]"))))  # defanged
            rows.append(("phish", u.replace(p.netloc, p.netloc.upper())))                                 # case games
        else:
            rows.append(("legit", "https://www.google.com/url?q=" + quote(u, safe="")))
    return rows


def run(split: str = "test") -> dict:
    out = {"generated": time.strftime("%Y-%m-%d"), "split": split, "flag_rule": "risk level >= medium", "sets": []}
    for key, fname, kind, pos, title, source in SETS:
        f = fname.format(split=split)
        if not (DS / f).exists():
            continue
        m = _metrics(_read(f), kind, pos)
        out["sets"].append({"key": key, "file": f, "title": title, "source": source, **m})
    if (DS / f"urls_{split}.tsv").exists():
        m = _metrics(_evasion_rows(split), "url", "phish")
        out["sets"].append({"key": "evasion", "file": f"urls_{split}.tsv (transformed)", "title": {
            "en": "Evasion: disguised phishing links (redirect wrapper, defanged, upper-case)", "ar": "التحايل: روابط تصيّد مموّهة (إعادة توجيه، تعطيل الرابط، أحرف كبيرة)"},
            "source": {"en": "The held-out OpenPhish links, each disguised 3 ways; legitimate sites wrapped in a Google redirect",
                       "ar": "روابط OpenPhish المحجوبة نفسها، كل رابط مموّه بثلاث طرق؛ ومواقع مشروعة داخل إعادة توجيه Google"}, **m})
    tot = {k: sum(s[k] for s in out["sets"] if s["key"] != "evasion") for k in ("tp", "fp", "tn", "fn", "n")}
    out["overall"] = {**tot, "accuracy": round((tot["tp"] + tot["tn"]) / max(1, tot["n"]), 4)}
    return out


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    res = run(split)
    for s in res["sets"]:
        print(f"{s['key']:5} n={s['n']:5} acc={s['accuracy']:.3f} prec={s['precision']:.3f} rec={s['recall']:.3f} "
              f"f1={s['f1']:.3f} fpr={s['false_positive_rate']:.3f} tp={s['tp']} fp={s['fp']} fn={s['fn']} tn={s['tn']}")
    if split == "test":
        f = Path(__file__).resolve().parent / "results.json"
        if f.exists():   # keep the recorded baseline (previous engine version) for the before/after comparison
            res["baseline"] = json.loads(f.read_text(encoding="utf-8")).get("baseline")
        f.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
