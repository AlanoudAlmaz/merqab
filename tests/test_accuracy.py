"""Detection-accuracy benchmark: reproducible, held-out, and served honestly."""
import json
from pathlib import Path

from ai.behavioral_analysis.url_analyzer import analyze_url
from ai.eval.run import run
from ai.pipeline import analyze

ROOT = Path(__file__).resolve().parents[1]


def test_recorded_results_are_reproducible():
    rec = json.loads((ROOT / "ai" / "eval" / "results.json").read_text(encoding="utf-8"))
    now = run("test")
    assert now["overall"] == rec["overall"], "engine changed: re-run `python -m ai.eval.run` and commit results.json"
    for a, b in zip(now["sets"], rec["sets"]):
        assert (a["tp"], a["fp"], a["tn"], a["fn"]) == (b["tp"], b["fp"], b["tn"], b["fn"])


def test_dev_and_test_splits_do_not_overlap():
    ds = ROOT / "ai" / "eval" / "datasets"
    for stem in ("urls", "uci_sms"):
        dev = set((ds / f"{stem}_dev.tsv").read_text(encoding="utf-8").splitlines())
        test = set((ds / f"{stem}_test.tsv").read_text(encoding="utf-8").splitlines())
        assert dev and test and not (dev & test - {""})


def test_accuracy_api(client):
    r = client.get("/api/accuracy").json()
    assert r["overall"]["n"] > 3500 and {s["key"] for s in r["sets"]} == {"urls", "uae", "sms", "evasion"}
    assert r["baseline"]["sets"]["urls"]["recall"] < r["sets"][0]["recall"]
    live = client.post("/api/accuracy/run").json()
    assert live["live"] and live["matches_recorded"] and live["overall"] == r["overall"]


def test_url_signals_general_rules():
    assert analyze_url("https://google.de/").level == "low"                      # a brand's real country site
    assert analyze_url("https://amazon.co.jp/").level == "low"
    assert analyze_url("https://roblox.com.kz/users/1/profile").level != "low"    # brand without country sites
    r = analyze_url("https://lh4ml-gco-36ng-wsd06-17-10-2026-aa.pages.dev/")
    assert {s.key for s in r.signals} >= {"free_hosting", "generated_name"} and r.level != "low"
    assert analyze_url("https://johnsmith.github.io/").level == "low"             # ordinary free-hosted page
    assert "email_prefilled" in {s.key for s in analyze_url("https://x.example/login.php?email=a@b.com").signals}
    assert "brand_in_path" in {s.key for s in analyze_url("https://someone.github.io/netflix/").signals}
    assert analyze_url("https://mail.ru/").level == "low"                         # short words aren't typo-squats


def test_premium_rate_trap():
    r = analyze("text", "You have won a prize! Call 09058094599 now to claim. Calls 150p/min")
    assert "premium_rate" in {b["key"] for b in r["risk"]["breakdown"]} and r["risk"]["level"] != "low"
    assert analyze("text", "Call me on 0501234567 when you land")["risk"]["level"] == "low"
