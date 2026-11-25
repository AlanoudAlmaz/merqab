"""Investigation engine (pure functions) and community-intelligence privacy helpers."""
from pathlib import Path

from ai.investigation.correlation import build_timeline, correlate
from ai.investigation.email_parser import parse_eml
from ai.investigation.indicators import extract_indicators
from ai.threat_intelligence.community import anonymize, build_alert_draft, residual_pii

SAMPLES = Path(__file__).resolve().parents[1] / "sample_data"


def test_indicator_extraction_normalises_values():
    text = ("Call +971 50 123 4567 or 050-123-4567, mail pay@scam-example.top, IBAN AE07 0331 2345 6789 0123 456, "
            "wallet 0x52908400098527886E0F7030069857D2E4169EE7, card 4111 1111 1111 1111, pay 14 AED, link http://bad-site.xyz/p")
    inds = extract_indicators(text)
    by = {(i["type"], i["value"]) for i in inds}
    assert ("phone", "+971501234567") in by
    assert sum(1 for t, _ in by if t == "phone") == 1  # both spellings normalise to one value
    assert ("email", "pay@scam-example.top") in by
    assert ("bank_account", "AE070331234567890123456") in by
    assert ("card", "card:1111") in by  # never the full card number
    assert not any("4111111111111111" in v for _, v in by)
    assert ("domain", "bad-site.xyz") in by
    assert ("amount", "AED 14") in by


def test_dates_are_not_phone_numbers():
    assert not [i for i in extract_indicators("Meeting on 20261102 at 10") if i["type"] == "phone"]


def test_correlation_links_shared_indicators_and_tactics():
    ev = [
        {"id": 1, "indicators": [{"type": "domain", "value": "x.top", "display": "x[.]top"}], "tactics": ["urgency", "payment_instruction"]},
        {"id": 2, "indicators": [{"type": "domain", "value": "x.top", "display": "x[.]top"}], "tactics": ["urgency"]},
        {"id": 3, "indicators": [], "tactics": ["urgency", "payment_instruction"]},
        {"id": 4, "indicators": [], "tactics": []},
    ]
    c = correlate(ev)
    links = {(l["a"], l["b"]): l for l in c["links"]}
    assert links[(1, 2)]["strength"] == "strong"
    assert links[(1, 3)]["strength"] == "behavioural"
    assert (1, 4) not in links
    assert [1, 2] in c["clusters"]
    assert c["recurring_tactics"][0]["tactic"] == "urgency"


def test_timeline_orders_and_labels_time_sources():
    ev = [
        {"id": 1, "label": "chat", "messages": [
            {"index": 0, "sender": "A", "timestamp": "2026-11-02T09:18", "text": "pay", "tactics": ["payment_instruction"]},
            {"index": 1, "sender": "A", "timestamp": "2026-11-02T09:14", "text": "hi from bank", "tactics": ["authority_impersonation"]},
            {"index": 2, "sender": "A", "timestamp": None, "text": "no time", "tactics": []}]},
        {"id": 2, "label": "mail", "metadata": {"event_time": "2026-11-02T10:05"}, "tactics": ["urgency"]},
        {"id": 3, "label": "sms", "tactics": ["urgency"], "submitted_at": "2026-11-03T00:00:00+00:00"},
    ]
    tl = build_timeline(ev)
    assert [e["time"] for e in tl["events"]] == ["2026-11-02T09:14", "2026-11-02T09:18", "2026-11-02T10:05"]
    assert tl["events"][0]["time_source"] == "content" and tl["events"][2]["time_source"] == "metadata"
    assert len(tl["undated"]) == 2
    assert [p["stage"] for p in tl["progression"]] == ["pretext", "pressure", "extraction"]


def test_email_header_analysis():
    e = parse_eml((SAMPLES / "phishing_email.eml").read_bytes())
    keys = {s["key"] for s in e["header_signals"]}
    assert {"reply_to_mismatch", "display_name_spoof", "spf_fail", "dmarc_fail"} <= keys
    assert e["event_time"] == "2026-11-02T10:05"
    assert "customs fee" in e["text"]


def test_anonymize_removes_personal_data():
    raw = ("Dear Ahmed Ali, call me on +971 50 123 4567 or mail ahmed@example.com. IBAN AE070331234567890123456. "
           "ID 784-1990-1234567-1. Code 482913. عزيزي محمد، link https://bad.example.top/track?id=me@x.com")
    out = anonymize(raw)
    for leaked in ("Ahmed", "4567", "ahmed@example.com", "AE0703", "784-1990", "482913", "محمد", "id=me"):
        assert leaked not in out, leaked
    assert "[PHONE]" in out and "[EMAIL]" in out and "hxxps://bad[.]example[.]top/…" in out
    assert residual_pii(out) == []
    assert "email" in residual_pii("contact x@y.com")


def test_alert_draft_is_bilingual_and_actionable():
    d = build_alert_draft("parcel_fee", ["payment_instruction", "urgency", "link_prompt"], ["bad.top"])
    assert d["title_en"].startswith("Warning") and d["title_ar"].startswith("تحذير")
    assert d["signs"] and all(s["en"] and s["ar"] for s in d["signs"])
    assert any("money" in a["en"].lower() for a in d["actions"])
    assert d["indicators"] == [{"type": "domain", "value": "bad.top"}]


def test_numbers_inside_urls_ids_and_timestamps_are_not_phones():
    """Regression: radar snapshots produced fake phone indicators from URL paths and log entry numbers."""
    text = ('https://www.roblox.com.am/users/36707123404/profile | evidence {"entry_index": 1234567890} '
            'certificate 2026-11-19T21:22 | ref 784199012345671')
    assert [i for i in extract_indicators(text) if i["type"] == "phone"] == []
