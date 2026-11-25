"""API: prevention, investigation workflow, reports, community validation loop."""
import io
import json

from PIL import Image, ImageDraw

from tests.conftest import SAMPLES, auth


# ---------------------------------------------------------------- prevention
def test_analyze_text_and_feedback(client, app):
    r = client.post("/api/analyze", json={"kind": "text", "content": "Your account will be blocked. Send the OTP now."})
    assert r.status_code == 200
    body = r.json()
    assert body["risk"]["level"] in ("high", "critical")
    aid = body["analysis_id"]
    assert client.post(f"/api/analyze/{aid}/feedback", json={"verdict": "incorrect"}).status_code == 200
    assert client.post(f"/api/analyze/{aid}/feedback", json={"verdict": "helpful"}).status_code == 409
    # data minimisation: submitted text is not stored by default
    c = app.state.connect()
    assert c.execute("SELECT input_text FROM analyses WHERE id=?", (aid,)).fetchone()[0] is None
    assert client.get("/api/community/impact").json()["analysis_feedback"]["incorrect"] == 1


def test_analyze_url(client):
    r = client.post("/api/analyze", json={"kind": "url", "content": "http://paypa1-login.xyz/verify"}).json()
    assert r["urls"][0]["impersonated_brand"] == "paypal" and r["risk"]["level"] in ("high", "critical")


def test_analyze_validation_errors(client):
    assert client.post("/api/analyze", json={"kind": "text", "content": ""}).status_code == 422
    assert client.post("/api/analyze", json={"kind": "video", "content": "x"}).status_code == 422
    assert client.post("/api/analyze", json={"kind": "text", "content": "x" * 20001}).status_code == 422
    assert client.post("/api/analyze", json={"kind": "text", "content": "   "}).status_code == 422


def _png_with_text(text):
    img = Image.new("RGB", (900, 160), "white")
    from PIL import ImageFont
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 30)
    except OSError:
        font = ImageFont.load_default()
    ImageDraw.Draw(img).text((20, 50), text, fill="black", font=font)
    b = io.BytesIO()
    img.save(b, "PNG")
    return b.getvalue()


def test_analyze_screenshot_ocr_or_honest_fallback(client):
    data = _png_with_text("URGENT: send me the OTP code now")
    r = client.post("/api/analyze/file", files={"file": ("shot.png", data, "image/png")}).json()
    caps = client.get("/api/capabilities").json()
    if caps["ocr"]["status"] == "available":
        assert r["extracted"] and "credential_request" in {i["key"] for i in r["result"]["indicators"]}
    else:
        assert r["extracted"] is False and "OCR" in r["note"]


def test_analyze_eml_file(client):
    eml = (SAMPLES / "phishing_email.eml").read_bytes()
    r = client.post("/api/analyze/file", files={"file": ("m.eml", eml)}).json()
    assert r["extracted"] and r["header_signals"]
    assert r["result"]["risk"]["level"] in ("high", "critical")


# ---------------------------------------------------------------- investigation
def test_case_workflow_correlation_timeline_findings(client, inv, demo_case):
    a = client.get(f"/api/cases/{demo_case}/analysis", headers=inv).json()
    assert a["summary"]["highest_risk"] == "critical"
    assert a["summary"]["patterns"][0]["key"] == "parcel_fee"
    shared = {(s["type"], s["value"]) for s in a["correlation"]["shared_indicators"]}
    assert ("domain", "aramex-delivery-ae.top") in shared
    assert ("phone", "+971501234567") in shared
    assert a["timeline"]["events"][0]["time"] == "2026-11-02T09:14"
    assert a["timeline"]["span"]["end"] == "2026-11-02T10:05"
    fs = client.get(f"/api/cases/{demo_case}/findings", headers=inv).json()
    cats = {f["category"] for f in fs}
    assert {"observed", "indicator", "inference"} <= cats
    assert all(f["status"] == "unreviewed" for f in fs)  # nothing is verified automatically


def test_inference_verification_requires_note_and_survives_reanalysis(client, inv, demo_case):
    fs = client.get(f"/api/cases/{demo_case}/findings", headers=inv).json()
    inf = next(f for f in fs if f["category"] == "inference")
    assert client.patch(f"/api/findings/{inf['id']}", json={"status": "verified"}, headers=inv).status_code == 422
    assert client.patch(f"/api/findings/{inf['id']}", json={"status": "verified", "note": "Matches E1 messages"}, headers=inv).status_code == 200
    client.post(f"/api/cases/{demo_case}/analyze", headers=inv)
    again = {f["id"]: f for f in client.get(f"/api/cases/{demo_case}/findings", headers=inv).json()}
    assert again[inf["id"]]["status"] == "verified"


def test_cross_case_correlation(client, inv, demo_case):
    cid = client.post("/api/cases", json={"title": "Second report"}, headers=inv).json()["id"]
    client.post(f"/api/cases/{cid}/evidence/text", json={"kind": "text", "label": "sms", "content": "Pay now http://aramex-delivery-ae.top/x"}, headers=inv)
    a = client.post(f"/api/cases/{cid}/analyze", headers=inv).json()
    assert any(x["case_id"] == demo_case and x["indicator_type"] == "domain" for x in a["cross_case"])


def test_evidence_integrity_and_immutability(client, inv, demo_case, app):
    case = client.get(f"/api/cases/{demo_case}", headers=inv).json()
    ev = case["evidence"][0]
    assert client.get(f"/api/evidence/{ev['id']}/verify", headers=inv).json()["intact"] is True
    # Simulate tampering on disk -> detected
    c = app.state.connect()
    rel = c.execute("SELECT storage_path FROM evidence WHERE id=?", (ev["id"],)).fetchone()[0]
    p = app.state.settings.evidence_dir / rel
    p.chmod(0o600)
    p.write_bytes(p.read_bytes() + b"x")
    assert client.get(f"/api/evidence/{ev['id']}/verify", headers=inv).json()["intact"] is False
    # no update/delete routes exist for evidence
    assert client.delete(f"/api/evidence/{ev['id']}", headers=inv).status_code in (404, 405)
    assert client.patch(f"/api/evidence/{ev['id']}", json={}, headers=inv).status_code in (404, 405)


def test_evidence_download_is_opaque_attachment(client, inv, demo_case):
    ev = client.get(f"/api/cases/{demo_case}", headers=inv).json()["evidence"][-1]
    r = client.get(f"/api/evidence/{ev['id']}/download", headers=inv)
    assert r.headers["content-type"] == "application/octet-stream"
    assert "attachment" in r.headers["content-disposition"]


def test_report_export_formats(client, inv, demo_case):
    md = client.get(f"/api/cases/{demo_case}/report?format=md", headers=inv)
    assert md.status_code == 200 and "## Limitations" in md.text and "Chain of custody" in md.text and "intact" in md.text
    js = client.get(f"/api/cases/{demo_case}/report?format=json", headers=inv).json()
    assert js["findings"]["verified"] == [] and js["evidence"][0]["integrity"] is True
    assert any(a["action"] == "evidence.add" for a in js["chain_of_custody"])
    html = client.get(f"/api/cases/{demo_case}/report?format=html", headers=inv)
    assert html.text.startswith("<!DOCTYPE html>") and "<script" not in html.text


def test_report_html_escapes_evidence_content(client, inv):
    cid = client.post("/api/cases", json={"title": "<script>alert(1)</script> case"}, headers=inv).json()["id"]
    client.post(f"/api/cases/{cid}/evidence/text", json={"kind": "text", "label": "<img src=x onerror=alert(1)>", "content": "hello"}, headers=inv)
    html = client.get(f"/api/cases/{cid}/report?format=html", headers=inv).text
    assert "<script>alert" not in html and "<img src=x" not in html


def test_closed_case_is_read_only(client, inv):
    cid = client.post("/api/cases", json={"title": "Closed one"}, headers=inv).json()["id"]
    client.patch(f"/api/cases/{cid}", json={"status": "closed"}, headers=inv)
    r = client.post(f"/api/cases/{cid}/evidence/text", json={"kind": "text", "label": "x", "content": "y"}, headers=inv)
    assert r.status_code == 409


def test_analyze_empty_case_rejected(client, inv):
    cid = client.post("/api/cases", json={"title": "Empty"}, headers=inv).json()["id"]
    assert client.post(f"/api/cases/{cid}/analyze", headers=inv).status_code == 409


# ---------------------------------------------------------------- community loop
def _verify_one(client, inv, cid):
    f = next(f for f in client.get(f"/api/cases/{cid}/findings", headers=inv).json() if f["category"] == "observed")
    client.patch(f"/api/findings/{f['id']}", json={"status": "verified", "note": "checked"}, headers=inv)


CHECK = {"checklist": {"pii_removed": True, "evidence_supported": True, "guidance_accurate": True}}


def test_alert_requires_verified_finding(client, inv, demo_case):
    assert client.post(f"/api/cases/{demo_case}/alert-draft", headers=inv).status_code == 409


def test_full_validation_loop_feeds_prevention(client, inv, rev, demo_case):
    _verify_one(client, inv, demo_case)
    aid = client.post(f"/api/cases/{demo_case}/alert-draft", headers=inv).json()["id"]
    # draft is not public and does not influence prevention
    assert client.get("/api/community/alerts").json() == []
    probe = {"kind": "text", "content": "Pay here http://aramex-delivery-ae.top/x"}
    assert client.post("/api/analyze", json=probe).json()["community_matches"] == []
    # cannot approve a draft that was not submitted
    assert client.post(f"/api/community/alerts/{aid}/approve", json=CHECK, headers=rev).status_code == 409
    client.post(f"/api/community/alerts/{aid}/submit", headers=inv)
    # two-person rule: the author (even if promoted) cannot approve; investigators lack the role
    assert client.post(f"/api/community/alerts/{aid}/approve", json=CHECK, headers=inv).status_code == 403
    # checklist must be complete
    bad = {"checklist": {"pii_removed": True, "evidence_supported": False, "guidance_accurate": True}}
    assert client.post(f"/api/community/alerts/{aid}/approve", json=bad, headers=rev).status_code == 422
    assert client.post(f"/api/community/alerts/{aid}/approve", json=CHECK, headers=rev).status_code == 200
    pub = client.get("/api/community/alerts").json()
    assert len(pub) == 1 and "created_by" not in pub[0] and "source_case_id" not in pub[0]
    m = client.post("/api/analyze", json=probe).json()["community_matches"]
    assert m and m[0]["type"] == "indicator" and m[0]["alert_id"] == aid
    imp = client.get("/api/community/impact").json()
    assert imp["alerts_published"] == 1 and imp["community_warning_matches"] == 1
    # archived alerts stop influencing prevention
    client.post(f"/api/community/alerts/{aid}/archive", headers=rev)
    assert client.post("/api/analyze", json=probe).json()["community_matches"] == []


def test_pii_gate_blocks_publication(client, inv, rev, demo_case):
    _verify_one(client, inv, demo_case)
    aid = client.post(f"/api/cases/{demo_case}/alert-draft", headers=inv).json()["id"]
    client.patch(f"/api/community/alerts/{aid}", json={"summary_en": "Victim contact: victim@example.com called us"}, headers=inv)
    client.post(f"/api/community/alerts/{aid}/submit", headers=inv)
    r = client.post(f"/api/community/alerts/{aid}/approve", json=CHECK, headers=rev)
    assert r.status_code == 422 and "email" in r.json()["detail"]


def test_other_investigator_cannot_edit_someone_elses_draft(client, inv, demo_case):
    _verify_one(client, inv, demo_case)
    aid = client.post(f"/api/cases/{demo_case}/alert-draft", headers=inv).json()["id"]
    other = auth(client, "inv2")
    assert client.patch(f"/api/community/alerts/{aid}", json={"title_en": "Hijacked title here"}, headers=other).status_code == 403


def test_public_report_is_anonymised_and_unverified(client, rev):
    r = client.post("/api/community/reports", json={"text": "Dear Fatima, send OTP to +971 55 987 6543 or mail me at a@b.com now"})
    assert r.status_code == 201
    body = r.json()
    assert "+971" not in body["stored_text"] and "a@b.com" not in body["stored_text"] and "Fatima" not in body["stored_text"]
    assert body["status"] == "unverified"
    assert client.get("/api/community/alerts").json() == []  # never auto-published
    q = client.get("/api/community/review", headers=rev).json()
    assert q["reports"][0]["text_anonymized"] == body["stored_text"]


def test_family_shield_content_is_engine_backed_and_not_counted(client):
    before = client.get("/api/community/impact").json()["analyses_total"]
    d = client.get("/api/community/shield").json()
    from ai.behavioral_analysis.tactics import STAGE_ORDER, TACTICS
    assert [s["key"] for s in d["stages"]] == STAGE_ORDER
    assert sum(len(s["tactics"]) for s in d["stages"]) == len(TACTICS)  # every engine tactic is taught
    for p in d["practice"]:
        eng = p["engine"]
        # the engine agrees with every training label, and highlights are real spans in the text
        assert (eng["level"] in ("high", "critical")) == (p["truth"] == "scam"), p["id"]
        for hl in eng["highlights"]:
            a, b = hl["span"]
            assert 0 <= a < b <= len(p["text"])
    assert {a["key"] for a in d["audiences"]} == {"everyone", "seniors", "students", "families", "businesses"}
    assert isinstance(d["brands_now"], list) and d["brands_window_days"] == 7
    # practice analysis is never recorded as real usage
    assert client.get("/api/community/impact").json()["analyses_total"] == before
