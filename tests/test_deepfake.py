import io, json
import httpx
import pytest
from fastapi.testclient import TestClient

from ai.deepfake import provenance, vision_review
from backend.app.main import create_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from tests.conftest import make_settings
    return TestClient(create_app(make_settings(tmp_path)))


def test_provenance_detects_generator_and_declaration():
    r = provenance(PNG + b"tEXtparameters\x00a cat, Steps: 20, Sampler: Euler", "image")
    assert r["verdict"] == "ai_markers" and any("Stable Diffusion" in t for f in r["findings"] for t in f.get("tools", []))
    r = provenance(JPG + b"http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia", "image")
    assert r["verdict"] == "declared_ai"
    r = provenance(JPG, "image")
    assert r["verdict"] == "no_markers" and r["findings"][0]["key"] == "stripped"


def test_scan_endpoint_validates_and_never_says_real(client):
    r = client.post("/api/deepfake/scan", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert r.status_code == 415
    r = client.post("/api/deepfake/scan", files={"file": ("fake.png", b"not a png", "image/png")})
    assert r.status_code == 415
    r = client.post("/api/deepfake/scan", files={"file": ("a.png", PNG, "image/png")})
    body = r.json()
    assert r.status_code == 200 and body["level"] == "unknown" and body["stored"] is False
    assert body["ai_review"]["status"] == "not_configured"
    assert "real" not in json.dumps(body["provenance"]).lower().replace("proves nothing", "")


def test_vision_review_parses_and_hides_errors(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
    ok = httpx.MockTransport(lambda req: httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
        {"assessment": "likely_ai", "signs": [{"en": "six fingers", "ar": "ستة أصابع"}], "confidence": "medium"})}}]}))
    r = vision_review(PNG, "image/png", transport=ok)
    assert r["status"] == "used" and r["assessment"] == "likely_ai" and r["signs"][0]["en"] == "six fingers"
    bad = httpx.MockTransport(lambda req: httpx.Response(401, json={"error": "sk-test-secret invalid"}))
    r = vision_review(PNG, "image/png", transport=bad)
    assert r["status"] == "failed" and "sk-test" not in json.dumps(r)


def test_openai_provider_is_grounded():
    from ai.llm.provider import OpenAIProvider
    text = "URGENT: your account is locked, send the OTP now"
    t = httpx.MockTransport(lambda req: httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
        {"tactics": [{"key": "urgency", "quote": "URGENT"}, {"key": "urgency", "quote": "not in text"}], "confidence": "high"})}}]}))
    r = OpenAIProvider("k", "gpt-4o-mini", transport=t).analyze(text)
    assert r.status == "used" and r.provider == "openai" and [g["key"] for g in r.grounded_tactics] == ["urgency"]


@pytest.mark.parametrize("name,verdict", [
    ("1-stable-diffusion.png", "ai_markers"), ("2-declared-ai.jpg", "declared_ai"), ("3-camera-metadata.jpg", "no_markers"),
    ("4-no-metadata.jpg", "no_markers"), ("5-voice-tagged.mp3", "ai_markers"), ("6-voice-note-plain.mp3", "no_markers")])
def test_sample_files_give_documented_results(client, name, verdict):
    from pathlib import Path
    data = (Path(__file__).resolve().parents[1] / "sample_data" / "deepfake" / name).read_bytes()
    r = client.post("/api/deepfake/scan", files={"file": (name, data)})
    assert r.status_code == 200 and r.json()["provenance"]["verdict"] == verdict
