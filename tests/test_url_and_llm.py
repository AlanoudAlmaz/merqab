"""URL analysis and the optional LLM layer (grounding, injection resistance, fallback)."""
import json

import httpx
import pytest

from ai.behavioral_analysis.url_analyzer import analyze_url, extract_urls, registrable_domain
from ai.llm.provider import AnthropicProvider, LLMProvider, ground
from ai.pipeline import analyze


@pytest.mark.parametrize("url,min_level,signal", [
    ("http://paypa1-login.xyz/verify", "high", "typosquat"),
    ("https://xn--pple-43d.com", "high", "typosquat"),
    ("http://192.168.4.3:8080/login.apk", "critical", "dangerous_download"),
    ("https://paypal.com.secure-login.xyz/", "medium", "brand_lookalike"),
    ("bit.ly/abc123", "medium", "shortener"),
    ("https://www.google.com@evil.example/", "medium", "userinfo"),
])
def test_risky_urls(url, min_level, signal):
    order = ["low", "medium", "high", "critical"]
    r = analyze_url(url)
    assert order.index(r.level) >= order.index(min_level), (url, r.to_dict())
    assert signal in {s.key for s in r.signals}


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://amazon.ae/orders", "https://www.emiratesnbd.com/en",
                                 "https://en.wikipedia.org/wiki/Phishing", "https://www.pineapple-recipes.com/"])
def test_benign_urls_low(url):
    r = analyze_url(url)
    assert r.level == "low", r.to_dict()


def test_registrable_domain_handles_second_level_suffixes():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("login.alrajhibank.com.sa") == "alrajhibank.com.sa"
    assert registrable_domain("x.y.example.com") == "example.com"


def test_extract_urls_refangs_and_ignores_filenames():
    urls = extract_urls("visit hxxp://bad[.]example[.]com/x and see report.pdf or www.site.org")
    assert any("bad" in u for u in urls) and "report.pdf" not in urls and "www.site.org" in urls


# ---------------------------------------------------------------- LLM grounding
SRC = "This is your bank. Send me the OTP now or your account will be blocked."


def test_grounding_keeps_only_quotes_present_in_source():
    out = json.dumps({"tactics": [
        {"key": "credential_request", "quote": "Send me the OTP now"},
        {"key": "threat_fear", "quote": "we will arrest you"},          # hallucinated quote
        {"key": "made_up_tactic", "quote": "This is your bank"},        # not in taxonomy
    ], "summary_en": "Bank impersonation asking for OTP.", "summary_ar": "انتحال بنك", "likely_goal": "share_credentials", "confidence": "high"})
    r = ground(out, SRC)
    assert r.status == "used"
    assert [g["key"] for g in r.grounded_tactics] == ["credential_request"]
    assert r.rejected_claims == 2


def test_grounding_rejects_non_json():
    assert ground("Sure! It is a scam.", SRC).status == "failed"


class FakeLLM(LLMProvider):
    name = "fake"

    def __init__(self, payload):
        self.payload = payload

    def available(self):
        return True

    def analyze(self, text):
        return ground(json.dumps(self.payload), text, "fake")


def test_llm_cannot_lower_deterministic_score():
    rules_only = analyze("text", SRC)
    llm = FakeLLM({"tactics": [], "summary_en": "This message is safe.", "confidence": "high"})
    with_llm = analyze("text", SRC, llm)
    assert with_llm["risk"]["score"] == rules_only["risk"]["score"]
    assert with_llm["engine"]["llm"]["status"] == "used"


def test_llm_grounded_extra_tactic_is_labelled_inference():
    text = "Hello dear, I am a widow with a large inheritance and need your help moving it abroad."
    llm = FakeLLM({"tactics": [{"key": "reward_lure", "quote": "large inheritance"}], "summary_en": "Advance-fee style story."})
    r = analyze("text", text, llm)
    ai = [i for i in r["indicators"] if i["source"] == "ai_inference"]
    assert ai and ai[0]["key"] == "reward_lure"
    assert any(i["source"] == "ai_inference" and i["verified"] is False for i in r["inferences"])


def test_anthropic_provider_wraps_untrusted_content_and_parses_reply():
    seen = {}

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        seen["body"] = body
        assert req.headers["x-api-key"] == "k"
        reply = {"tactics": [{"key": "credential_request", "quote": "Send me the OTP now"}], "summary_en": "x", "summary_ar": "y"}
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(reply)}]})

    p = AnthropicProvider("k", "test-model", transport=httpx.MockTransport(handler))
    r = p.analyze(SRC)
    assert r.status == "used" and r.grounded_tactics[0]["key"] == "credential_request"
    user_msg = seen["body"]["messages"][0]["content"]
    assert user_msg.startswith("<<MIRQAB-") and SRC in user_msg
    assert "UNTRUSTED" in seen["body"]["system"]


def test_anthropic_provider_failure_falls_back():
    p = AnthropicProvider("k", "m", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    r = analyze("text", SRC, p)
    assert r["engine"]["llm"]["status"] == "failed"
    assert r["risk"]["level"] in ("high", "critical")


def test_radar_intelligence_weights_are_graded_and_unverified_is_labelled():
    from ai.risk_assessment.scoring import score
    def run(m):
        return score(set(), [], [], [], 80, False, [], "not_configured", None, [m])
    live = run({"host": "a.xyz", "confirmed": True, "active": True})
    gone = run({"host": "a.xyz", "confirmed": True, "active": False})
    sus = run({"host": "a.xyz", "confirmed": False})
    pred = run({"host": "a.xyz", "confirmed": False, "predicted": True})
    assert [r.breakdown[0]["points"] for r in (live, gone, sus, pred)] == [40, 25, 20, 10]
    unverified = lambda r: any("not yet confirmed" in u["en"] for u in r.uncertainty)
    assert not unverified(live) and unverified(sus) and unverified(pred)
