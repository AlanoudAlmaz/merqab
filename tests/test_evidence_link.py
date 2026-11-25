"""Evidence & takedown pack: RDAP registration, hosting, newly-registered flag, never opens the site."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest

import backend.app.api.evidence_link as ev


def _rdap(request: httpx.Request) -> httpx.Response:
    p = request.url.path
    assert request.url.host == "rdap.org"                       # only the RDAP service is contacted
    if p.startswith("/domain/"):
        created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        return httpx.Response(200, json={
            "events": [{"eventAction": "registration", "eventDate": created}, {"eventAction": "expiration", "eventDate": "2027-11-21T00:00:00Z"}],
            "status": ["client transfer prohibited"], "nameservers": [{"ldhName": "NS1.EXAMPLE-DNS.COM"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]],
                          "publicIds": [{"identifier": "9999"}],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]]}]}]})
    if p.startswith("/ip/"):
        return httpx.Response(200, json={"name": "HOSTCO-NET", "country": "NL", "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                                         "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@hostco.example"]]]}]})
    return httpx.Response(404)


@pytest.fixture(autouse=True)
def mock_net(monkeypatch):
    ev._cache.clear()
    monkeypatch.setattr(ev, "TRANSPORT", httpx.MockTransport(_rdap))
    monkeypatch.setattr(ev, "resolve", lambda host: ["185.199.108.153"])


def test_pack_has_registration_hosting_and_new_domain_flag(client):
    r = client.post("/api/evidence/link", json={"url": "hxxps://tamm-abudhabi-pay[.]top/fines"})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["pack_id"].startswith("MQ-") and len(p["sha256"]) == 64 and p["generated_at"].endswith("Z")
    assert p["url"]["defanged"].startswith("hxxps://") and "[.]" in p["url"]["host"]
    assert p["registration"]["registrar"] == "Example Registrar LLC" and p["registration"]["newly_registered"] is True
    assert p["registration"]["age_days"] == 3 and p["registration"]["nameservers"] == ["ns1.example-dns.com"]
    assert p["hosting"][0]["network"] == "HOSTCO-NET" and p["hosting"][0]["country"] == "NL"
    assert set(p["abuse_contacts"]) == {"abuse@registrar.example", "abuse@hostco.example"}
    assert p["analysis"]["impersonated_brand"] == "tamm" and "registered only 3 day" in p["analysis"]["signals"][0]["en"]


def test_pack_degrades_gracefully(client, monkeypatch):
    monkeypatch.setattr(ev, "TRANSPORT", httpx.MockTransport(lambda r: httpx.Response(503)))
    monkeypatch.setattr(ev, "resolve", lambda host: [])
    p = client.post("/api/evidence/link", json={"url": "https://unknown-site.example/x"}).json()
    assert p["registration"]["status"] == "unavailable" and p["hosting"] == [] and p["analysis"]["level"] in ("low", "medium", "high", "critical")


def test_pack_rejects_non_addresses(client):
    assert client.post("/api/evidence/link", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/evidence/link", json={"url": "not a url at all"}).status_code == 422


def test_redirect_wrapper_is_unwrapped():
    from ai.behavioral_analysis.url_analyzer import analyze_url
    r = analyze_url("https://www.google.com/url?q=https%3A%2F%2Fpaypa1-login.top%2Fverify")
    assert r.redirect_target and "paypa1-login" in r.redirect_target and r.level in ("high", "critical")
    assert analyze_url("https://accounts.google.com/signin?continue=https://mail.google.com/").level == "low"
