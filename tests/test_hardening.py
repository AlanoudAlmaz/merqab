"""Regression tests for the security audit fixes."""
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.security import CSP, RateLimiter
from tests.conftest import PASSWORD, make_settings


def test_dns_rebinding_host_is_rejected(client):
    assert client.get("/api/health").status_code == 200
    r = client.get("/api/radar", headers={"host": "evil.example"})
    assert r.status_code == 400 and r.json()["detail"] == "Invalid host header"
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400
    assert client.get("/api/health", headers={"host": "10.0.0.7:10000"}).status_code == 200   # host health checker only
    assert client.get("/api/health", headers={"host": "127.0.0.1:8765"}).status_code == 200
    assert client.get("/api/health", headers={"host": "[::1]:8765"}).status_code == 200


def test_oversized_body_rejected_before_parsing(client):
    big = b"x" * (27 * 1024 * 1024)
    r = client.post("/api/analyze/file", files={"file": ("a.txt", big, "text/plain")})
    assert r.status_code == 413


def test_account_lockout_after_repeated_failures(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "inv2", "password": "wrong-pass-123"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": "inv2", "password": PASSWORD})
    assert r.status_code == 429          # even the right password is refused while locked
    assert client.post("/api/auth/login", json={"username": "inv1", "password": PASSWORD}).status_code == 200


def test_api_docs_disabled_by_default(client):
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_security_headers_and_csp(client):
    h = client.get("/").headers
    assert "script-src 'self'" in h["content-security-policy"] and "unsafe-inline" not in CSP.split("style-src")[0]
    assert h["x-frame-options"] == "DENY" and h["cross-origin-resource-policy"] == "same-origin"
    assert "strict-transport-security" not in h      # only sent over HTTPS
    assert "strict-transport-security" in client.get("/", headers={"x-forwarded-proto": "https"}).headers


def test_global_api_throttle(tmp_path):
    c = TestClient(create_app(make_settings(tmp_path, rate_limit_per_min=2)))
    codes = [c.get("/api/health").status_code for _ in range(25)]
    assert 429 in codes and codes[0] == 200


def test_rate_limiter_memory_is_bounded():
    rl = RateLimiter()
    rl.MAX_KEYS = 50
    for i in range(500):
        rl.check(f"k{i}", 5)
    rl._swept = -10_000            # force a sweep: stale buckets go, recent ones stay
    rl.hits.update({f"old{i}": __import__("collections").deque([-10_000.0]) for i in range(100)})
    rl.check("fresh", 5)
    assert not any(k.startswith("old") for k in rl.hits)
