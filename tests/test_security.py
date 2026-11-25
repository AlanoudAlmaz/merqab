"""Security controls: authn/authz, tokens, uploads, headers, rate limiting, audit chain, i18n parity."""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.audit import verify_chain
from backend.app.main import create_app
from backend.app.security import UploadRejected, issue_token, read_token, validate_upload
from tests.conftest import PASSWORD, make_settings

ROOT = Path(__file__).resolve().parents[1]


def test_investigation_requires_auth(client):
    for path in ("/api/cases", "/api/community/review", "/api/evidence/1"):
        assert client.get(path).status_code == 401
    assert client.post("/api/cases", json={"title": "abc"}).status_code == 401


def test_role_enforcement(client, inv):
    assert client.get("/api/audit", headers=inv).status_code == 403
    assert client.post("/api/users", json={"username": "x1", "password": "abcdefgh12", "role": "admin"}, headers=inv).status_code == 403


def test_bad_login_and_tampered_token(client):
    assert client.post("/api/auth/login", json={"username": "inv1", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "nobody", "password": PASSWORD}).status_code == 401
    tok = client.post("/api/auth/login", json={"username": "inv1", "password": PASSWORD}).json()["token"]
    payload, sig = tok.split(".")
    forged = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + sig
    assert client.get("/api/cases", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_expiry_and_signature():
    t = issue_token("k" * 40, 1, "investigator", ttl_min=-1)
    assert read_token("k" * 40, t) is None
    t2 = issue_token("k" * 40, 1, "investigator", ttl_min=5)
    assert read_token("k" * 40, t2)["uid"] == 1
    assert read_token("other" * 10, t2) is None


def test_admin_user_creation_password_policy(client):
    from tests.conftest import auth
    adm = auth(client, "adm")
    assert client.post("/api/users", json={"username": "newbie", "password": "onlyletters", "role": "investigator"}, headers=adm).status_code == 422
    assert client.post("/api/users", json={"username": "newbie", "password": "letters12345", "role": "investigator"}, headers=adm).status_code == 201


@pytest.mark.parametrize("name,data,reason", [
    ("evil.exe", b"MZ\x90\x00", "Unsupported"),
    ("photo.png", b"MZ\x90\x00rest", "does not match"),
    ("photo.png", b"GIF89a....", "does not match"),
    ("invoice.pdf.exe", b"MZ", "Unsupported"),
    ("invoice.exe.pdf", b"%PDF-1.4", "Double"),
    ("notes.txt", b"\x00\x01\x02binary", "binary"),
    ("empty.txt", b"", "Empty"),
    ("noext", b"hello", "not recognised"),
    ("page.html", b"<script>", "Unsupported"),
    ("image.svg", b"<svg onload=alert(1)>", "Unsupported"),
])
def test_upload_validation_rejects(name, data, reason):
    with pytest.raises(UploadRejected, match=reason):
        validate_upload(name, data, 1024 * 1024)


def test_upload_size_limit():
    with pytest.raises(UploadRejected, match="exceeds"):
        validate_upload("a.txt", b"a" * 2048, 1024)


def test_upload_accepts_valid_types():
    assert validate_upload("a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 10, 1 << 20)[0] == "png"
    assert validate_upload("../../etc/a.pdf", b"%PDF-1.7 ...", 1 << 20)[0] == "pdf"


def test_malicious_upload_rejected_and_audited(client, inv, app):
    cid = client.post("/api/cases", json={"title": "Upload test"}, headers=inv).json()["id"]
    r = client.post(f"/api/cases/{cid}/evidence/file", files={"file": ("x.png", b"MZ\x90\x00payload")}, data={"label": "x"}, headers=inv)
    assert r.status_code == 415
    c = app.state.connect()
    assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='evidence.rejected'").fetchone()[0] == 1
    assert client.post("/api/analyze/file", files={"file": ("a.exe", b"MZ")}).status_code == 415


def test_pdf_with_active_content_is_flagged_not_executed(client, inv):
    cid = client.post("/api/cases", json={"title": "PDF test"}, headers=inv).json()["id"]
    pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF"
    r = client.post(f"/api/cases/{cid}/evidence/file", files={"file": ("doc.pdf", pdf)}, data={"label": "pdf"}, headers=inv)
    assert r.status_code == 201
    note = r.json()["extraction_note"]
    assert "active content" in note or "could not be parsed" in note


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_validation_errors_do_not_echo_input(client):
    r = client.post("/api/analyze", json={"kind": "bogus", "content": "SECRET-TOKEN-123"})
    assert r.status_code == 422 and "SECRET-TOKEN-123" not in r.text


def test_rate_limiting(tmp_path):
    app = create_app(make_settings(tmp_path, rate_limit_per_min=3))
    with TestClient(app) as c:
        codes = [c.post("/api/analyze", json={"kind": "text", "content": "hello there"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]


def test_audit_chain_detects_tampering(client, inv, app):
    client.post("/api/cases", json={"title": "Audit me"}, headers=inv)
    c = app.state.connect()
    assert verify_chain(c)["valid"] is True
    c.execute("UPDATE audit_log SET actor='mallory' WHERE id=(SELECT MAX(id) FROM audit_log)")
    c.commit()
    res = verify_chain(c)
    assert res["valid"] is False and res["broken_at"]


def test_capabilities_are_honest(client):
    caps = client.get("/api/capabilities").json()
    assert caps["live_monitoring"]["status"] == "not_implemented"
    assert caps["deepfake_media_analysis"]["status"] == "integration_ready"
    assert caps["url_reputation"]["status"] == "not_configured"  # radar off in tests: no reputation source


def test_link_reputation_available_when_radar_runs(client, app):
    app.state.radar.enabled = True
    try:
        caps = client.get("/api/capabilities").json()
        assert caps["url_reputation"]["status"] == "available" and "OpenPhish" in caps["url_reputation"]["source"]
    finally:
        app.state.radar.enabled = False


def test_no_secrets_in_repository():
    pattern = re.compile(r"(sk-ant-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA )?PRIVATE KEY-----)")
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix in {".py", ".js", ".json", ".md", ".txt", ".env", ".example", ".html", ".css"} and "data" not in p.parts:
            assert not pattern.search(p.read_text(encoding="utf-8", errors="ignore")), p


# ---------------------------------------------------------------- localisation
def test_i18n_key_parity_and_coverage():
    en = json.loads((ROOT / "frontend/i18n/en.json").read_text(encoding="utf-8"))
    ar = json.loads((ROOT / "frontend/i18n/ar.json").read_text(encoding="utf-8"))
    assert set(en) == set(ar)
    assert all(v.strip() for v in ar.values())
    js = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "frontend/js").glob("*.js"))
    used = set(re.findall(r'\bt\("([a-z_]+\.[a-z_.0-9]+)"\)', js))
    missing = sorted(k for k in used if k not in en)
    assert not missing, missing


def test_arabic_text_is_arabic():
    ar = json.loads((ROOT / "frontend/i18n/ar.json").read_text(encoding="utf-8"))
    skip = {"rep.export_md", "rep.export_json", "lang.toggle"}
    non_arabic = [k for k, v in ar.items() if k not in skip and not re.search(r"[؀-ۿ]", v)]
    assert not non_arabic, non_arabic


def test_app_shell_is_revalidated_after_upgrades(client):
    assert client.get("/js/app.js").headers["cache-control"] == "no-cache"


def test_single_account_mode_keeps_only_admin(tmp_path, monkeypatch):
    from backend.app import db as dbm
    from backend.app.cli import single_account
    from backend.app.security import hash_password
    dbp = tmp_path / "s.db"
    monkeypatch.setenv("MIRQAB_DB_PATH", str(dbp))
    monkeypatch.setenv("MIRQAB_DATA_DIR", str(tmp_path))
    dbm.init(dbp)
    c = dbm.connect(dbp)
    for u, r in (("investigator", "investigator"), ("reviewer", "reviewer"), ("admin", "admin")):
        c.execute("INSERT INTO users (username, pw_hash, role, created_at) VALUES (?,?,?,?)", (u, hash_password("x" * 12 + "7a"), r, dbm.now()))
    c.commit(); c.close()
    single_account(None)
    c = dbm.connect(dbp)
    active = [r["username"] for r in c.execute("SELECT username FROM users WHERE active=1")]
    assert active == ["admin"]
    assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3  # deactivated, never deleted
    single_account(None)  # idempotent
