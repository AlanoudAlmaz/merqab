import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app import db as dbm  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.security import hash_password  # noqa: E402

PASSWORD = "Test-pass-1234"
SAMPLES = ROOT / "sample_data"


def make_settings(tmp_path, **kw):
    base = dict(secret_key="s" * 48, db_path=tmp_path / "t.db", evidence_dir=tmp_path / "evidence", rate_limit_per_min=10_000)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def app(tmp_path):
    s = make_settings(tmp_path)
    application = create_app(s)
    c = dbm.connect(s.db_path)
    for u, r in (("inv1", "investigator"), ("inv2", "investigator"), ("rev1", "reviewer"), ("adm", "admin")):
        c.execute("INSERT INTO users (username, pw_hash, role, created_at) VALUES (?,?,?,?)", (u, hash_password(PASSWORD), r, dbm.now()))
    c.commit()
    c.close()
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def auth(client, username):
    r = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture
def inv(client):
    return auth(client, "inv1")


@pytest.fixture
def rev(client):
    return auth(client, "rev1")


@pytest.fixture
def demo_case(client, inv):
    """A case populated with the synthetic demo evidence and analysed."""
    import json
    data = json.loads((SAMPLES / "demo_case.json").read_text(encoding="utf-8"))
    cid = client.post("/api/cases", json={"title": data["title"]}, headers=inv).json()["id"]
    for ev in data["evidence"]:
        assert client.post(f"/api/cases/{cid}/evidence/text", json=ev, headers=inv).status_code == 201
    eml = SAMPLES / "phishing_email.eml"
    r = client.post(f"/api/cases/{cid}/evidence/file", files={"file": (eml.name, eml.read_bytes())}, data={"label": "Email"}, headers=inv)
    assert r.status_code == 201, r.text
    assert client.post(f"/api/cases/{cid}/analyze", headers=inv).status_code == 200
    return cid
