from backend.app.api import radar


def test_public_campaigns_allowlist_and_investigator_routes(client, inv, monkeypatch):
    campaign = {
        "id": "C-123", "sector": "delivery", "status": "confirmed",
        "first_seen": "2026-11-23T09:00:00Z", "last_seen": "2026-11-24T09:00:00Z", "size": 2,
        "hosts": ["example.invalid"], "members": [1, 2], "genes": [{"value": "private-path"}],
        "name_en": "Contains example.invalid",
    }
    monkeypatch.setattr(radar, "radar_intel", lambda _: {"campaigns": [campaign], "items": [], "campaign_of": {}})
    response = client.get("/api/radar/public")
    assert response.status_code == 200
    assert set(response.json()["campaigns"][0]) == {
        "id", "sector", "status", "first_seen", "last_seen", "size", "level", "brand_en", "brand_ar", "listed_now", "sources", "harm_en", "harm_ar", "prevention",
    }
    for path in ("", "/graph", "/lookup?q=example.invalid", "/campaigns/C-123", "/intel",
                 "/report", "/report.csv"):
        assert client.get(f"/api/radar{path}").status_code == 401
    assert client.get("/api/radar", headers=inv).status_code == 200


def test_public_check_redacts_radar_campaign_metadata():
    from backend.app.api.prevention import _public_result

    result = {
        "radar_matches": [{"host": "example.invalid", "confirmed": True, "campaign": {"hosts": ["other.invalid"]}}],
        "inferences": [{"type": "campaign"}, {"type": "campaign_prediction"}, {"type": "summary"}],
    }
    assert _public_result(result) == {
        "radar_matches": [{"host": "example.invalid", "confirmed": True}],
        "inferences": [{"type": "summary"}],
    }


def test_public_summary_counts_stored_data(client, monkeypatch):
    """The plain-language radar numbers are counted from stored data, never invented."""
    import json
    from backend.app import db as dbm
    from backend.app.api import radar as radar_api
    conn = dbm.connect(client.app.state.settings.db_path)
    now = dbm.now()
    for i, brand in enumerate(["emiratesnbd", "emiratesnbd", None]):
        conn.execute("INSERT INTO radar_items (host, registrable_domain, sources, brand, first_seen, last_seen, score) VALUES (?,?,?,?,?,?,?)",
                     (f"h{i}.example.invalid", f"h{i}.example.invalid", "[]", brand, now, now, 90))
    conn.execute("INSERT INTO radar_items (host, registrable_domain, sources, first_seen, last_seen, status) VALUES ('x.invalid','x.invalid','[]',?,?,'dismissed')", (now, now))
    conn.execute("INSERT INTO radar_sources (name, state, last_success, detail, updated_at) VALUES ('ct','ok',?,?,?)",
                 (now, json.dumps({"newest_certificate_age_seconds": 7}), now))
    conn.commit()
    ids = [r[0] for r in conn.execute("SELECT id FROM radar_items WHERE status!='dismissed'")]
    camps = [{"id": "C-1", "sector": "banking", "status": "confirmed", "first_seen": now, "last_seen": now, "size": 2, "members": ids[:2]},
             {"id": "C-2", "sector": "delivery", "status": "suspected", "first_seen": now, "last_seen": now, "size": 1, "members": ids[2:]}]
    items = [{"id": i, "score": 90, "sources": []} for i in ids]
    monkeypatch.setattr(radar_api, "radar_intel", lambda _: {"campaigns": camps, "items": items, "campaign_of": {}})
    s = client.get("/api/radar/public").json()["summary"]
    assert s["indicators"] == 3 and s["new_24h"] == 3 and s["brands"] == 1
    assert s["campaigns"] == 2 and s["critical_campaigns"] == 2
    assert s["sectors"] == {"banking": 1, "delivery": 1}
    assert s["speed_seconds"] == 7
    assert 0.5 < s["accuracy"]["accuracy"] <= 1 and s["accuracy"]["n"] > 1000


def test_preview_qr_carries_a_message_not_a_link(client):
    r = client.get("/api/qr/preview.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml") and b"<svg" in r.content
    from backend.app.api.devices import PREVIEW_MESSAGE
    assert "http" not in PREVIEW_MESSAGE and "MERQAB" in PREVIEW_MESSAGE
