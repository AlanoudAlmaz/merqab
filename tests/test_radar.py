"""Live Threat Radar: CT parsing, look-alike detection, feed parsing, API and prevention integration."""
import base64
import datetime as dt
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ai.threat_intelligence.ct_parser import domains_from_entry
from ai.threat_intelligence.radar import classify_domain, parse_feed_line
from backend.app.radar import upsert
from tests.conftest import auth


def _cert_der(names):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_ct_x509_entry_parsing():
    der = _cert_der(["emiratesnbd-secure.xyz", "*.emiratesnbd-secure.xyz", "www.emiratesnbd-secure.xyz"])
    leaf = b"\x00\x00" + struct.pack(">Q", 0) + struct.pack(">H", 0) + len(der).to_bytes(3, "big") + der
    entry = {"leaf_input": base64.b64encode(leaf).decode(), "extra_data": ""}
    assert domains_from_entry(entry) == ["emiratesnbd-secure.xyz", "www.emiratesnbd-secure.xyz"]


def test_ct_precert_entry_parsing():
    der = _cert_der(["uaepass-login.com"])
    leaf = b"\x00\x00" + struct.pack(">Q", 0) + struct.pack(">H", 1) + b"\x00" * 40
    extra = len(der).to_bytes(3, "big") + der
    entry = {"leaf_input": base64.b64encode(leaf).decode(), "extra_data": base64.b64encode(extra).decode()}
    assert domains_from_entry(entry) == ["uaepass-login.com"]


def test_ct_garbage_is_ignored():
    assert domains_from_entry({"leaf_input": "!!", "extra_data": ""}) == []
    assert domains_from_entry({}) == []


@pytest.mark.parametrize("host,brand", [
    ("emiratesnbd-secure.xyz", "emiratesnbd"), ("dhl-delivery-ae.top", "dhl"), ("paypa1.com", "paypal"),
    ("uaepass-login.com", "uaepass"), ("salik-fines-pay.com", "salik"), ("paypal.com.verify-login.xyz", "paypal"),
    ("paypal-account.blogspot.com", "paypal"), ("xn--pple-43d.com", "apple"), ("mashreq-secure-update.info", "mashreq"),
])
def test_lookalikes_detected(host, brand):
    f = classify_domain(host)
    assert f and f["brand"] == brand and f["score"] >= 45 and f["reasons"]


@pytest.mark.parametrize("host", [
    "emiratesnbd.com", "www.paypal.com", "amazon.ae", "login.microsoftonline.com", "microsoft-int.com",
    "email.ops.prod.aura.acm.aws.dev", "dhl.com", "dewa.gov.ae", "pineapple-recipes.com", "my-blog.example.org",
    "xbdoh.carrs.canary.test.sfdc.net", "cloud.example.com",
])
def test_legitimate_or_unrelated_not_flagged(host):
    assert classify_domain(host) is None


def test_feed_line_parsing():
    assert parse_feed_line("# comment") is None
    assert parse_feed_line("not a url") is None
    it = parse_feed_line("https://facebookaccount1234.blogspot.com/login")
    assert it["host"] == "facebookaccount1234.blogspot.com" and it["registrable_domain"] == "blogspot.com"


REAL_FALSE_ALARMS = ["www.takara-muralpaint.com", "deli.takara-butz.co.jp", "pro-finance.com", "hm-career-ai.cn",
                     "rodzpwww.staging.corp.login.forticloud.online"]


@pytest.mark.parametrize("host", REAL_FALSE_ALARMS)
def test_real_false_alarms_from_live_ct_are_not_flagged(host):
    """Regression: these were flagged during the first live run on real CT data and are ordinary domains."""
    assert classify_domain(host) is None


@pytest.mark.parametrize("host", ["office365.001366.xyz", "www.facebook.ki-sia.xyz", "netflixir.shop", "meta.pendulum-puzzle.click"])
def test_real_suspicious_ct_findings_still_flagged(host):
    assert classify_domain(host) is not None


def _seed(app):
    c = app.state.connect()
    upsert(c, classify_domain("emiratesnbd-secure.xyz"), "ct", evidence={"log": "Test log", "entry_index": 7})
    upsert(c, classify_domain("emiratesnbd-secure.top"), "ct")
    feed = parse_feed_line("https://facebookaccount1234.blogspot.com/login")
    feed.update(method="confirmed_feed", score=95, reasons=[{"en": "listed", "ar": "مدرج"}])
    upsert(c, feed, "openphish", feed["url"])
    assert upsert(c, classify_domain("emiratesnbd-secure.xyz"), "ct") is False  # dedup
    return c


def test_radar_api_campaigns_and_prevention(client, app):
    _seed(app)
    d = client.get("/api/radar").json()
    assert d["service"]["enabled"] is False
    assert {s["name"] for s in d["service"]["sources"]} == {"ct", "openphish", "certpl", "phishing_army", "phishing_db", "blocklist_project"}
    assert d["counts"]["confirmed_total"] == 1 and d["counts"]["suspected"] == 2
    camp = d["campaigns"][0]
    assert camp["size"] == 2 and camp["status"] == "suspected" and camp["confidence"] == "high"
    assert "emiratesnbd-secure" in camp["name_en"] and camp["links"][0]["strength"] == "strong"
    assert camp["harm_en"] and camp["prevention"] and "do not prove" in camp["uncertainty_en"]
    item = next(i for i in d["items"] if i["host"] == "emiratesnbd-secure.xyz")
    assert item["campaign"]["campaign_id"] == camp["id"] and item["evidence"]["log"] == "Test log"

    # known look-alike in a public check → radar match + campaign context
    r = client.post("/api/analyze", json={"kind": "url", "content": "https://login.emiratesnbd-secure.xyz/x"}).json()
    m = r["radar_matches"][0]
    assert m["host"] == "emiratesnbd-secure.xyz" and m["campaign"]["campaign_id"] == camp["id"]
    assert any(b["source"] == "radar" and b["points"] == 20 for b in r["risk"]["breakdown"])
    # never-seen domain with the same naming DNA → predicted (lower weight, labelled unverified)
    p = client.post("/api/analyze", json={"kind": "url", "content": "https://emiratesnbd-secure.online/verify"}).json()
    pm = p["radar_matches"][0]
    assert pm["predicted"] is True and pm["campaign"]["campaign_id"] == camp["id"]
    assert any(b["source"] == "radar_predicted" and b["points"] == 10 for b in p["risk"]["breakdown"])
    assert any(i["type"] == "campaign_prediction" and i["verified"] is False for i in p["inferences"])
    # confirmed feed URL matches that host only, not the whole shared platform
    r2 = client.post("/api/analyze", json={"kind": "url", "content": "https://facebookaccount1234.blogspot.com/"}).json()
    assert r2["radar_matches"][0]["confirmed"] and r2["risk"]["level"] in ("high", "critical")
    assert client.post("/api/analyze", json={"kind": "url", "content": "https://someone-else.blogspot.com/"}).json()["radar_matches"] == []


def test_campaign_detail_and_unknown_campaign(client, app, inv):
    _seed(app)
    cid = client.get("/api/radar").json()["campaigns"][0]["id"]
    pub = client.get(f"/api/radar/campaigns/{cid}").json()
    assert len(pub["items"]) == 2 and "linked_cases" not in pub
    assert "linked_cases" in client.get(f"/api/radar/campaigns/{cid}", headers=inv).json()
    assert client.get("/api/radar/campaigns/C-000000").status_code == 404


def test_investigate_campaign_creates_case_with_immutable_snapshot(client, app, inv):
    _seed(app)
    cid = client.get("/api/radar").json()["campaigns"][0]["id"]
    assert client.post("/api/radar/investigate", json={"campaign_id": cid}).status_code == 401
    r = client.post("/api/radar/investigate", json={"campaign_id": cid}, headers=inv).json()
    case = client.get(f"/api/cases/{r['case_id']}", headers=inv).json()
    assert case["title"].startswith(f"Radar campaign {cid}") and len(case["evidence"]) == 1
    ev = client.get(f"/api/evidence/{r['evidence_id']}", headers=inv).json()
    assert "emiratesnbd-secure.top" in ev["extracted_text"] and "do not prove" in ev["extracted_text"]
    assert client.get(f"/api/evidence/{r['evidence_id']}/verify", headers=inv).json()["intact"]
    # case analysis links the evidence back to the radar and the campaign
    a = client.post(f"/api/cases/{r['case_id']}/analyze", headers=inv).json()
    assert {x["host"] for x in a["radar_links"]} >= {"emiratesnbd-secure.xyz", "emiratesnbd-secure.top"}
    fs = client.get(f"/api/cases/{r['case_id']}/findings", headers=inv).json()
    assert any("live radar" in f["statement_en"] for f in fs)
    assert any(cid in f["statement_en"] and f["category"] == "inference" for f in fs)
    # add a single finding to the existing case
    item = client.get("/api/radar?source=openphish").json()["items"][0]["id"]
    r2 = client.post("/api/radar/investigate", json={"item_id": item, "case_id": r["case_id"]}, headers=inv).json()
    assert r2["case_id"] == r["case_id"]
    assert client.post("/api/radar/investigate", json={"item_id": item, "campaign_id": cid}, headers=inv).status_code == 422


def test_existing_case_evidence_links_to_radar(client, app, inv):
    _seed(app)
    cid = client.post("/api/cases", json={"title": "SMS report"}, headers=inv).json()["id"]
    client.post(f"/api/cases/{cid}/evidence/text", json={"kind": "text", "label": "sms",
                "content": "Your card is blocked, verify now: https://emiratesnbd-secure.xyz/login"}, headers=inv)
    a = client.post(f"/api/cases/{cid}/analyze", headers=inv).json()
    assert a["radar_links"][0]["host"] == "emiratesnbd-secure.xyz" and a["radar_links"][0]["campaign"]


def _seed_confirmed_kit(app):
    """Two OpenPhish-listed URLs on different hosts that share a phishing-kit path → a confirmed campaign."""
    c = app.state.connect()
    for u in ("https://roblox.ly/users/9912/profile", "https://www.roblox.com.am/users/5512/profile"):
        f = parse_feed_line(u)
        f.update(method="confirmed_feed", score=95, reasons=[{"en": "listed", "ar": "مدرج"}])
        upsert(c, f, "openphish", u, {"feed": "test", "fetched_at": "2026-11-19T10:00:00+00:00"})
    return c


def test_warning_drafts_only_from_validated_findings(client, app, rev, inv):
    _seed(app)
    _seed_confirmed_kit(app)
    camps = {c["status"]: c["id"] for c in client.get("/api/radar").json()["campaigns"]}
    # suspected-only campaign: refused, with guidance to investigate first
    r = client.post("/api/radar/warn", json={"campaign_id": camps["suspected"]}, headers=rev)
    assert r.status_code == 409 and "Open a case" in r.json()["detail"]
    sus = next(i for i in client.get("/api/radar?source=ct").json()["items"])
    assert client.post("/api/radar/warn", json={"item_id": sus["id"]}, headers=rev).status_code == 409
    # confirmed campaign: investigators cannot, reviewers can draft
    assert client.post("/api/radar/warn", json={"campaign_id": camps["confirmed"]}, headers=inv).status_code == 403
    w = client.post("/api/radar/warn", json={"campaign_id": camps["confirmed"]}, headers=rev).json()
    assert set(w["included"]) == {"roblox.ly", "www.roblox.com.am"} and w["excluded_unverified"] == []
    assert client.post("/api/radar/warn", json={"campaign_id": camps["confirmed"]}, headers=rev).status_code == 409
    assert client.get("/api/community/alerts").json() == []  # still a draft
    aid = w["alert_id"]
    client.post(f"/api/community/alerts/{aid}/submit", headers=rev)
    check = {"checklist": {"pii_removed": True, "evidence_supported": True, "guidance_accurate": True}}
    assert client.post(f"/api/community/alerts/{aid}/approve", json=check, headers=rev).status_code == 403  # two-person rule
    assert client.post(f"/api/community/alerts/{aid}/approve", json=check, headers=auth(client, "adm")).status_code == 200
    # published warning is reflected on the constellation nodes
    g = client.get("/api/radar/graph").json()
    assert {n["host"] for n in g["nodes"] if n["alert_status"] == "published"} == {"roblox.ly", "www.roblox.com.am"}


def test_constellation_graph_contains_only_real_findings_and_explained_links(client, app):
    _seed(app)
    _seed_confirmed_kit(app)
    g = client.get("/api/radar/graph").json()
    c = app.state.connect()
    stored = {r[0]: r[1] for r in c.execute("SELECT id, host FROM radar_items WHERE status != 'dismissed'")}
    ids = {n["id"] for n in g["nodes"]}
    assert ids <= set(stored) and all(stored[n["id"]] == n["host"] for n in g["nodes"])   # every node is a stored finding
    assert g["edges"] and all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    assert all(e["reason_en"] and e["reason_ar"] and e["strength"] in ("strong", "moderate", "weak") for e in g["edges"])
    # connected_only (default) hides the unlinked feed finding; it is counted, not invented or dropped
    assert "facebookaccount1234.blogspot.com" not in {n["host"] for n in g["nodes"]}
    assert g["totals"]["unconnected"] == 1
    full = client.get("/api/radar/graph?connected_only=false").json()
    assert len(full["nodes"]) == len(stored)
    n = next(x for x in full["nodes"] if x["host"] == "emiratesnbd-secure.xyz")
    assert n["status"] == "suspected" and n["risk_level"] in ("high", "critical") and n["first_seen"]
    assert n["evidence"]["log"] == "Test log" and n["prevention"] and n["harm_en"] and n["campaign_id"]
    # campaigns in the graph are the same objects Scam Campaign DNA produces
    radar_ids = {x["id"] for x in client.get("/api/radar").json()["campaigns"]}
    assert {x["id"] for x in g["campaigns"]} <= radar_ids
    for camp in g["campaigns"]:
        assert len(camp["members"]) >= 2 and set(camp["members"]) <= ids


def test_constellation_filters(client, app):
    _seed(app)
    _seed_confirmed_kit(app)
    conf = client.get("/api/radar/graph?status=confirmed").json()
    assert conf["nodes"] and all(n["status"] == "confirmed" for n in conf["nodes"])
    sus = client.get("/api/radar/graph?status=suspected").json()
    assert sus["nodes"] and all(n["status"] == "suspected" for n in sus["nodes"])
    rb = client.get("/api/radar/graph?brand=roblox").json()
    assert {n["brand"] for n in rb["nodes"]} == {"roblox"}
    assert client.get("/api/radar/graph?status=bogus").status_code == 422
    assert len(client.get("/api/radar/graph?connected_only=false&limit=1").json()["nodes"]) == 1


def test_constellation_empty_state(client):
    g = client.get("/api/radar/graph").json()
    assert g["nodes"] == [] and g["edges"] == [] and g["campaigns"] == [] and g["totals"]["findings"] == 0


def test_dismiss_removes_from_prevention(client, app, rev):
    c = _seed(app)
    fid = c.execute("SELECT id FROM radar_items WHERE host='facebookaccount1234.blogspot.com'").fetchone()[0]
    assert client.post(f"/api/radar/{fid}/dismiss", json={"note": "fp"}, headers=rev).status_code == 200
    assert client.post("/api/analyze", json={"kind": "url", "content": "https://facebookaccount1234.blogspot.com/"}).json()["radar_matches"] == []


def test_feed_listing_status_and_maintenance(app):
    from backend.app.radar import RadarService, maintain
    c = _seed(app)
    svc = RadarService(app.state.settings.db_path, enabled=False)
    res = svc.refresh_feed(c, "https://other-phish.example.top/x\n", "2026-11-19T00:00:00+00:00")
    assert res == {"listed_now": 1, "new": 1}
    gone = c.execute("SELECT active FROM radar_items WHERE host='facebookaccount1234.blogspot.com'").fetchone()[0]
    assert gone == 0  # kept for history, marked as no longer listed
    # rule update: a stored CT finding that no longer matches is dismissed with a note, never deleted
    c.execute("INSERT INTO radar_items (host, registrable_domain, sources, method, first_seen, last_seen) VALUES "
              "('www.takara-muralpaint.com','takara-muralpaint.com','ct','typosquat','2026-11-19','2026-11-19')")
    c.commit()
    assert maintain(c)["dismissed_by_rule_update"] == 1
    row = c.execute("SELECT status, review_note FROM radar_items WHERE host='www.takara-muralpaint.com'").fetchone()
    assert row[0] == "dismissed" and "rule update" in row[1]


def test_migration_adds_columns_to_existing_database(tmp_path):
    import sqlite3
    from backend.app import db as dbm
    p = tmp_path / "old.db"
    old = sqlite3.connect(p)
    old.execute("CREATE TABLE radar_items (id INTEGER PRIMARY KEY, host TEXT UNIQUE NOT NULL, registrable_domain TEXT NOT NULL, url TEXT,"
                " sources TEXT NOT NULL, brand TEXT, method TEXT, score INTEGER, reasons TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,"
                " seen_count INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'new', reviewed_by INTEGER, alert_id INTEGER)")
    old.execute("INSERT INTO radar_items (host, registrable_domain, sources, first_seen, last_seen) VALUES ('a.xyz','a.xyz','ct','t','t')")
    old.commit(); old.close()
    dbm.init(p)
    c = dbm.connect(p)
    cols = {r[1] for r in c.execute("PRAGMA table_info(radar_items)")}
    assert {"evidence", "active", "last_listed", "review_note"} <= cols
    assert c.execute("SELECT host, active FROM radar_items").fetchone()[:] == ("a.xyz", 1)


def test_campaign_rules_on_kits_and_free_platforms():
    from ai.threat_intelligence.campaigns import build_campaigns
    items = [
        {"id": 1, "host": "roblox.ly", "registrable_domain": "roblox.ly", "url": "https://roblox.ly/users/9912/profile", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
        {"id": 2, "host": "www.roblox.com.am", "registrable_domain": "roblox.com.am", "url": "https://www.roblox.com.am/users/5512/profile", "first_seen": "2026-11-19T11:00:00+00:00", "confirmed": True},
        {"id": 3, "host": "security-server-stat-3f7g.bolt.host", "registrable_domain": "bolt.host", "url": "https://security-server-stat-3f7g.bolt.host/", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
        {"id": 4, "host": "security-server-stat-k7kn.bolt.host", "registrable_domain": "bolt.host", "url": "https://security-server-stat-k7kn.bolt.host/", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
        {"id": 5, "host": "my-bakery.bolt.host", "registrable_domain": "bolt.host", "url": "https://my-bakery.bolt.host/", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
        {"id": 6, "host": "www.x-promo.blogspot.com", "registrable_domain": "blogspot.com", "url": "https://www.x-promo.blogspot.com/", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
        {"id": 7, "host": "x-promo.blogspot.com", "registrable_domain": "blogspot.com", "url": "https://x-promo.blogspot.com/", "first_seen": "2026-11-19T10:00:00+00:00", "confirmed": True},
    ]
    camps = {tuple(c["members"]): c for c in build_campaigns(items)}
    assert (1, 2) in camps and camps[(1, 2)]["links"][0]["strength"] == "moderate"  # shared kit path '/users/#'
    assert (3, 4) in camps  # same naming stem on a free platform
    assert not any(5 in m for m in camps)  # sharing a free platform alone is not a link
    assert not any(6 in m for m in camps)  # www.x and x are the same site, not a campaign
    assert all(c["status"] == "confirmed" for c in camps.values())


def test_intelligence_view_dna_is_explainable_and_private_data_gated(client, app, rev, inv):
    _seed(app)
    _seed_confirmed_kit(app)
    camps = {c["status"]: c["id"] for c in client.get("/api/radar").json()["campaigns"]}
    d = client.get("/api/radar/intel", params={"campaign_id": camps["confirmed"]}).json()
    site_ids = {s["id"] for s in d["sites"]}
    assert d["kind"] == "campaign" and len(site_ids) == 2
    # every trait edge points at real sites and every trait is shared by 2+ of them
    assert d["genes"] and all(len(g["members"]) >= 2 and set(g["members"]) <= site_ids for g in d["genes"])
    assert any(g["key"] == "path" and g["value"] == "/users/#" for g in d["genes"])
    # every site-to-site edge carries its stated reason
    assert d["links"] and all(l["reason_en"] and {l["a"], l["b"]} <= site_ids for l in d["links"])
    assert all(s["evidence"].get("feed") == "test" for s in d["sites"])  # public source evidence
    assert d["prevention"] and d["harm_en"] and d["warnings"] == []
    assert "linked_cases" not in d  # anonymous: no private case data
    assert "linked_cases" in client.get("/api/radar/intel", params={"campaign_id": camps["confirmed"]}, headers=inv).json()
    # approved community warning appears once published (two-person rule)
    aid = client.post("/api/radar/warn", json={"campaign_id": camps["confirmed"]}, headers=rev).json()["alert_id"]
    client.post(f"/api/community/alerts/{aid}/submit", headers=rev)
    check = {"checklist": {"pii_removed": True, "evidence_supported": True, "guidance_accurate": True}}
    assert client.post(f"/api/community/alerts/{aid}/approve", json=check, headers=auth(client, "adm")).status_code == 200
    w = client.get("/api/radar/intel", params={"campaign_id": camps["confirmed"]}).json()["warnings"]
    assert [x["id"] for x in w] == [aid] and set(w[0]["covers"]) == {"roblox.ly", "www.roblox.com.am"}
    # a finding inside a campaign opens the campaign focused on that site; bad input is rejected
    item = d["sites"][0]["id"]
    f = client.get("/api/radar/intel", params={"item_id": item}).json()
    assert f["kind"] == "campaign" and f["focus"] == item
    assert client.get("/api/radar/intel").status_code == 422
    assert client.get("/api/radar/intel", params={"item_id": 999999}).status_code == 404


def test_same_certificate_is_strong_evidence_and_intel_explains_prevention(client, app):
    from ai.threat_intelligence.campaigns import analyze_relationships
    a = {"id": 1, "host": "adcb-verify-login.top", "registrable_domain": "adcb-verify-login.top", "brand": "adcb",
         "first_seen": "2026-11-20T10:00:00+00:00", "method": "brand_lure", "evidence": {"log": "Argon", "entry_index": 55}}
    b = {**a, "id": 2, "host": "secure-adcb-portal.xyz", "registrable_domain": "secure-adcb-portal.xyz"}
    camps, edges = analyze_relationships([a, b])
    assert edges[0]["strength"] == "strong" and "same TLS certificate" in edges[0]["en"]
    assert camps[0]["confidence"] == "high"
    # different certificate entries are not linked by this rule
    _, e2 = analyze_relationships([a, {**b, "evidence": {"log": "Argon", "entry_index": 56}}])
    assert not any("certificate" in x["en"] for x in e2)
    # the intelligence view turns detection into prevention, with an honest evidence basis
    _seed(app)
    cid = next(c["id"] for c in client.get("/api/radar").json()["campaigns"] if c["status"] == "suspected")
    d = client.get("/api/radar/intel", params={"campaign_id": cid}).json()
    assert d["sector"] == "banking" and d["script"]["next_en"] and d["script"]["learn_stage"] == "extraction"
    assert [t["key"] for t in d["script"]["tactics"]][-1] == "credential_request"
    assert d["basis"]["confirmed"] == 0 and d["basis"]["suspected"] == 2 and d["basis"]["sources"] == {"ct": 2}
    assert d["basis"]["strongest"]["strength"] == "strong" and d["warnings"] == []   # nothing published automatically


def test_domain_lists_scan_everything_and_keep_only_brand_impersonation(app):
    from backend.app.radar import DOMAIN_FEEDS, RadarService, parse_domain_list
    hosts = "# comment\n0.0.0.0 emiratesnbd-verify.top\n0.0.0.0 localhost\nrandom-blog-site.com\nadnoc-ai.live  # trailing\n\n1.2.3.4\n"
    assert list(parse_domain_list(hosts)) == ["emiratesnbd-verify.top", "random-blog-site.com", "adnoc-ai.live"]
    from backend.app import radar as radar_mod
    radar_mod.LISTED.clear()
    c = app.state.connect()
    svc = RadarService(app.state.settings.db_path if hasattr(app.state.settings, "db_path") else None, False)
    res = svc.refresh_domain_feed(c, "certpl", hosts, "2026-11-23T10:00:00+00:00")
    assert res == {"scanned": 3, "listed_now": 2, "new": 2}
    row = c.execute("SELECT sources, active, brand, reasons FROM radar_items WHERE host='adnoc-ai.live'").fetchone()
    assert row["sources"] == "certpl" and row["active"] == 1 and row["brand"] == "adnoc" and "CERT Polska" in row["reasons"]
    assert c.execute("SELECT COUNT(*) FROM radar_items WHERE host='random-blog-site.com'").fetchone()[0] == 0
    # the same site on a second list keeps both sources; dropping off one list keeps it listed by the other
    svc.refresh_domain_feed(c, "phishing_army", "adnoc-ai.live\n", "t")
    svc.refresh_domain_feed(c, "certpl", "emiratesnbd-verify.top\n", "t")
    r = c.execute("SELECT sources, active FROM radar_items WHERE host='adnoc-ai.live'").fetchone()
    assert set(r["sources"].split(",")) == {"certpl", "phishing_army"} and r["active"] == 1
    svc.refresh_domain_feed(c, "phishing_army", "", "t")
    assert c.execute("SELECT active FROM radar_items WHERE host='adnoc-ai.live'").fetchone()[0] == 0
    assert set(DOMAIN_FEEDS) == {"certpl", "phishing_army", "phishing_db", "blocklist_project"}


def test_link_lookup(client, app):
    _seed(app)
    d = client.get("/api/radar/lookup", params={"q": "hxxps://facebookaccount1234[.]blogspot[.]com/login?x=1"}).json()
    assert d["query_host"] == "facebookaccount1234.blogspot.com"
    assert d["found"]["status"] == "confirmed" and d["found"]["listed_now"] is True
    assert "never opens" in d["limits_en"]
    s = client.get("/api/radar/lookup", params={"q": "emiratesnbd-secure.top"}).json()
    assert s["found"]["status"] == "suspected" and s["found"]["campaign"]["size"] == 2
    o = client.get("/api/radar/lookup", params={"q": "https://www.emiratesnbd.com"}).json()
    assert o["found"] is None and o["analysis"]["official_domain"] is True
    n = client.get("/api/radar/lookup", params={"q": "emiratesnbd-refund.xyz"}).json()
    assert n["found"] is None and n["same_brand"]["count"] >= 2 and n["analysis"]["level"] in ("high", "critical", "medium")
    assert client.get("/api/radar/lookup", params={"q": "not a link at all"}).status_code == 422
    assert client.get("/api/radar/lookup", params={"q": "ab"}).status_code == 422


def test_constellation_advanced_filters(client, app):
    _seed(app)
    q = lambda **p: client.get("/api/radar/graph", params={"connected_only": "false", **p}).json()["totals"]["shown_nodes"]
    assert q() == 3
    assert q(source="ct") == 2 and q(source="feeds") == 1 and q(source="openphish") == 1 and q(source="certpl") == 0
    assert q(listed_now="true") == 1
    assert q(min_risk="critical") == 3   # all three seeded sites score ≥ 70
    assert q(since_hours=1) == 3 and q(in_campaign="true") == 2 and q(warned="true") == 0
    assert client.get("/api/radar/graph", params={"min_risk": "extreme"}).status_code == 422


def test_report_counts_only_stored_findings_and_uses_radar_filters(client, app):
    _seed(app)
    d = client.get("/api/radar/report").json()
    assert d["totals"]["sites"] == 3 and d["totals"]["confirmed"] == 1 and d["totals"]["suspected"] == 2
    assert d["totals"]["campaigns"] == 1 and sum(x["confirmed"] + x["suspected"] for x in d["by_day"]) == 3
    assert {s["source"]: s["count"] for s in d["by_source"]} == {"ct": 2, "openphish": 1}
    assert all("[.]" in s["host"] for s in d["sites"])               # defanged, never clickable
    assert d["top_campaigns"][0]["in_report"] == 2 and d["limits_en"]
    assert sum(x["confirmed"] + x["suspected"] for x in d["by_hour"]) == 3     # short span -> hourly buckets
    # same filters as the radar
    c = client.get("/api/radar/report", params={"status": "confirmed"}).json()
    assert c["totals"]["sites"] == 1 and c["filters"] == {"status": "confirmed"}
    assert client.get("/api/radar/report", params={"source": "ct"}).json()["totals"]["sites"] == 2
    assert client.get("/api/radar/report", params={"min_risk": "bogus"}).status_code == 422
    e = client.get("/api/radar/report", params={"brand": "nobrand"}).json()
    assert e["totals"]["sites"] == 0 and e["sites"] == [] and e["period"]["from"] is None


def test_report_csv_is_defanged_and_formula_safe(client, app):
    c = _seed(app)
    upsert(c, {"host": "=cmd.example-adcb.top", "registrable_domain": "example-adcb.top", "brand": "adcb", "method": "t", "score": 70, "reasons": []}, "ct")
    r = client.get("/api/radar/report.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    body = r.text.lstrip("\ufeff").splitlines()
    assert body[0].startswith("host_defanged,status,listed_now")
    assert len(body) == 1 + 4
    assert all("[.]" in line.split(",")[0] for line in body[1:])
    assert any(line.startswith("'=cmd[.]") for line in body[1:])   # spreadsheet formula neutralised


def test_report_analysis_is_computed_from_findings(client, app):
    c = _seed(app)
    for h in ("netflix-login.pages.dev", "netflix-verify.pages.dev", "netflix-support.top"):
        f = classify_domain(h) or {"host": h, "registrable_domain": h, "brand": "netflix", "method": "t", "score": 60, "reasons": []}
        f.update(brand="netflix", method="confirmed_feed", score=95)
        upsert(c, f, "certpl")
    a = client.get("/api/radar/report", params={"since_hours": 168}).json()["analysis"]
    # comparison: everything is new this week, nothing before -> change is undefined, never invented
    assert a["comparison"]["previous"]["sites"] == 0 and a["comparison"]["change_pct"]["sites"] is None
    inf = a["infrastructure"]
    assert {"label": "pages.dev", "count": 2} in inf["platforms"]
    assert any(w["label"] == "login" for w in inf["words"]) and not any(w["label"] == "pay" for w in inf["words"])
    pr = {p["brand"]: p for p in a["priorities"]}
    assert pr["netflix"]["count"] == 3 and pr["netflix"]["listed_now"] == 3
    assert {"key": "platform", "platform": "pages.dev", "n": 2, "pct": 67} in pr["netflix"]["actions"]
    assert a["lifetime"]["delisted"] == 0 and a["lifetime"]["still_listed"] >= 3
    # without a period there is nothing to compare against
    assert client.get("/api/radar/report").json()["analysis"]["comparison"] is None


def test_campaign_ids_are_unique_even_when_groups_share_a_broad_trait():
    from ai.threat_intelligence.campaigns import analyze_relationships
    items = []
    for k, (a, b) in enumerate([("apple-help-one.com", "apple-help-two.com"), ("apple-id-red.com", "apple-id-blue.com")]):
        for j, h in enumerate((a, b)):
            items.append({"id": k * 10 + j + 1, "host": h, "registrable_domain": h, "brand": "apple", "sources": ["certpl"],
                          "first_seen": f"2026-11-2{k}T10:0{j}:00+00:00", "last_seen": f"2026-11-2{k}T10:0{j}:00+00:00",
                          "url": None, "evidence": {}, "confirmed": True, "method": "confirmed_feed", "score": 90, "reasons": []})
    camps, _ = analyze_relationships(items)
    ids = [c["id"] for c in camps]
    assert len(ids) == len(set(ids))
