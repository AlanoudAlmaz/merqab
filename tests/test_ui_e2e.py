"""Browser end-to-end checks (Playwright + Chromium). Skipped automatically if unavailable.

Covers: public analysis journey, Arabic/RTL switching, responsive navigation, investigator sign-in,
case creation and evidence analysis, and absence of JavaScript errors.
"""
import os
import shutil
import socket
import threading
import time

import pytest

pw = pytest.importorskip("playwright.sync_api")

from backend.app import db as dbm  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.security import hash_password  # noqa: E402
from tests.conftest import PASSWORD, make_settings  # noqa: E402

CHROME = os.getenv("MIRQAB_CHROME") or shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")


DB: dict = {}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn
    tmp = tmp_path_factory.mktemp("e2e")
    s = make_settings(tmp)
    DB["path"] = s.db_path
    app = create_app(s)
    c = dbm.connect(s.db_path)
    c.execute("INSERT INTO users (username, pw_hash, role, created_at) VALUES (?,?,?,?)", ("inv1", hash_password(PASSWORD), "investigator", dbm.now()))
    c.commit()
    # radar findings stored exactly as the live service stores them
    from ai.threat_intelligence.radar import classify_domain, parse_feed_line
    from backend.app.radar import upsert
    for u in ("https://roblox.ly/users/9912/profile", "https://www.roblox.com.am/users/5512/profile"):
        f = parse_feed_line(u)
        f.update(method="confirmed_feed", score=95, reasons=[{"en": "Listed by OpenPhish", "ar": "مدرج"}])
        upsert(c, f, "openphish", u, {"feed": "test"})
    upsert(c, classify_domain("emiratesnbd-secure.xyz"), "ct", evidence={"log": "Test log"})
    upsert(c, classify_domain("emiratesnbd-secure.top"), "ct", evidence={"log": "Test log"})
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(50):
        if srv.started:
            break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/"
    srv.should_exit = True
    th.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            fake_media = ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"]   # Call Guardian tests
            b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox", *fake_media]) if CHROME else p.chromium.launch(args=fake_media)
        except Exception as e:  # pragma: no cover
            pytest.skip(f"Chromium not available: {e}")
        yield b
        b.close()


def _page(browser, **kw):
    ctx = browser.new_context(**kw)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e) + " | " + (e.stack or "")[:900]))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    return page, errors


def test_public_protection_journey(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/home")
    page.fill("#pin", "Your bank account will be blocked within 2 hours. Send the OTP code now.")
    page.click("form.hero button[type=submit]")
    page.wait_for_selector("#result")
    assert "Critical risk" in page.inner_text(".risk") or "High risk" in page.inner_text(".risk")
    assert "Do not share any code" in page.inner_text(".action-card")
    page.wait_for_selector(".rx-acc:not([hidden])")
    assert "Detection accuracy" in page.inner_text(".rx-acc") and "%" in page.inner_text(".rx-acc")
    page.click("text=No, it's wrong")
    page.wait_for_selector("text=Thank you")
    assert not errors, errors


def test_benign_message_shows_low_risk(server, browser):
    page, errors = _page(browser)
    page.goto(server + "#/protect")  # old route still works (merged into Home)
    page.fill("#pin", "Hi Sara, the meeting moved to 3pm tomorrow. See you!")
    page.click("form.hero button[type=submit]")
    page.wait_for_selector("#result")
    assert "Low risk" in page.inner_text(".risk")
    assert not errors, errors


def test_arabic_rtl_switch(server, browser):
    page, errors = _page(browser)
    page.goto(server + "#/home")
    page.wait_for_selector(".lang-btn")  # app initialised
    page.click(".lang-btn"); page.click(".lang-menu li[data-code='ar']")
    page.wait_for_selector("html[dir=rtl]", state="attached")
    assert page.evaluate("document.documentElement.lang") == "ar"
    assert "تحقّق قبل أن تتصرّف" in page.inner_text("h1")
    page.click(".lang-btn"); page.click(".lang-menu li[data-code='en']")
    page.wait_for_selector("html[dir=ltr]", state="attached")
    assert not errors, errors


def test_responsive_navigation(server, browser):
    mobile, errors = _page(browser, viewport={"width": 390, "height": 844}, is_mobile=True)
    mobile.goto(server + "#/home")
    mobile.wait_for_selector("#bottomnav a")
    assert mobile.is_visible("#bottomnav") and not mobile.is_visible("#topnav")
    no_overflow = mobile.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    assert no_overflow
    desktop, _ = _page(browser, viewport={"width": 1280, "height": 900})
    desktop.goto(server + "#/home")
    desktop.wait_for_selector("#topnav a")
    assert desktop.is_visible("#topnav") and not desktop.is_visible("#bottomnav")
    assert not errors, errors


def test_no_staff_or_case_ui_in_public_app(server, browser):
    """Case management stays a backend capability (API + its tests); the public app exposes none of it."""
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    for old in ("#/investigate", "#/investigate/1", "#/reports", "#/login", "#/radar/cases", "#/radar/case/1"):
        page.goto(server + old)
        page.wait_for_selector(".cst")
        assert page.url.endswith("#/radar")
        assert page.locator(".drawer, form.login, .cst-cases").count() == 0
    assert page.locator("text=Sign in").count() == 0
    assert not errors, errors


def test_navigation_is_consolidated(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/home")
    page.wait_for_selector("#topnav a")
    labels = page.locator("#topnav a").all_inner_texts()
    assert labels == ["Check", "Live Radar", "Community"]
    page.goto(server + "#/radar")
    page.wait_for_selector(".pl")
    assert not errors, errors


def test_threat_constellation_workflow(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/radar")
    page.wait_for_selector(".cst-graph canvas")  # graph rendered from /api/radar/graph
    label = page.get_attribute(".cst-graph", "aria-label")
    assert "4 indicators" in label and "2 relationships" in label
    # accessible list view: same data, same detail panel
    page.click(".seg2 button:has-text('List')")
    page.click(".cst-list button:has-text('emiratesnbd-secure[.]xyz')")
    panel = page.inner_text(".cst-panel")
    assert "Detected" in panel and "Test log" in panel and "Strong" in panel and "naming pattern" in panel
    assert "Suspected" in panel
    # full intelligence opens in context: DNA graph, evidence, prevention
    page.click(".cst-panel button:has-text('Explore intelligence')")
    page.wait_for_selector(".iv-graph canvas")
    iv = page.inner_text(".iv")
    assert "Detect" in iv and "Understand" in iv and "Do not open the link" in iv and "Test log" in iv
    page.keyboard.press("Escape")
    page.wait_for_selector(".iv", state="detached")
    # campaign selection shows how it developed
    page.click(".cst-list tr.grp button >> nth=0")
    assert "How it developed" in page.inner_text(".cst-panel")
    # filter confirmed only
    page.click(".seg2 button:has-text('confirmed')")
    page.locator(".cst-list button:has-text('emiratesnbd')").first.wait_for(state="detached")
    page.wait_for_selector(".cst-list button:has-text('roblox[.]ly')")
    assert "emiratesnbd" not in page.inner_text(".cst-list")
    # Smart Protection integration: check a finding's link
    page.click(".cst-list button:has-text('roblox[.]ly')")
    page.click(".cst-panel button:has-text('Check this link')")
    page.wait_for_selector("#result .radar-hit")
    assert "confirmed phishing list" in page.inner_text("#result .radar-hit")
    assert not errors, errors


def test_constellation_deep_link_and_mobile(server, browser):
    page, errors = _page(browser, viewport={"width": 390, "height": 844}, is_mobile=True)
    cid = page.request.get(server + "api/radar").json()["campaigns"][0]["id"]
    page.goto(server + f"#/radar/{cid}")  # deep link used by Check results and case analysis
    page.wait_for_selector(".cst-graph canvas")
    page.wait_for_selector(".cst-panel :text('How it developed')")
    assert cid in page.inner_text(".cst-panel")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    assert not errors, errors


def test_constellation_updates_only_from_stored_intelligence(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/radar")
    page.wait_for_selector(".cst-graph canvas")
    before = page.get_attribute(".cst-graph", "aria-label")
    page.wait_for_timeout(16000)  # one refresh with no new data: nothing new appears
    assert page.locator(".cst .badge.medium").is_hidden()
    # a real finding is stored (as the radar service would) and a related one shares its naming template
    from ai.threat_intelligence.radar import classify_domain
    from backend.app.radar import upsert
    c = dbm.connect(DB["path"])
    upsert(c, classify_domain("paypal-secure-update.xyz"), "ct", evidence={"log": "Test log"})
    upsert(c, classify_domain("paypal-secure-update.top"), "ct", evidence={"log": "Test log"})
    c.close()
    assert page.get_attribute(".cst-graph", "aria-label") == before
    page.wait_for_selector(".cst-toolbar :text('2 new since you opened this page')", timeout=20000)
    after = page.get_attribute(".cst-graph", "aria-label")
    assert after != before and "relationships" in after  # graph updated in place, not rebuilt from scratch
    # the live ticker reports the real new detection, flagged as new
    page.wait_for_selector(".cst-tick.new:has-text('paypal-secure-update')", timeout=10000)
    page.click(".seg2 button:has-text('List')")
    assert "paypal-secure-update[.]xyz" in page.inner_text(".cst-list")
    assert not errors, errors


def test_constellation_motion_reflects_real_state(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/radar")
    page.wait_for_selector(".cst-graph canvas")
    # countdown to the next real refresh, and a ticker built only from stored findings
    assert "Next update in" in page.inner_text(".cst-hud")
    tick = page.inner_text(".cst-ticker")
    hosts = [n["host"] for n in page.request.get(server + "api/radar/graph").json()["nodes"]]
    assert any(h.replace(".", "[.]")[:20] in tick for h in hosts), tick
    # hovering the graph never throws; leaving the page stops all motion loops
    box = page.locator(".cst-graph").bounding_box()
    for x in range(10, 90, 8):
        page.mouse.move(box["x"] + box["width"] * x / 100, box["y"] + box["height"] / 2)
    page.goto(server + "#/")
    page.wait_for_timeout(600)
    assert not errors, errors


def test_constellation_respects_reduced_motion(server, browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, reduced_motion="reduce")
    page = ctx.new_page(); errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(server + "#/radar")
    page.wait_for_selector(".cst-graph canvas")
    assert page.locator(".cst-sweep").evaluate("e => getComputedStyle(e).display") == "none"
    assert not errors, errors
    ctx.close()


def test_constellation_enlarge_and_restore(server, browser):
    for vp, mobile in (({"width": 1280, "height": 900}, False), ({"width": 390, "height": 844}, True)):
        page, errors = _page(browser, viewport=vp, is_mobile=mobile)
        page.goto(server + "#/radar")
        page.wait_for_selector(".cst-graph canvas")
        small = page.locator(".cst-graph").bounding_box()
        page.click(".cst-expand")
        page.wait_for_selector(".cst-stage.max")
        page.wait_for_timeout(300)
        big = page.locator(".cst-graph").bounding_box()
        assert big["height"] > small["height"] and big["width"] >= small["width"] - 1
        assert page.get_attribute(".cst-expand", "aria-pressed") == "true"
        page.keyboard.press("Escape")
        page.wait_for_selector(".cst-stage:not(.max)")
        page.wait_for_timeout(300)
        assert abs(page.locator(".cst-graph").bounding_box()["height"] - small["height"]) < 2
        assert not errors, errors


def test_community_pulse_decoder_and_board(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/community")
    page.wait_for_selector(".pu")
    # awareness hero: personal progress only — Community takes nothing from the radar
    assert page.locator(".pl-stat").count() == 3
    assert page.locator(".pu-ticker").count() == 0 and "roblox" not in page.inner_text("#cm-pulse").lower()
    # Decoder = situation + scam chain: the chain is explorable before choosing anything
    assert page.locator(".dc-node").count() == 4
    page.click(".dc-node >> nth=3")
    page.click(".dc-result .dc-tacs button >> nth=0")
    assert page.inner_text(".dc-result .dc-explain") != ""
    page.click(".dc-sits button[data-k='official']")
    v = page.inner_text(".dc-result").lower()
    assert "pause and verify" in v and "doesn’t prove" in v                 # never called safe
    page.click(".dc-q[data-k='rush']")
    assert "Pressure" in page.inner_text(".dc-node.here")                   # marker moves to the pressure step
    assert "the ask" in page.inner_text(".dc-next").lower() or page.locator(".dc-next").count() == 1
    page.click(".dc-q[data-k='money']")
    v = page.inner_text(".dc-result")
    assert "STOP" in v.upper() and "official number" in v
    assert "The ask" in page.inner_text(".dc-node.here")
    assert page.locator(".dc-found-chips span").count() >= 3                 # real engine tactic labels
    assert page.get_attribute(".dc-actions a[href^='https://wa.me/']", "href").startswith("https://wa.me/?text=")
    page.click(".dc-sits button[data-k='video']")
    assert "caller ID can be faked" in page.inner_text(".dc-result")
    assert "null" not in page.inner_text(".dc-result")
    # signal board keeps the anonymised report form and impact numbers
    assert page.locator("#cm-board textarea").count() == 1
    assert page.locator(".bd-impact .stat").count() == 5
    assert not errors, errors


def test_scam_theater_branches_and_rapid_round(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.add_init_script("window.matchMedia = (q) => ({ matches: q.includes('reduce'), addEventListener(){}, removeEventListener(){} })")
    page.goto(server + "#/community")
    page.wait_for_selector(".th-ep")
    assert page.locator(".th-ep").count() == 6
    page.click(".th-ep:has-text('bank')")
    page.wait_for_selector(".th-decide", timeout=40000)                    # pauses at the decision
    assert page.locator(".th-choice").count() == 3
    page.click(".th-choice:has-text('number on my card')")
    page.wait_for_selector(".th-verdict.ok", timeout=20000)
    deb = page.inner_text(".th-debrief")
    assert "No bank ever asks for a code" in deb and "Artificial urgency" in deb   # real engine tactic labels
    assert '"bank":{"safe":true' in page.evaluate("localStorage.getItem('mirqab.theater')")
    page.click(".th-next button:has-text('Use it in real life')")             # film -> decoder with that situation
    page.wait_for_selector(".dc-sits button[data-k='official'].on")
    assert page.locator("#cm-happened a[href='tel:8002626']").count() == 1   # inline "if it already happened" channels
    # the test still uses the real engine's highlights
    page.click("#cm-test .rr-scam")
    page.wait_for_selector(".rr-res")
    assert "MERQAB engine" in page.inner_text(".rr-res")
    assert not errors, errors


def test_family_circle_and_emergency_mode(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/community")
    page.wait_for_selector(".fc-node")
    assert len(page.inner_text(".fc-word").split()) == 2
    page.click(".fc-node >> nth=0", force=True)
    assert "1/5" in page.inner_text(".fc-pct")
    assert '"word":true' in page.evaluate("localStorage.getItem('mirqab.plan')")
    page.reload(); page.wait_for_selector(".fc-node")
    assert "1/5" in page.inner_text(".fc-pct") and "20%" in page.inner_text(".pu-stats")
    page.click(".fc-auds button:has-text('Students')")
    txt = page.inner_text(".fc-wa-b")
    assert "Students" in txt and "Never share a code" in txt
    assert page.get_attribute(".fc-actions a", "href").startswith("https://wa.me/?text=")
    # emergency mode: official channels as real links, actions can be ticked off, Esc closes
    page.click(".pu-sos")
    page.wait_for_selector(".em")
    assert page.locator(".em a[href='tel:8002626']").count() == 1
    assert page.locator(".em a[href='sms:2828']").count() == 1
    assert page.locator(".em a[href^='https://u.ae/']").count() == 1
    page.click(".em-done >> nth=0")
    assert page.locator(".em-act.done").count() == 1
    page.keyboard.press("Escape")
    assert page.locator(".em").count() == 0
    assert not errors, errors


def test_one_protection_journey(server, browser):
    """Home warning → intelligence → Family Shield (same scam) → back → Check what you received."""
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    page.goto(server + "#/home")
    page.wait_for_selector(".warn-row[href^='#/radar/C']")
    page.click(".warn-row[href^='#/radar/C']")
    page.wait_for_selector(".iv-graph canvas")
    iv = page.inner_text(".iv").lower()   # section labels are styled upper-case
    assert "what happens next" in iv and "don't" in iv and "check what you received" in iv
    assert "confirmed" in page.inner_text(".iv-basis")
    page.click(".iv-personas button:has-text('Seniors')")
    assert "no bank or police officer" in page.inner_text(".iv-tip")
    page.click(".iv-act:has-text('See how this scam works')")
    page.wait_for_selector(".cm .jb")
    assert page.locator(".dc-node.hot").count() >= 1           # the campaign's own tactics are marked
    assert "The ask" in page.inner_text(".dc-node.open")      # opens at the step where it causes harm
    page.click(".jb-btn")                                      # back to the same intelligence
    page.wait_for_selector(".iv-graph canvas")
    page.click(".iv-act:has-text('Check what you received')")
    page.wait_for_selector(".hero .jb")
    page.fill("#pin", "Verify your account now https://roblox.ly/users/1/profile")
    page.click(".hero button[type=submit]")
    page.wait_for_selector(".rh")
    assert "Same campaign you were exploring" in page.inner_text(".rh")
    assert "Confirmed phishing" in page.inner_text(".rh")
    assert not errors, errors


def test_public_surfaces_are_simple(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 900})
    for old in ("#/settings", "#/login"):                           # removed pages redirect
        page.goto(server + old)
        page.wait_for_timeout(300)
        assert "settings" not in page.url and "login" not in page.url
    page.goto(server + "#/home")
    page.wait_for_selector(".hero")
    assert page.locator("#simpleBtn").count() == 0                   # header: navigation + language only
    page.goto(server + "#/radar")
    page.wait_for_selector(".cst-graph canvas")
    assert "null" not in page.inner_text(".cst-toolbar")
    assert not page.is_visible(".cst-select")                      # target filter lives behind "Filters"
    page.click(".cst-filters summary")
    assert page.is_visible(".cst-select")
    assert page.evaluate("document.body.dataset.page") == "radar"
    assert not errors, errors


def test_landing_entrance(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 800})
    page.goto(server)                                   # site root opens the entrance
    page.wait_for_selector(".ld-enter")
    assert page.locator(".topbar").is_hidden()
    assert page.locator(".ld-note, .ld-hint").count() == 0
    assert page.locator(".ld-how").count() == 0        # no demo button: one action only
    # the falcon eye: original artwork + live layers (rings, sweep, pupil), no old sphere
    assert page.locator(".fx-svg image[href='/assets/falcon.png']").count() == 1
    assert page.locator(".fx-pupil, .fx-spin, .fx-sweep, .fx-orbit").count() == 4
    page.mouse.move(1200, 120); page.wait_for_timeout(600)
    assert "translate" in (page.get_attribute(".fx-pupil", "transform") or "")      # pupil follows the pointer
    was_dark = page.evaluate("document.documentElement.classList.contains('dark')")
    page.click(".ld-theme")                                                         # day / night on the entrance
    assert page.evaluate("document.documentElement.classList.contains('dark')") != was_dark
    page.click(".ld-theme")
    assert page.locator(".ld-lang").count() == 1                                    # language picker on the entrance
    brand = page.inner_text(".ld-brand")
    assert brand.count("MERQAB") == 1 and brand.count("مرقاب") == 1
    page.click(".ld-enter")
    page.wait_for_selector(".hero", timeout=15000)     # straight into the app, no login or onboarding
    assert page.url.endswith("#/home") and page.locator(".topbar").is_visible()
    page.goto(server)                                   # once per visit
    page.wait_for_selector(".hero")
    page.goto(server + "#/radar")                       # deep links never see the entrance
    page.wait_for_selector(".cst")
    assert page.locator(".ld").count() == 0
    assert not errors, errors


def test_logo_returns_to_landing(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 800})
    for start in ("#/home", "#/radar", "#/community"):
        page.goto(server + start)
        page.wait_for_selector(".topbar .brand")
        page.evaluate("window.__noReload = true")
        page.click(".topbar .brand")
        page.wait_for_selector(".ld-enter")                 # the entrance, via the router
        assert page.evaluate("window.__noReload") is True    # no full page reload
    page.click(".ld-lang")                                   # works the same after switching language
    page.click(".ld-enter")
    page.wait_for_selector(".hero", timeout=15000)
    page.click(".topbar .brand")
    page.wait_for_selector(".ld-enter")
    assert not errors, errors


def test_live_link_search_and_advanced_filters(server, browser):
    page, errors = _page(browser, viewport={"width": 1366, "height": 900})
    page.goto(server + "#/radar")
    page.wait_for_selector(".rs-input")
    page.wait_for_selector(".cst-graph canvas")
    # typing narrows the view; submitting checks the link against everything stored (defanged input is accepted)
    page.fill(".rs-input", "emiratesnbd")
    page.locator(".rs-hint", has_text="2 matching").wait_for()
    page.fill(".rs-input", "hxxps://roblox[.]ly/users/9912/profile")
    page.press(".rs-input", "Enter")
    page.wait_for_selector(".rs-panel")
    assert "listed as phishing right now" in page.inner_text(".rs-v").lower()
    assert "never opens" in page.inner_text(".rs-panel")
    page.click(".rs-v button:has-text('Show on radar')")
    page.wait_for_selector(".cst-panel-body:not(.rs-panel)")
    assert "roblox" in page.inner_text(".cst-panel")
    # a site MIRQAB has never seen is not called safe
    page.fill(".rs-input", "emiratesnbd-refund.xyz"); page.press(".rs-input", "Enter")
    page.wait_for_selector(".rs-panel")
    assert "not in merqab live" in page.inner_text(".rs-v").lower()
    assert "tracking" in page.inner_text(".rs-panel")
    # advanced filters: source + risk, shown as removable chips
    page.click(".cst-filters summary")
    page.select_option(".fl-field:has-text('Source') select", "ct")
    page.wait_for_selector(".cst-chip")
    page.click(".cst-filters summary")
    assert "Newly secured" in page.inner_text(".cst-chips")
    page.click(".cst-filters summary")
    assert "Showing" in page.inner_text(".fl-foot")
    page.click(".fl-foot button:has-text('Reset')")
    page.locator(".cst-chip").wait_for(state="detached")
    assert not errors, errors


def test_theme_toggle_dark_by_default_and_remembered(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 800})
    page.goto(server + "#/home")
    page.wait_for_selector("#themeBtn svg")
    assert page.evaluate("document.documentElement.classList.contains('dark')")
    assert page.get_attribute("#themeBtn", "aria-label") == "Switch to light mode"
    page.click("#themeBtn")
    assert not page.evaluate("document.documentElement.classList.contains('dark')")
    page.reload(); page.wait_for_selector("#themeBtn svg")
    assert not page.evaluate("document.documentElement.classList.contains('dark')")
    assert page.get_attribute("#themeBtn", "aria-label") == "Switch to dark mode"
    page.click("#themeBtn")
    assert not errors, errors


def test_language_menu_nine_languages_rtl_and_fallback(server, browser):
    page, errors = _page(browser, viewport={"width": 1280, "height": 800})
    page.goto(server + "#/home")
    page.wait_for_selector(".lang-btn")
    page.click(".lang-btn")
    codes = page.eval_on_selector_all(".lang-menu li", "els => els.map(e => e.dataset.code)")
    assert codes == ["ar", "en", "ur", "hi", "tl", "zh", "fr", "es", "ru"]
    page.click(".lang-menu li[data-code='ur']")
    page.locator("html[lang='ur'][dir='rtl']").wait_for(state="attached")
    assert "جانچیں" in page.inner_text(".topnav")
    # keyboard: open with ArrowDown, move, choose with Enter
    page.focus(".lang-btn"); page.keyboard.press("ArrowDown")
    page.keyboard.press("ArrowDown"); page.keyboard.press("Enter")   # ur -> hi
    page.locator("html[lang='hi'][dir='ltr']").wait_for(state="attached")
    assert "जाँचें" in page.inner_text(".topnav")
    page.reload(); page.locator("html[lang='hi']").wait_for(state="attached")
    # no raw i18n keys anywhere on the main pages
    for route in ("#/home", "#/community", "#/radar"):
        page.goto(server + route); page.wait_for_timeout(1200)
        body = page.inner_text("body")
        assert not any(k in body for k in ("rn.title", "sh.title", "home.title", "cst.filters", "rs.ph")), route
    page.click(".lang-btn"); page.click(".lang-menu li[data-code='en']")
    assert not errors, errors


def test_generate_report_from_radar(server, browser):
    page, errors = _page(browser, viewport={"width": 1366, "height": 900})
    page.goto(server + "#/radar")
    page.wait_for_selector(".rp-open-btn")
    page.click(".rp-open-btn")
    page.wait_for_selector(".rp-form")
    page.select_option(".rp-field:has-text('Period') select", "")      # all time
    page.select_option(".rp-field:has-text('Status') select", "confirmed")
    page.click(".rp-kind:has-text('Technical')")
    page.click(".rp-form button[type=submit]")
    page.wait_for_selector(".rp-doc")
    doc = page.inner_text(".rp-doc")
    assert "Threat intelligence report" in doc and "MERQAB" in doc
    assert "confirmed by public lists" in doc and "roblox" in doc.lower()
    assert "emiratesnbd" not in doc.lower()                              # status filter applied
    assert page.locator(".rp-long .rp-table tbody tr").count() == 2
    assert "[.]" in page.inner_text(".rp-long .rp-table")
    assert "Priority actions by brand" in doc and "Attacker infrastructure" in doc
    assert "Key findings" in doc and "TLP:CLEAR" in doc and page.locator(".rp-toc li").count() >= 8
    assert page.locator(".rp-donut").count() == 2
    href = page.get_attribute(".rp-toolbar a[download]", "href")
    assert href.startswith("/api/radar/report.csv?") and "status=confirmed" in href
    page.click(".rp-toolbar button:has-text('Change filters')")
    page.wait_for_selector(".rp-form")
    page.keyboard.press("Escape")
    assert page.locator(".rp-overlay").count() == 0
    assert not errors, errors


def test_deepfake_scan_tab(server, browser, tmp_path):
    png = tmp_path / "gen.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + b"tEXtparameters\x00portrait, Steps: 30, Sampler: DPM++")
    p, errors = _page(browser, viewport={"width": 1280, "height": 900})
    p.goto(server + "#/home")
    p.get_by_role("tab", name="Deepfake scan").click()
    p.locator("#pmedia").set_input_files(str(png))
    p.click("form.hero button[type=submit]")
    res = p.locator(".df-res")
    res.wait_for()
    assert "AI-generation markers found" in res.inner_text()
    assert "Stable Diffusion" in res.inner_text()
    assert "not stored" in res.inner_text()
    assert not errors, errors


def test_theater_voice_follows_page_language(server, browser):
    fake = """
      window.__spoken = [];
      window.speechSynthesis.speak = (u) => { window.__spoken.push({lang: u.lang, text: u.text}); setTimeout(() => u.onend && u.onend(), 50); };
    """
    for lang, expect in (("ar", "ar"), ("en", "en")):
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        ctx.add_init_script(f"try {{ localStorage.setItem('mirqab.lang', '{lang}'); }} catch (e) {{}}" + fake)
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(server + "#/community")
        page.wait_for_selector(".th-btn")
        page.locator(".th-btn", has_text="🔇").first.click()          # sound on
        page.locator(".th-btn", has_text="▶").first.click()           # play
        first = None
        for _ in range(60):
            first = page.evaluate("() => window.__spoken[0] || null")
            if first:
                break
            page.wait_for_timeout(250)
        assert first, "nothing was spoken"
        assert first["lang"].startswith(expect), first
        is_arabic = any("\u0600" <= ch <= "\u06ff" for ch in first["text"])
        assert is_arabic == (expect == "ar"), first
        assert not errors, errors
        ctx.close()

def test_shield_dashboard_honest_states(server, browser):
    page, errors = _page(browser, viewport={"width": 390, "height": 844}, is_mobile=True)
    page.goto(server + "#/shield")
    page.wait_for_selector(".sh-hero")
    assert "not activated" in page.inner_text(".sh-hero h1")
    caps = page.inner_text(".sh-caps")
    for label in ("Message Guardian", "Live Call Guardian", "Phone-call audio", "Automatic SMS filtering"):
        assert label in caps
    assert "Unavailable" in caps and "Native app (roadmap)" in caps
    assert page.locator(".bottomnav a[href='#/shield']").count() == 0      # not a menu tab
    page.goto(server + "#/home")
    page.wait_for_selector(".ms")                                          # lives inside the Check page
    assert page.locator(".ms a[href='#/shield/call']").count() == 1 and page.locator(".ms a[href='#/shield']").count() == 1
    assert not errors, errors


def test_call_guardian_live_flow(server, browser):
    fake = """
      class FakeSR { start(){ const s=this; ['معك موظف من البنك','حسابك بيتسكر اليوم','عطني الرمز اللي وصلك الحين'].forEach((t,i)=>
        setTimeout(()=>{ const r=[{transcript:t}]; r.isFinal=true; s.onresult&&s.onresult({resultIndex:0,results:[r]}); }, 300+i*700)); }
        stop(){} abort(){} }
      window.webkitSpeechRecognition = FakeSR; window.SpeechRecognition = FakeSR;"""
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, permissions=["microphone"])
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.add_init_script(fake)
    page.goto(server + "#/shield/call")
    page.click(".cg-start")
    assert "consent" in page.inner_text(".cg-status").lower()       # refuses without consent
    page.check("#cg-consent")
    page.click(".cg-start")
    page.wait_for_timeout(4000)
    assert "Critical" in page.inner_text(".cg-gauge")
    assert "عطني الرمز" in page.inner_text(".cg-tactics")
    page.click(".cg-start")
    assert "microphone is off" in page.inner_text(".cg-status")
    assert "null" not in page.inner_text(".cg-transcript")
    hist = page.evaluate("() => JSON.parse(localStorage.getItem('mirqab.history'))")
    assert hist[0]["source"] == "call" and hist[0]["level"] == "critical"
    assert not errors, errors
    ctx.close()

