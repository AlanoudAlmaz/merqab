# MIRQAB | مِرقاب

**AI-assisted cybercrime prevention, investigation and community protection — bilingual (Arabic / English).**

Built for the SCAMSHIELD AI Hackathon. MIRQAB is a working prototype: every feature described as *implemented* below runs in this repository and is covered by automated tests. Capabilities that need external models or services are labelled *integration-ready* and are reported as inactive in the app itself (Settings → "What this installation can do").

---

## 1. Project Overview

MIRQAB connects three things that are usually separate products:

| Module | Who it serves | What it does |
|---|---|---|
| **Smart Protection** (Solution A) | Public, seniors, students, families | Analyses a suspicious message, conversation, link, screenshot or e-mail, explains the risk with evidence, and tells the person the *specific* harmful action to avoid next. |
| **Investigation** (Solution B) | Authorised investigators | Case management, immutable evidence with SHA-256 integrity, indicator correlation (within and across cases), incident timeline reconstruction, reviewable findings and report export. |
| **Live Threat Radar** | Everyone, reviewers | Watches public Certificate Transparency logs for newly certified domains that imitate protected brands (UAE banks, government services, couriers, global platforms) and loads the OpenPhish confirmed-phishing feed, so links are flagged *before* anyone checks them. |
| **Community Intelligence** | Everyone | Turns *verified* investigation results into anonymised, bilingual public warnings through a two-person validation workflow. Published warnings then strengthen prevention. |

All three share one behavioural-intelligence engine (`ai/`).

## 2. Problem Statement

Most scam losses happen at a single moment: the victim shares a one-time code, transfers money, installs a remote-access app or opens a link. Conventional tools either classify a message as "spam / not spam" without telling the person what to do, or they stop at detection and never feed what investigators learn back to the public. Arabic-language scams are additionally under-served by English-centric tools.

## 3. Proposed Solution

A single loop — **Analyse → Investigate → Validate → Extract patterns → Improve prevention** — with explicit human checkpoints:

1. A person checks content in Smart Protection and receives an explainable risk result plus a pre-harm intervention.
2. Investigators open cases, add evidence, run the same engine across all evidence, and correlate indicators.
3. Investigators verify individual findings (automated findings are never "verified" by themselves).
4. From a case with verified findings, an investigator drafts a community alert; a *different* reviewer must approve it after a checklist and an automated personal-data gate.
5. Only published alerts are shown publicly and only their indicators are used by the prevention engine.

## 4. Core Innovation

Technical differentiation, as implemented (no claims of global novelty):

- **Pre-harm intervention, not just a score.** The engine maps detected tactics to the concrete harmful action being requested (share code, transfer money, install remote access, share ID, open link) and returns bilingual "do now" and "if you already did it" steps. When a message is still at the *story/pressure* stage, it predicts the likely next request from the fraud pattern and warns about it in advance (marked as an unverified prediction).
- **Multi-stage scam understanding.** Conversations are parsed into messages (WhatsApp exports, `[time] Name:` and `Name:` formats) and tracked through four stages — contact → story → pressure → request — with escalation detection per sender.
- **Evidence-grounded explainability.** Every rule indicator carries the exact quote and character offsets from the original text (Arabic normalisation keeps an offset map), and results are separated into *observed evidence*, *rule indicators*, *inferences* and (in investigations) *human-verified findings*.
- **Contextual-inconsistency reasoning.** e.g. "claims to be a bank **and** asks for an OTP", "message names Brand X but the link is not X's domain", "pay first to receive a prize/job".
- **Grounded, injection-resistant LLM layer (optional).** If configured, the LLM's claimed tactics are accepted only when its quote literally exists in the input; it can add indicators but can never lower the deterministic score. Instructions aimed at the analyser are themselves treated as a scam indicator.
- **Cross-incident correlation with privacy limits.** Normalised indicators (phones, domains, IBANs, wallets, e-mails, last-4 of cards) link evidence and cases without identifying or accusing individuals.
- **Validated community intelligence.** Two-person rule, checklist, PII gate, and real usage-based impact metrics (no seeded numbers).

## 5. Prevention Module (Smart Protection)

Inputs: message text, full conversation, link, or file (PNG/JPG/WEBP screenshot via OCR, PDF, TXT, EML e-mail with header checks). Files submitted publicly are processed in memory and **not stored**.

Output (see `ai/pipeline.py`):
- Risk level (low / caution / high / critical), score 0–100 with a traceable point breakdown, confidence and explicit uncertainty notes ("no indicators does not prove safety").
- **Do this now** card + "Already did it?" recovery steps + predicted next request.
- Indicators with plain-language explanations and highlighted quotes.
- Contradictions, link analysis (never fetched), conversation stage strip, community-warning matches.
- Feedback ("helpful" / "wrong") used to measure false positives.
- **Simple mode** (Settings) enlarges text and hides technical sections for seniors.

### Entrance — "Before the Threat Reaches You"

Opening the site root (once per visit, or any time at `#/welcome`) shows a short, full-screen entrance (`frontend/js/landing.js`). It uses a CSP-safe 2D canvas with 3D projection and no external libraries.

- **A living lattice core.** It breathes and swells toward the pointer. Incoming red signals are linked by the core and turn cyan as they are absorbed. Pointing at a signal, or tapping, sends a scan pulse that catches it.
- **No live data on this page.** The visuals are abstract; live detections appear only in MIRQAB LIVE.
- **One action: *Enter MIRQAB | ادخل مِرقاب*.** The core expands around the viewer into a light fade, and the app opens at `#/home`. There is no login or onboarding. Deep links such as `#/radar` skip the entrance.
- **Back to the entrance.** The header logo links to `#/welcome` from every page. The router handles it without a reload, in both languages.
- **Accessibility.** The page is responsive and bilingual. With reduced motion it shows a single still frame.

### Interface principles

- **Public wording on LIVE, provenance kept.**
  - The overview shows **Digital Threat Signals → MIRQAB AI Engine → Preventive Intelligence**. The two signals are *Newly secured websites* (sampled Certificate Transparency logs) and *Verified phishing reports* (OpenPhish).
  - Every number is the real measured value: certificates analysed, measured rate, confirmed, suspected and linked campaigns.
  - The technical source names stay available for verification in three places: the tooltip on each signal, the ⓘ coverage note, and each site's evidence (log name, entry index, issuer, certificate time, feed listing). The source names also stay in the API and the audit trail.

- **Public first.**
  - The navigation has three tabs: Check, Live Radar, Community.
  - The public app has no sign-in, staff, case or review screens. Old links (`#/login`, `#/investigate…`, `#/reports`, `#/radar/case…`) redirect to LIVE.
  - Case management, alert review and approval remain **backend capabilities**. They are available through the authenticated API (`/api/auth/login`, `/api/cases…`, `/api/community/review…`) with role checks, the two-person rule and audit logging. No interface exposes them.
- **Home.** The check box comes first. Above the headline, a live pill shows the radar's real counts (confirmed sites, look-alikes, campaigns) and links to LIVE. It is hidden when the radar has nothing to report. Early warnings appear as cards with a colour-coded status rail.
- **LIVE.** The Live Radar page uses a dark, full-page canvas. View and status controls stay in the toolbar; the target filter and unlinked findings sit behind *Filters*. Campaigns in the overview are rows you can tap, with a bar showing their size.
- **No Settings page.**
  - The header holds only the navigation and the language button. Its layout is fixed in both languages: logo on the right, fixed-width tabs, language on the left. Only the label text changes.
  - `#/settings` redirects to Home.
  - Capability limits are shown where they matter, in each result's "Limits of this result", and through `GET /api/capabilities`.
- **Consistency.** All pages share the same entrance motion, focus ring, hover lift and logical (RTL-safe) properties. The layout changes at the desktop, tablet (≤860 px) and phone breakpoints. All motion is disabled under `prefers-reduced-motion`.

### One protection journey (detection → prevention)

MIRQAB connects LIVE, the Scam Campaign DNA, Smart Protection and Family Shield into one flow. A shared journey context (`frontend/js/journey.js`) is built only from the intelligence payload and published warnings, and travels between pages.

- **Intelligence view: Prevent comes first.**
  - **What happens next:** the scam's likely next harmful step for its sector, with the engine tactics it uses (`SCRIPT` in `campaigns.py`).
  - **Don't:** what to avoid.
  - **Who I'm protecting:** everyone, seniors, students, families or businesses. The choice is shared with Home's protection guide and Family Shield.
  - **Three actions:**
    - *Check what you received*: opens Check with the threat in view.
    - *See how this scam works*: opens Family Shield at the harmful step, with this campaign's tactics marked.
    - *Share the approved warning*: only if a published warning covers these sites. Otherwise the action is disabled and says why.
- **Evidence basis in the header.** It shows:
  - confirmed versus suspected sites, and how many are still listed;
  - each source with its count;
  - the first-seen and last-seen span;
  - the strongest explained link.

  When nothing is confirmed, a note says so plainly.
- **Replay how it grew.** A slider in the DNA graph adds the sites in the order MIRQAB first saw them.
- **Smart Protection results label each live match.** A match is a *Confirmed phishing* listing, a *Suspected look-alike* or a *Pattern match*. Unverified matches are marked "not confirmed" and add an uncertainty note. A match also says when it is the same campaign the person was exploring, with *Explore campaign* to reopen it. Risk weights are graded: listed now 40, previously listed 25, suspected 20, naming-pattern prediction 10.
- **Journey bar.** A slim bar on Check and Family Shield keeps the threat in view and leads back to its intelligence. Home's live warnings open the intelligence view directly.
- **Stronger correlation.** Two names found in the **same Certificate Transparency entry** (one TLS certificate requested for both) form a *strong* link. This is also a trait in the DNA graph.
- **Link-check limits.** The note on a result now states which reputation data was used: the OpenPhish list and radar detections, or none.

### Judging criteria — where each one lives

The **Detection accuracy** page (`#/accuracy`, linked from the badge on Check) lists all five criteria with direct links and an honest "not covered" note for each.

- **Detection accuracy (30 %):**
  - held-out benchmark (`python -m ai.eval.run`) on live OpenPhish links vs legitimate sites, UAE scenarios and the UCI SMS set;
  - an **evasion test**: the same hidden phishing links wrapped in a Google redirect, defanged, or upper-cased, plus legitimate sites wrapped in redirects to measure false alarms;
  - redirect wrappers (`google.com/url?q=`, `l.facebook.com/l.php?u=`, `?redirect=`…) are unwrapped and the destination is analysed, without opening the link.
- **Early detection (25 %):**
  - Certificate Transparency radar, five threat feeds and look-alike detection;
  - registration age from RDAP in the evidence pack; a domain younger than 30 days is flagged as newly registered.
- **Explainability & actionability (20 %):** every link result has an **Evidence & takedown pack** (`POST /api/evidence/link`) containing:
  - RDAP/WHOIS registration: registrar and IANA ID, registration and expiry dates, name servers;
  - DNS and hosting network (RDAP IP record) and abuse contacts;
  - the radar/feed record, a UTC timestamp and a SHA-256 fingerprint;
  - a ready-to-send takedown letter and a JSON export.
  The suspicious site is never opened; only rdap.org is contacted.
- **UAE relevance (15 %):**
  - Arabic, Emirati dialect and English;
  - brand list includes TAMM, ICP, MOI, Abu Dhabi Police, Dubai Police, RTA, Salik, DEWA, UAE PASS, Emirates Post, UAE banks (incl. ADIB, DIB, Emirates Islamic), Etisalat/du, Etihad.
- **Feasibility (10 %):** live installable demo, 230+ tests, honest limits.



MIRQAB installs from Safari or Chrome as a Progressive Web App. No App Store, TestFlight or developer account is involved.

**Judges: try it in 2 minutes**

1. Scan the QR code on the **Shield** tab (or `/api/qr.svg`) with the iPhone camera. It opens in Safari.
2. Tap **Share → Add to Home Screen → Add**, then open **MIRQAB** from the Home Screen. iPhone delivers web notifications only to Home Screen apps (iOS 16.4+).
3. On **Shield**, tap **Activate MIRQAB protection** and allow notifications. A real test alert arrives within seconds. Tick *Allow demonstration alerts* if you want to receive the presenter's [DEMO] alert.
4. **Check**: paste a suspicious SMS/WhatsApp/email or link, tap **Paste from clipboard**, or **Scan a QR code** (take a photo). Android can also share straight to MIRQAB.
5. **Shield → Live Call Guardian**: tick consent, tap **Start listening**, and speak (Arabic, Emirati dialect or English). You can also put a call on speaker on a second phone. The transcript, risk score and detected tactics update live. High risk flashes the screen and sounds an alarm; Android also vibrates.
6. **Shield** shows real permission states, which capabilities are active, unavailable or roadmap, alerts received, and this phone's own threat history.

**What is real**

| Capability | How | Notes |
|---|---|---|
| Install | Web App Manifest, icons, Apple meta tags, service worker (offline shell; API never cached) | iOS Safari → Add to Home Screen; Android → Install |
| Push notifications | Web Push with VAPID (RFC 8292, `vapid t=…,k=…`), aes128gcm payloads, `pywebpush` | Works when MIRQAB is closed. Subscriptions are accepted only for Apple, Google, Mozilla and Microsoft push services (no SSRF). Expired subscriptions (404/410) are deleted. |
| Test alert | `POST /api/devices/me/test` | Rate limited; arrives in the device's language |
| Verified alerts | Pushed when a community alert passes the two-person review | Topic `alerts` |
| Phishing campaigns | Live radar campaigns with ≥ 3 feed-confirmed sites | Topic `campaigns`; brand-level; at most 1 per device per 6 h; existing campaigns at start-up are never blasted |
| UAE-relevant alerts | Campaigns against UAE banks, government, telecom and delivery brands | Opt-in. Location is read once **on the phone** only to decide "inside the UAE"; coordinates are never sent |
| Demo alert | `/admin.html` (admin role), `POST /api/push/demo` | Only to phones that opted in; always labelled `[DEMO]` / `[تجريبي]` with "not a real threat"; audited |
| Message Guardian | Existing explainable engine: clipboard, QR (jsQR, on-device), screenshots/files, Android share target | QR content is decoded on the phone and then checked like a link |
| Live Call Guardian | Microphone + the phone's speech engine (`SpeechRecognition`, ar-AE / en-US) → `POST /api/guardian/analyze` every sentence | No audio is sent or stored. The transcript is analysed in memory. Stops on Stop, when leaving the screen, or when the phone locks. Fallback: server speech-to-text (OpenAI) if configured, otherwise typed input |
| Dialect | Gulf/Emirati urgency and threat phrases added to the engine (`الحين…`, `بسرعة`, `بيتسكر`, `بنرفع عليك`…) | Scores the whole conversation (stages + inconsistencies), not single keywords |

**Device security.** A phone gets a random 256-bit device token when it registers; only its SHA-256 hash is stored. Every `/api/devices/me` call is scoped to that one device, so one phone can't see another's inbox or settings. Disconnecting deletes the registration and its inbox. Threat history stays in the phone's `localStorage`.

**Honest limits (iOS).** No web app, and no App Store app, can hear cellular call audio on iPhone, read SMS automatically, or listen in the background. MIRQAB never claims to. The Guardian works through the speakerphone or your own voice while the screen is open. Push needs the Home Screen install on iOS 16.4+. Vibration is not available to web apps on iPhone. Whether speech recognition works inside an installed Home Screen app depends on the iOS version; if it is unavailable, MIRQAB says so and offers typed input, and the Safari tab is an alternative.

**Native roadmap** (shown in the app as "Native app (roadmap)"):
- iOS Message Filter extension and Android SMS role, using the same engine on the device;
- CallKit Call Directory for caller ID from verified reports;
- a Safari content blocker fed by radar-confirmed phishing domains;
- Android call screening with explicit consent.

The API is already device-token based, so native clients can reuse it unchanged.

**Deploy (Render).** `Dockerfile` + `render.yaml`:
- Docker web service with a 1 GB disk at `/app/data` (SQLite, VAPID key, TTS cache);
- `MIRQAB_SECRET_KEY` is generated by Render;
- the public URL and Host allow-list come from `RENDER_EXTERNAL_URL` and `RENDER_EXTERNAL_HOSTNAME`;
- `MIRQAB_BOOTSTRAP_ADMIN=true` creates one admin. Set `MIRQAB_ADMIN_PASSWORD` yourself; otherwise a one-time password is printed in the log.

### Check: Deepfake scan

A fifth tab on the Check page accepts an image, voice note or video (JPG/PNG/WEBP/MP3/WAV/M4A/OGG/MP4/MOV, ≤ 25 MB, magic bytes verified). The file is analysed **in memory and never stored**.

- **Provenance (deterministic, always on):** Content Credentials (C2PA/JUMBF), the IPTC `trainedAlgorithmicMedia` declaration, and generator signatures written by AI tools (Stable Diffusion `parameters`, ComfyUI workflows, Midjourney, DALL·E, Firefly, Imagen, Ideogram, FLUX, Sora, Runway, Pika, Kling, HeyGen, Synthesia, ElevenLabs …). Camera-maker metadata is reported as *consistent with a photo, but editable*.
- **AI visual review (images, optional):** with `OPENAI_API_KEY` set, a vision model looks for concrete artefacts (hands, lighting, warped text, face seams) and returns at most four signs plus a confidence. It is labelled as an AI opinion that can be wrong in both directions. Results are cached by SHA-256 so the same file never costs twice.
- **Honesty rules:** MIRQAB never says a file is "real". No markers → "this does not prove it is real". Audio and video get provenance only, plus the behavioural defence (hang up, call back on a saved number, family code word) and a link to the deepfake-call scenario in Community.

### Scenario voices

Scam Theater starts with narration enabled when browser speech synthesis is available. It reads the scene’s script and message text as the story plays. The speaker control lets viewers mute narration. **The voice follows the page language:** an Arabic page plays the Arabic script with an installed `ar-*` voice; every other language plays the English script with an `en-*` voice. No API key is needed.

### LIVE: Generate report

The **Generate report** button in the LIVE toolbar opens a report builder.

**Filters.** The builder uses the radar's own filters, starting from the radar's current ones:
- period;
- status;
- imitated brand;
- source;
- minimum risk;
- listed now;
- has a published warning;
- part of a campaign.

**Report types.**
- *Executive summary:* figures, charts, main campaigns, recommended actions and the 15 newest sites.
- *Technical detail:* adds the site list (up to 500) with sources and campaign IDs, for blocking and takedown requests.

**Design.** The report is a print-ready A4 document. It has:
- a branded cover band showing the report type, a TLP sharing label (CLEAR, GREEN or AMBER, chosen in the builder), the reference, the generation time, the period and the filters;
- **Key findings** written from the data;
- a contents list;
- numbered sections, donut charts for sources and risk, and a timeline with a marked peak (hourly when detections span 3 days or less);
- P1–P3 priority cards;
- action cards for each audience.

It always prints on white with no dark margins, whatever the app theme. The cover starts at the top of page 1.

**The document.** It is branded with the MIRQAB mark, a reference number, the generation time, the covered period and the filters applied. Its sections:
1. Summary, with key figures and a sentence built from them.
2. Detections over time (daily, confirmed vs suspected).
3. Most imitated brands.
4. Sources.
5. Risk distribution.
6. Main campaigns, with why their sites are linked, the potential harm and how to protect people.
7. Recommended actions.
8. Sites.
9. Method and limits.

**Analysis sections** (all computed by `_analysis()` in `backend/app/api/radar.py` from stored findings):
- **Change vs the previous period.** The same filters are applied to the window before the chosen one, as a total and per brand. When there is no earlier data, the report says so instead of showing a percentage.
- **Priority actions by brand.** The top brands are ranked by volume, growth and sites listed right now. Each gets concrete actions built from its own numbers:
  - takedown of the N listed sites;
  - a bulk removal request to the free platform hosting ≥30% of its sites;
  - watching new registrations in the domain ending used by ≥30% of its sites;
  - reviewing its suspected sites;
  - a community warning.
- **Attacker infrastructure.** Free hosting and site-builder platforms (`pages.dev`, `vercel.app`, `web.app`…), domain endings, and lure words in site names (whole words only).
- **Fastest-growing campaigns.** Sites first seen in the period, compared with sites already known before it.
- **How long sites stay listed.** The median and 90th percentile, measured from first to last listing while MIRQAB was running. These are lower bounds and are labelled that way.

**Campaign IDs.** IDs are unique even when several groups share a broad trait such as "apple + .com". Unique IDs are unchanged, and only colliding ones get the group's earliest site mixed into the hash.

**Export.**
- *Print / save as PDF* prints only the report, on A4.
- *Download CSV* exports every matching site (up to 20,000).

**Data integrity.**
- All figures come from `GET /api/radar/report`, and the CSV from `GET /api/radar/report.csv`.
- Both use the same `RadarFilter` as `/api/radar/graph`, so the report always matches the radar.
- Nothing is estimated.
- Links are always defanged (`example[.]com`).
- CSV cells that could run as spreadsheet formulas are neutralised.

### Languages

The interface is available in nine languages from the 🌐 menu in the header and on the landing page:
- Arabic and Urdu, right-to-left;
- English, Hindi, Filipino, Chinese (Simplified), French, Spanish and Russian.

The choice is remembered. On a first visit the browser language is used when it is one of these.

The menu works with the keyboard: ↓ opens it, ↑/↓ move through it, Enter chooses and Esc closes.

How text is chosen:
- Every interface string the app uses is translated (`frontend/i18n/<code>.json`).
- A string missing from a language falls back to English, never to a raw key.
- Dates and numbers follow the language's locale.
- Content produced by the engine and the radar is written in Arabic and English, and other languages show its English version. This covers detection reasons, tactic names, campaign names and published warnings.

### LIVE: wider detection, link search and advanced filters

**Sources.** LIVE watches six public sources:
- Certificate Transparency logs (now 8 logs, sampled every few seconds);
- the OpenPhish community feed;
- four large public phishing-domain lists, refreshed every 3 hours with conditional downloads:
  - CERT Polska warning list;
  - Phishing Army;
  - Phishing.Database (active);
  - Block List Project — phishing.

Every entry of every list is scanned (about 850,000 in a test on 2026-11-23). Entries that impersonate a monitored brand are stored, so the graph stays meaningful; in that test this was about 12,700 sites. A site counts as *confirmed* when any feed lists it. It stays *listed now* while at least one feed currently lists it. URLhaus was evaluated and left out: its downloads now return HTTP 410 without an account key.

**Link search.** The search bar above the radar accepts a pasted link, a defanged link (`hxxps://x[.]y`) or a site name.
- Typing highlights matching sites in the graph or list.
- *Check* calls `GET /api/radar/lookup?q=…`. It searches **everything stored**, not only what the current filters show, and returns:
  - whether the site is listed now, was listed, or is a suspected look-alike, with its sources and campaign;
  - other sites on the same domain;
  - how many other fake sites imitate the same brand;
  - the rule engine's URL analysis.
- The link is never opened or fetched, and the query is not stored. "Not in MIRQAB LIVE's records" is never presented as safe.

**Advanced filters** (server-side on `/api/radar/graph`):
- imitated brand;
- source (`ct`, `feeds` or a single feed);
- first detected (`since_hours`);
- minimum risk (`min_risk`);
- listed right now;
- has a published warning;
- part of a campaign;
- include unlinked sites.

Performance at this scale:
- The graph draws the newest 160 matching sites. The rest stay reachable through search, filters and the list, and the counts always cover everything.
- The animation runs at about 12 fps. Link dashes move only on small graphs, and the canvas pixel ratio is capped.
- `/api/radar` returns campaign summaries rather than full member lists.

Active filters appear as removable chips. The panel shows how many sites are shown, how many match and how many are stored.

**Theme.** Dark mode, based on the LIVE palette, is the default across Check and Community. The sun/moon button next to the language button switches to light mode, and the choice is remembered in this browser.

### Community — a living experience

The Community tab is one continuous experience rather than numbered sections.

- **Awareness hero.** "Know the trick before it reaches you", with three actions (start a scenario, test yourself, it already happened) and personal progress kept in this browser: scenarios survived, test score and family readiness. **Community takes nothing from the radar.** It uses only `/api/community/shield` (scam-tactics engine and training messages), verified warnings, reports and impact.
- **Decoder.** This merges "Is something happening now?" and "How a scam works":
  - One panel: the scam chain runs across the top, with two equal boxes below — "What is happening?" (situations, then warning signs) and a single concise result (badge, one action, the tactics MIRQAB recognises, what they will try next, two buttons).
  - The person picks what is happening and answers three yes/no signals.
  - The answers map to real engine tactics, which light up the four-step scam chain and place a **"You are here"** marker.
  - Tapping a step shows its goal, tactics (with explanations) and how to stop it.
  - The verdict is *Stop* or *Pause and verify*, never "safe", with one action, the chain position and the next step.
  - Arriving from a campaign opens the chain at the harmful step, with that campaign's tactics marked.
- **Scam Theater.** Six short interactive dramatizations play on an animated phone stage: voice clone, account takeover, parcel fee, bank "fraud team", investment group and police notice.
  - Captions are on by default. Narration uses the browser's own speech engine and is optional.
  - Each film pauses at the critical moment with a 12-second countdown (the pressure itself is the lesson) and branches to the outcome of the choice.
  - The debrief shows the verdict, the rule to remember and the real MIRQAB tactic labels. *Use it in real life* opens the Decoder with that situation.
  - Results are stored only in this browser.
- **Test yourself.** The training messages, scored live by the real engine with its highlights. The last score is kept in this browser.
- **Family Circle.**
  - The five plan habits orbit a code word generated in the browser; tapping a habit completes it and fills the ring (`localStorage`, never sent).
  - The audience-aware WhatsApp warning is built from engine tactics and approved warnings only.
- **If it already happened.** An inline section with tap-to-call official channels and **Emergency mode**: A full-screen overlay with a timer since opening and four actions that can be ticked off: bank, report, secure accounts, warn others. It includes the official channels (Aman 800 2626, SMS 2828, u.ae eCrime list, 999) and a jump to the report form.
- **Signal board.** Verified two-reviewer warnings with helpful/not-helpful feedback, the anonymised report form, and impact numbers counted from this installation.

Motion respects `prefers-reduced-motion`. The layout is responsive down to 360 px and works right-to-left. Film scripts are written in Arabic and English, and the other interface languages show them in English.

**Research basis:**
- the FBI's December 2024 PSA on AI voice and video impersonation (family code word, hang up and verify);
- UK Finance's Take Five and Australia's Scamwatch (Stop · Check · Protect);
- fraud-warning research favouring specific, just-in-time warnings;
- the UAE Government portal for reporting channels.

### Live Threat Radar (proactive) and Scam Campaign DNA

**Sources (real, public, no API keys):** Certificate Transparency logs from Google's CT log list (RFC 6962 `get-sth` / `get-entries`) and the OpenPhish community feed.

**Reliable ingestion.** Each CT log has exponential back-off on failure. The feed is downloaded conditionally (ETag) with retry/back-off. Source health is stored in `radar_sources`, so freshness survives restarts: last success, error count, number of healthy logs, age of the newest certificate seen, and number of URLs listed now.

**Evidence and freshness for every finding.** CT findings keep the log name, entry index, certificate time and issuer. Feed findings keep the feed URL and fetch time, plus whether they are *still listed* or *no longer listed*. Nothing is ever deleted.

**Detection on new certificates.** A domain is flagged only when:
- its *registered* name contains or misspells a protected brand, **and**
- it also has a lure word (login, verify, pay, delivery, careers…), a frequently abused ending, or look-alike characters.

Brand-in-subdomain tricks are flagged on free hosting or on lure-named domains. The rules were tightened using real false alarms from a live run ("takara" vs "tamara", "career" vs "careem", "forticloud" vs "icloud"), and these are regression tests. When the rules change, stored findings are re-checked at startup and dismissed with a note, not deleted.

**Scam Campaign DNA** (`ai/threat_intelligence/campaigns.py`). Each finding is reduced to observable "genes": target brand, naming template (`{brand}-secure-update`), registered domain, sub-domain naming stem on free platforms, page-path signature (`/users/#`), domain ending, lure words and time. Findings are linked when they share genes:

| Strength | Rule |
|---|---|
| strong | Same registered domain (never a shared platform such as blogspot.com or pages.dev) |
| strong | Same brand and the same naming template |
| moderate | Same distinctive page path on different sites, within 7 days (a reused phishing kit is likely) |
| moderate | Same sub-domain naming stem on a free hosting platform |
| weak | Same target, same domain ending and same lure/trick, within 72 hours |

`www.x` and `x` are treated as one site. Connected groups of two or more sites become campaigns. Each campaign has a stable ID, a status (*confirmed* if any member is on the feed, otherwise *suspected*), a confidence level, the evidence for every link, an explicit uncertainty statement, the potential harm, and prevention steps. On the first real dataset (288 findings) it produced 8 campaigns, for example six fake Roblox domains in different countries sharing the kit path `/users/#`.

**Connected to every workflow:**
- **Check:** a link on the radar adds 40 points (confirmed) or 20 (suspected), with when it was first seen and its campaign. A *never-seen* domain that follows a campaign's naming template is flagged as a **prediction** (10 points, labelled unverified).
- **Investigation:** case analysis links evidence to radar findings and campaigns, as findings and in the Analysis step. `POST /api/radar/investigate` (API) adds an immutable, hashed radar snapshot as case evidence.
- **Community:** *Draft community warning* turns a finding or a whole campaign into an alert draft. It still needs a different reviewer and the personal-data check before publishing. *False alarm* removes a finding from all matching.

### Threat Constellation (interactive relationship graph)

The Live Radar page now centres on an interactive graph in place of the earlier text-heavy campaign cards and findings list.

- **Nodes are real findings only.** `GET /api/radar/graph` returns stored `radar_items`, a filtered view of the same Campaign DNA data the rest of the radar uses. **Edges** are exactly the links `analyze_relationships()` produced, each with its strength and bilingual reason. Campaigns appear as grouping boxes. Nothing is generated for display. Tests check that every node maps to a stored finding and every edge has a reason.
- **Explore.** Zoom, pan, fit, re-arrange; filter by confirmed/suspected and by imitated brand; optionally show findings that have no explainable relationship. These go in a separate grid so they never look connected.
- **Select a finding** to see:
  - its source (CT log, issuer and certificate time, or OpenPhish and whether it is still listed);
  - when it was detected and last seen;
  - its risk level and score, and why it was flagged;
  - each relationship with its evidence (neighbours are clickable);
  - its campaign, and the potential harm and prevention steps.
- **Select a campaign** to see its confidence, "How it developed" (members in the order MIRQAB first saw them, with a replay that highlights them in that order), grouped link reasons, an uncertainty statement, harm and prevention.
- **Actions reuse existing workflows:**
  - *Check this link* runs Smart Protection on the finding's URL.
  - `POST /api/radar/investigate` (investigator, API only) adds the hashed radar snapshot as case evidence.
  - *Draft community warning* (reviewer) is offered **only for validated findings** (confirmed by a phishing feed). Unverified members are excluded and reported back, and an all-unverified campaign is refused with guidance to investigate first. Publishing still needs a second reviewer.
  - *False alarm* (reviewer) removes a finding from all matching.
  - Findings covered by a published warning are marked in the graph.
- **Updates without inventing activity.** The view polls every 15 s and changes only when stored intelligence changes. New findings are added in place with a brief highlight, and "N new since you opened this page" counts only findings first seen after the page was opened.
- **Accessible alternative.** A *List* view shows the same nodes grouped by campaign in a table with keyboard-operable rows and opens the same detail panel. The graph has a descriptive label that updates with the data.
- **Radar projection — every position is data.** Distance from the centre is the time since MIRQAB first saw the site (rings: 1 h, 24 h, 7 days, older; newest in the centre), so sites drift outward as they age. Each campaign has its own angular sector (wider for bigger campaigns), with its label on the edge; findings with no explainable link share a separate sector. Site names appear on hover, on selection or when zoomed in, which keeps the overview uncluttered.
- **Motion that reports real state.**
  - The sweep makes one turn per refresh cycle, and sites light up as it passes them. A "Next update in N s" countdown shows when the next real poll happens.
  - Dashed links flow from the site seen first to the one seen later, showing the direction a campaign spread.
  - Sites first seen within the last hour pulse.
  - On load, each site travels out from the centre to its ring.
  - A ticker under the graph replays real detections ("Look-alike detected", "Listed as phishing", "Seen again on a new certificate"); entries that arrived during the session are marked *New*.
  - The certificates-checked counter rolls to its real value.
  - All motion pauses in background tabs and is disabled under `prefers-reduced-motion`.
- **Enlarge.** The ⛶ control expands the radar to full screen (or a full-window overlay where fullscreen is not allowed); ✕ or Esc restores it.
- **Intelligence pipeline.** Above the radar, one live strip shows *sources → MIRQAB analysis → what came out*: health and freshness of each Certificate Transparency log and the OpenPhish feed, certificates checked this session, the throughput measured between two polls, the share of certificates flagged, and the resulting confirmed sites, suspected look-alikes and campaigns. The flow animation runs at the measured rate and stops when nothing is arriving; the sampling note sits behind the ⓘ button.
- **Design and performance.** Cytoscape.js 3.35 (MIT) is bundled locally in `frontend/vendor/`, and the strict CSP is kept: its stylesheet is provided by `app.css` rather than injected. The layout is deterministic: the same data gives the same picture. All 288 real findings render in about 0.35 s. Highlights respect `prefers-reduced-motion`. On mobile the graph uses 58 % of the viewport height with the panel below it.

**Coverage (honest):** CT publishes thousands of certificates per second. The prototype samples the newest 512 entries of up to five logs every ~6 s, so it does not see every certificate. Sites without HTTPS, and links on existing domains, are not caught by the CT part. Campaign links are inferences from shared traits, not proof of a common operator.

## 8. Key Features

- Bilingual UI with full RTL layout, bundled Arabic (IBM Plex Sans Arabic) and Latin (Inter) fonts, Arabic-Indic digit normalisation.
- Arabic and English detection patterns for 15 manipulation tactics and 9 named fraud patterns.
- Offline URL analysis: punycode/mixed-script homographs, look-alike and leetspeak typosquats, brand-in-subdomain, IP hosts, shorteners, risky downloads, odd ports, `@` tricks.
- Role-based access (investigator, reviewer, admin), tamper-evident hash-chained audit log.
- Responsive layout (top navigation on desktop, bottom navigation on mobile).

## 9. AI Methodology

| Layer | Type | Status |
|---|---|---|
| Behavioural tactic detection | Deterministic bilingual pattern engine with negation handling ("never share your code" is protective, not a request) | Implemented |
| Risk model | Additive, explainable weights + inconsistency bonuses + known-pattern bonus + link risk + validated community match | Implemented |
| Fraud-pattern recognition & next-step prediction | Heuristic over tactic combinations and hint words | Implemented (results labelled *inference*) |
| Conversation stage model | Per-message tactic → stage mapping, escalation detection | Implemented |
| URL analysis | Static lexical/structural analysis, no network access | Implemented |
| Language-model analysis | Anthropic Messages API or OpenAI Chat Completions (`MIRQAB_LLM_PROVIDER=anthropic|openai`), JSON-only, taxonomy-constrained, quote-grounded | Implemented, **optional**; off by default. The live API call was tested with a mocked transport only. |
| OCR | Tesseract (`ara+eng`) | Implemented when Tesseract is installed |
| URL reputation (Safe Browsing, CERT feeds) | `ReputationProvider` interface | Integration-ready, not configured |
| Voice / video deepfake forensics | Provenance (C2PA, IPTC, generator signatures) + optional OpenAI visual review for images | Never claims a file is real; audio/video get provenance + behavioural verification |

Safeguards: input caps, untrusted-content boundaries for the LLM, grounding check, LLM can only add (half-weight) indicators, deterministic floor, explicit fallback status (`not_configured` / `failed` / `used`) in every result, no autonomous retraining — learning happens only through human-approved community alerts.

## 10. System Architecture

```
 Browser (vanilla JS SPA, i18n JSON, CSP-strict)
        │  fetch /api/*
 FastAPI app ── security (auth tokens, roles, rate limit, upload validation, headers)
   ├── api/prevention.py   Smart Protection
   ├── api/cases.py        Investigation (cases, evidence, findings, reports)
   ├── api/community.py    Alerts, reports, validation, impact
   └── api/system.py       Login, capabilities, users, audit
        │
 services.py  ── evidence.py (storage, OCR, PDF, EML) ── reports.py ── audit.py (hash chain)
        │
 ai/ (pure Python, framework-free)
   behavioral_analysis/  tactics, analyzer, conversation, url_analyzer
   risk_assessment/      scoring, intervention
   investigation/        indicators, correlation+timeline, findings, email_parser
   threat_intelligence/  anonymisation, alert drafting, PII gate
   llm/                  optional grounded provider
        │
 SQLite (data/mirqab.db)  +  read-only evidence store (data/evidence/<sha256>.bin)
```

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## 11. Technology Stack

- **Backend:** Python 3.11+ (tested on 3.13), FastAPI, Uvicorn, Pydantic v2, SQLite (standard library).
- **Processing:** Pillow, pypdf, pytesseract + Tesseract OCR, Python `email`.
- **Optional AI:** Anthropic Messages API via `httpx`.
- **Frontend:** framework-free ES modules, CSS with logical properties (RTL-ready), no build step; Cytoscape.js (bundled, MIT) for the Threat Constellation.
- **Tests:** pytest, FastAPI TestClient, Playwright (Chromium) for browser tests.

## 12. Repository Structure

```
mirqab/
├── ai/                       # Unified behavioural-intelligence engine (no web deps)
│   ├── behavioral_analysis/  # tactics taxonomy, text & conversation analysis, URL analysis
│   ├── risk_assessment/      # explainable scoring, pre-harm intervention
│   ├── investigation/        # indicators, correlation, timeline, findings, e-mail parsing
│   ├── threat_intelligence/  # anonymisation, alert drafts, PII gate
│   ├── llm/                  # optional grounded LLM provider
│   ├── data/brands.json      # sample impersonated-brand list (extend per deployment)
│   ├── pipeline.py           # single entry point used by all modules
│   └── text.py               # Arabic/English normalisation with offset mapping
├── backend/app/
│   ├── api/                  # prevention, cases, community, system routers
│   ├── main.py               # app factory
│   ├── config.py  db.py  security.py  audit.py  evidence.py  services.py  reports.py
│   └── cli.py                # create users, seed demo, verify audit chain
├── frontend/                 # index.html, css/, js/, i18n/{en,ar}.json, assets/
├── tests/                    # 157 tests (engine, API, security, i18n, browser)
├── sample_data/              # synthetic demo case, e-mail and screenshot
├── scripts/                  # sample screenshot generator
├── docs/ARCHITECTURE.md
├── .env.example  .gitignore  requirements.txt  requirements-dev.txt  pytest.ini
└── README.md
```

## 13. Prerequisites

- Python 3.11 or newer
- Optional, for screenshot OCR: Tesseract 5 with English and Arabic data
  - Ubuntu/Debian: `sudo apt install tesseract-ocr tesseract-ocr-ara`
  - macOS: `brew install tesseract tesseract-lang`
  - Windows: install from the UB Mannheim build and add it to `PATH`
- Optional, for browser tests: Chrome/Chromium (or `python -m playwright install chromium`)

## 14. Installation Instructions

```bash
git clone https://github.com/<your-org>/mirqab.git
cd mirqab
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt     # add -r requirements-dev.txt for tests
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into MIRQAB_SECRET_KEY in .env
```

## 15. Environment Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MIRQAB_SECRET_KEY` | *(ephemeral)* | ≥32 chars; signs session tokens. If missing, a random key is used and sessions end on restart. |
| `MIRQAB_DATA_DIR` | `./data` | Database and evidence store location. |
| `MIRQAB_MAX_UPLOAD_MB` | `10` | Upload size limit. |
| `MIRQAB_RATE_LIMIT_PER_MIN` | `30` | Per-IP limit for public endpoints (login is ~1/3 of this). |
| `MIRQAB_TOKEN_TTL_MIN` | `480` | Session lifetime. |
| `MIRQAB_STORE_ANALYSIS_TEXT` | `false` | Keep `false` for data minimisation. |
| `MIRQAB_OCR_ENABLED` | `true` | Use Tesseract when installed. |
| `MIRQAB_LLM_PROVIDER` | `none` | `anthropic` or `openai` to enable the optional LLM layer (same grounding safeguards). |
| `OPENAI_API_KEY` | — | OpenAI key: LLM layer when provider is `openai`, and the deepfake AI visual review. |
| `MIRQAB_ALLOWED_HOSTS` | — | Extra Host names (DNS-rebinding guard). |
| `MIRQAB_API_DOCS` | `false` | Expose `/api/docs`. |
| `ANTHROPIC_API_KEY` / `MIRQAB_LLM_MODEL` / `MIRQAB_LLM_TIMEOUT` | — | LLM settings. |
| `MIRQAB_RADAR_ENABLED` | `false` (`true` in `.env.example`) | Start the Live Threat Radar background service. |
| `MIRQAB_CORS_ORIGINS` | — | Only if the frontend is hosted on another origin. |
| `MIRQAB_DEMO_*_PASSWORD` | — | Passwords for `seed-demo`; random if empty. |

## 16. How to Run the Application

```bash
# macOS one-click: double-click start-mirqab.command (creates venv, one admin account saved in ACCOUNTS.txt,
# starts/restarts the server). Older installs with three accounts are switched to single-account mode:
#   python -m backend.app.cli single-account   (keeps the admin; others are deactivated, never deleted)
# Note: the two-person rule still applies, so publishing a community warning needs a second reviewer account.
# install-ocr.command installs Tesseract + Arabic data via Homebrew.

# 1. (optional) create demo accounts and a synthetic, analysed case
python -m backend.app.cli seed-demo
#    → prints the generated investigator / reviewer / admin passwords once

# 2. start the server
uvicorn --factory backend.app.main:create_app --host 127.0.0.1 --port 8000

# 3. open http://127.0.0.1:8000
```

Create real accounts instead of demo ones:

```bash
python -m backend.app.cli create-user --username alice --role investigator   # prompts for password (or set MIRQAB_NEW_USER_PASSWORD)
python -m backend.app.cli verify-audit                                         # check the audit hash chain
```

## 17. API Documentation

Interactive OpenAPI docs (enable with `MIRQAB_API_DOCS=true`): `http://127.0.0.1:8000/api/docs`. Authentication: `Authorization: Bearer <token>` from `/api/auth/login`.

| Method & path | Role | Description |
|---|---|---|
| `POST /api/analyze` | public | `{kind: text\|conversation\|url, content}` → explainable result |
| `POST /api/analyze/file` | public | multipart `file` (png/jpg/webp/pdf/txt/eml); processed in memory |
| `POST /api/analyze/{id}/feedback` | public | `{verdict: helpful\|incorrect}` (once) |
| `POST /api/deepfake/scan`, `GET /api/deepfake/status` | public | multipart image/audio/video; provenance + optional AI visual review; never stored |
| `GET /api/community/alerts` | public | Published alerts (`?audience=`) |
| `POST /api/community/alerts/{id}/feedback` | public | `{helpful: bool}` |
| `POST /api/community/reports` | public | Anonymised scam report |
| `GET /api/community/impact` | public | Real usage metrics |
| `GET /api/health`, `GET /api/capabilities` | public | Health, honest capability status |
| `POST /api/auth/login`, `GET /api/auth/me` | — | Session |
| `GET/POST /api/cases`, `GET/PATCH /api/cases/{id}` | investigator | Cases |
| `POST /api/cases/{id}/evidence/text` · `/evidence/file` | investigator | Add evidence |
| `GET /api/evidence/{id}` · `/verify` · `/download` | investigator | Evidence detail, integrity, original |
| `POST /api/cases/{id}/analyze`, `GET /api/cases/{id}/analysis` | investigator | Correlation, timeline, findings |
| `GET /api/cases/{id}/findings`, `PATCH /api/findings/{id}`, `POST /api/cases/{id}/notes` | investigator | Review findings |
| `GET /api/cases/{id}/report?format=md\|html\|json` | investigator | Export |
| `POST /api/cases/{id}/alert-draft` | investigator | Draft alert (needs verified finding) |
| `GET /api/community/review`, `PATCH /api/community/alerts/{id}`, `POST …/submit` | investigator | Workflow |
| `POST /api/community/alerts/{id}/approve` · `/reject` · `/archive`, `PATCH /api/community/reports/{id}` | reviewer | Validation |
| `GET /api/radar?source=ct\|openphish` | public | Source health, counts, campaigns, findings (with evidence) |
| `GET /api/radar/graph?status=&brand=&connected_only=&limit=` | public | Threat Constellation: real findings (nodes), explained links (edges), campaigns |
| `GET /api/radar/campaigns/{id}` | public (+ linked cases when signed in) | Campaign DNA: members, links, harm, prevention |
| `GET /api/radar/intel?campaign_id=\|item_id=` | public (+ linked cases when signed in) | Intelligence view: DNA traits and explained links, per-site public evidence, harm, prevention, covering published warnings |
| `POST /api/radar/investigate` `{item_id\|campaign_id, case_id?}` | investigator | Add an immutable radar snapshot to a new or existing case |
| `POST /api/radar/warn` `{item_id\|campaign_id}` | reviewer | Community-warning draft from **validated** findings only (second reviewer publishes) |
| `POST /api/radar/{id}/dismiss` | reviewer | Mark a false alarm |
| `POST /api/users`, `GET /api/audit`, `GET /api/audit/verify` | admin | Administration |

## 18. Testing Instructions

```bash
pip install -r requirements-dev.txt
python -m pytest            # 157 tests
python -m pytest -k "not e2e"   # skip browser tests
```

Browser tests use Playwright with Chromium. They use `google-chrome`/`chromium` from `PATH` or `MIRQAB_CHROME`; otherwise run `python -m playwright install chromium`. They are skipped if Playwright is not installed.

Coverage by requirement:

| Requirement | Tests |
|---|---|
| Suspicious / legitimate / false-positive messages (EN + AR) | `test_behavioral_engine.py` (9 scam, 7 legitimate cases, protective wording) |
| URL analysis | `test_url_and_llm.py` |
| Behavioural risk, pre-harm intervention, multi-stage | `test_behavioral_engine.py` |
| LLM grounding, injection, fallback | `test_url_and_llm.py` |
| Case creation, evidence upload, correlation, timeline, report export | `test_api.py`, `test_investigation_engine.py` |
| Community alert validation, PII gate, two-person rule | `test_api.py` |
| Security controls (auth, roles, tokens, uploads, headers, rate limit, audit tampering, evidence tampering) | `test_security.py`, `test_api.py` |
| Arabic/English switching, i18n parity, responsive layout, UI flows | `test_security.py`, `test_ui_e2e.py` |

## 19. Sample Demonstration Scenarios

All data is synthetic.

1. **Bank OTP (English)** — Smart Protection → Message:
   `This is your bank security team. Your account will be blocked within 2 hours. Send us the OTP code you received now: http://emiratesnbd-secure.xyz/verify` → *Critical*, "Do not share any code", brand/link contradiction.
2. **"Hi Mum" (Arabic)** — `هلا يمه هذا رقمي الجديد ضاع جوالي، محتاج فلوس ضروري حولي 2000 درهم على هذا الحساب ولا تقول لابوي` → family-emergency pattern, "Do not send money", safe-word advice.
3. **Pre-harm prediction** — `This is the fraud department of your bank. Your account will be suspended today due to suspicious activity.` → no request yet; MIRQAB warns the next step will be a code request.
4. **Legitimate OTP** — `Your verification code is 482913. Never share this code with anyone.` → Low risk (protective wording recognised).
5. **Conversation** — Conversation tab, paste the chat from `sample_data/demo_case.json` → stage strip shows story → pressure → request.
6. **Screenshot** — upload `sample_data/sms_screenshot.png` (OCR).
7. **Investigation loop (API)** — run `seed-demo`, then use the authenticated API: `POST /api/auth/login`, `POST /api/cases/{id}/analyze`, then the reports endpoints. The two-person approval of a community warning is `POST /api/community/alerts/{id}/approve` by a second reviewer. Afterwards, check `http://aramex-delivery-ae.top/x` in Smart Protection → "Matches a validated community warning".
8. **Report** — in the case drawer → Report → Markdown / HTML / JSON.
9. **Explore a campaign** — Live Radar → select a campaign → *Explore intelligence* → tap a trait in the DNA graph to see which sites carry it and why they are linked.

## 20. Security and Privacy

- **Authentication:** PBKDF2-SHA256 (260k iterations) password hashes, HMAC-signed expiring tokens, constant-time comparison, login rate limiting, failed logins audited.
- **Authorisation:** role hierarchy investigator < reviewer < admin; two-person rule for publishing.
- **Uploads:** extension allow-list, magic-byte verification, executable signature rejection, double-extension rejection, size limit, UTF-8 validation for text, decompression-bomb limit for images, page limit for PDFs; files never rendered by the browser.
- **Untrusted content:** all UI rendering via `textContent` (no `innerHTML`), strict CSP (`script-src 'self'`, no inline script), HTML reports escaped with a script-blocking CSP; links are never fetched; validation errors never echo input.
- **Prompt injection:** content boundary + data-only instructions, JSON-only output, taxonomy constraint, quote grounding, deterministic floor; manipulation attempts are flagged as a tactic.
- **Integrity:** content-addressed read-only evidence with re-verification; hash-chained audit log with verification endpoint/CLI.
- **Data minimisation:** public checks store only hash, risk level and pattern; community reports anonymised; card numbers stored as last-4 only.
- **Secrets:** environment variables only; `.env` git-ignored; a test scans the repository for key patterns.
- **Headers:** CSP (incl. `media-src`, `worker-src 'none'`), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, restrictive `Permissions-Policy`, `Cross-Origin-Resource-Policy`, HSTS when served over HTTPS, `no-store` on API responses.

**Security audit (Nov 2026)** — bandit, pip-audit (no known CVEs) and a manual route-by-route review. Fixed:

| Finding | Fix | Test |
|---|---|---|
| DNS rebinding: a hostile site could point its domain at 127.0.0.1 and drive the local API | Host-header allow-list (`MIRQAB_ALLOWED_HOSTS` to extend) | `test_dns_rebinding_host_is_rejected` |
| Oversized uploads were spooled to disk before the size check | ASGI body cap from `Content-Length` and mid-stream (413) | `test_oversized_body_rejected_before_parsing` |
| Password guessing limited per IP only | Per-account lockout (5 failures / 15 min), constant cost | `test_account_lockout_after_repeated_failures` |
| Several public endpoints had no throttle; limiter memory unbounded | Global per-IP API throttle; stale buckets swept | `test_global_api_throttle`, `test_rate_limiter_memory_is_bounded` |
| API docs exposed by default | Off unless `MIRQAB_API_DOCS=true` | `test_api_docs_disabled_by_default` |
| Threat feeds downloaded without a size cap / could redirect off HTTPS | Streamed, capped (8–64 MB), HTTPS-only | — |
| Dynamic SQL column names (bandit B608) | Explicit model allow-list before the query | existing case/alert tests |
| Hidden bidi characters in source (B613), SHA-1 flagged (B324) | Escaped; `usedforsecurity=False` (IDs only) | bandit clean |
| Paid AI calls repeatable on the same file | SHA-256 result cache | `test_vision_review_parses_and_hides_errors` |

Remaining by design: bearer tokens live in `localStorage` (mitigated by the strict no-inline CSP) and cannot be revoked before expiry; the server binds to 127.0.0.1 only.

## 21. Implemented Features and Limitations

**Implemented and tested:** everything in sections 5–7 and 20.

**Limitations (honest):**
- The rule engine recognises *known* manipulation patterns; novel scams with none of these cues may score low (the UI says so explicitly).
- The optional LLM layer was tested with a mocked HTTP transport; quality with a live model depends on the chosen model.
- No live monitoring of calls, chats or transactions; MIRQAB analyses what users submit. The Live Radar monitors public internet sources (CT logs, OpenPhish), not users.
- Campaign DNA uses only observable traits (no DNS/WHOIS/hosting lookups); campaign links are inferences and are labelled as such. Campaign IDs stay stable while the defining trait persists, but can change if a group splits or merges.
- The radar samples CT logs (not every certificate), needs internet access, and its brand list (`ai/data/brands.json`) should be extended per deployment.
- Deepfake scan reads provenance and (optionally) an AI visual opinion; there is no forensic audio/video model, and stripped metadata proves nothing.
- URL analysis is static; no reputation service is connected. Registrable-domain detection approximates the public-suffix list.
- OCR quality depends on the screenshot; OCR output is labelled as possibly inaccurate.
- Ambiguous numeric dates are read day-first.
- All investigators can see all cases (no per-case assignment yet). Rate limiting is in-memory (single process).
- SQLite is suitable for a prototype/single node, not high-concurrency production.
- Arabic UI text was written for this prototype and should be reviewed by a native editor before public release.

## 22. Future Development Roadmap

1. Reputation providers (national CERT feeds, Safe Browsing) behind `ReputationProvider`.
2. Audio/video forensic model integration for voice-clone and deepfake evidence.
3. Per-case assignment, organisation tenancy and SSO.
4. PostgreSQL and a shared rate-limit store for multi-instance deployment.
5. Evaluation set of labelled Arabic/English scams to calibrate weights and measure precision/recall.
6. Browser extension / messaging-app share target that calls `/api/analyze` with user consent.
7. Export of validated indicators in STIX 2.1 for sharing with authorised partners.

## 23. Team Information

| Name | Role | Contact |
|---|---|---|
| *To be completed by the team* | | |

---

*All names, numbers, domains and accounts in `sample_data/` and tests are fictitious.*
