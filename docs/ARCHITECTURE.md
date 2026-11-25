# MIRQAB architecture notes

## Design choices

- **One engine, three consumers.** `ai/pipeline.py::analyze()` is called by Smart Protection, by case analysis (per evidence item) and by community-report intake, so prevention and investigation always agree.
- **Monolith, no microservices.** A single FastAPI process serves the API and the static frontend. SQLite and a content-addressed file store keep setup to `pip install`.
- **Framework-free frontend.** ES modules, no build step, strict CSP. Every string goes through `i18n/{en,ar}.json`; layout uses CSS logical properties so RTL needs no separate stylesheet.
- **Deterministic first, LLM optional.** The rule engine is the floor. The LLM is an additive, grounded layer and its status is reported in every result.

## Result taxonomy

| Field | Meaning | Can it be wrong? |
|---|---|---|
| `observed` | Exact substrings (with offsets) and URLs present in the input | No — literal |
| `indicators` (`source: rule`) | A known tactic pattern matched an observed quote | Yes — rule may misfire; quote shown |
| `indicators` (`source: ai_inference`) | LLM-identified tactic whose quote was verified to exist | Yes — interpretation |
| `inferences` | Fraud-pattern resemblance, next-step prediction, LLM summary | Yes — always `verified: false` |
| Findings `verified` | Human investigator decision with reviewer name and timestamp | Human judgement |

## Risk score

`score = Σ tactic weights + inconsistency bonuses + known-pattern bonus (15) + link risk (60% of worst URL, or 100% for link-only checks) + validated community match (15)`, capped at 100. Levels: <20 low, 20–44 caution, 45–69 high, ≥70 critical. The `breakdown` array lists every contribution.

## Intelligence loop and trust boundaries

```
public check ──► analyses (hash, level only)
public report ─► community_reports (anonymised, unverified) ──► reviewer triage
case evidence ─► findings (unreviewed) ──► investigator verify/dismiss
                     │ ≥1 verified
                     ▼
               alert draft ──► submit ──► reviewer ≠ author + checklist + PII gate ──► published
                                                                                 │
                         prevention engine uses ONLY published alerts' domains ◄──┘
```

Nothing crosses a boundary automatically. There is no model retraining; "learning" is the human-approved alert set.

## Data model (SQLite)

`users`, `cases`, `evidence` (sha256, storage path, extracted text, metadata, analysis JSON), `indicators` (normalised values for cross-case lookups), `findings` (fingerprint keeps review status across re-analysis), `alerts`, `community_reports`, `analyses` (metrics only), `audit_log` (hash chain).

## Extension points

- `ai/llm/provider.py` — add providers implementing `available()` / `analyze()`; reuse `ground()`.
- `ai/behavioral_analysis/url_analyzer.py::ReputationProvider` — URL reputation services.
- `ai/behavioral_analysis/tactics.py` — add tactics/patterns (bilingual); tests enforce quote fidelity.
- `ai/data/brands.json` — deployment-specific impersonated brands and official domains.

## Proactive intelligence (v1.2)

```
CT logs ─┐                         ┌─► Check: radar match / campaign / predicted-by-naming-DNA
         ├─► radar_items ─► Campaign DNA (cached) ─┼─► Investigation: radar links in case analysis, snapshot evidence
OpenPhish┘   (+evidence,            build_campaigns ├─► Community: warning draft from finding or campaign (2-person rule)
             freshness,                             └─► Radar page: early warnings with harm, prevention, evidence, uncertainty
             source health)
```

* `backend/app/services.py::radar_intel` is the single entry point used by the radar API, public checks and case analysis.
  It recomputes campaigns only when findings change (cache key = counts and timestamps).
* Database changes are applied in place by `db.MIGRATIONS` (ALTER TABLE ADD COLUMN), so existing installations keep their data.
* UI consolidation: Home and Smart Protection merged into **Check**; the Reports page was folded into each case's Report step;
  the account control lives only in the header.

## Threat Constellation (v1.3)

`analyze_relationships()` (Campaign DNA) now returns campaigns **and all edges**. `radar_intel()` caches both. Consumers:

| Consumer | Uses |
|---|---|
| `GET /api/radar/graph` → Live Radar constellation (graph + accessible list) | items, edges, campaigns |
| `GET /api/radar` → source health, counts, Check-page early warnings | items, campaigns |
| Check (`/api/analyze`) | radar hosts, campaign templates |
| Case analysis | items by host / registrable domain, campaign membership |

There is no separate graph engine: the endpoint only filters and shapes the shared data. Teardown of the graph stops animations,
and delayed callbacks check that the graph instance they belong to still exists.
