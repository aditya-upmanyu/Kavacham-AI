# KAVACHAM LAB — PROJECT CONTEXT

> Persistent architectural memory of the Kavacham Lab build.
> Read this file before any future architectural change (version2.txt D.1).
> Last updated: Phase 10/11 (Reporting) milestone — see section 29.

## 1. Project Overview

KAVACHAM LAB is an **evidence-driven cyber investigation environment**
added to the existing KAVACHAM AI product. It exposes a workflow of
`CASE → EVIDENCE → ANALYSIS → INTELLIGENCE → CORRELATION → TIMELINE → RISK
→ INVESTIGATION → REPORT` under a separate `/lab` Flask Blueprint.

Two products share the repository but remain independent surfaces:

* **Product A — KAVACHAM AI**: Cybersecurity Threat Detection (existing).
  Must not be broken by Lab work.
* **Product B — KAVACHAM LAB**: Cyber Investigation & Threat Intelligence.

## 2. Existing Architecture

* Backend: Flask (Python 3), SQLite via stdlib `sqlite3` (no ORM), flat JSON
  APIs for Product A.
* Frontend: server-rendered Jinja2 templates + vanilla JS modules.
  No build step, no SPA framework.
* Product A entry: `app.py` (Flask app `app`), models under `model_training/`,
  analyzers under `analyzers/`, VirusTotal wrapper under `intel/`.
* Product A QA suite: `QA_test.py` (baseline 50/51 — one known expectation
  asserts "Intel reported unavailable" without a key).
* Lab QA suite: `test_lab.py` (see section 21).

## 3. Existing Kavacham AI

* Gmail/Phishing/spam detection product: `/`, `/predict`,
  `/api/phishing-check`, `/health`, model metrics in
  `static/model_performance.json` / metrics dict `app.metrics_data`.
* Must keep: working models, routes, pages, Gmail flow, settings, history,
  integrations (Sections B.1, CD).
* `app.py` boots `lab_db.bootstrap()` after registering the Lab blueprint so
  the live DB auto-migrates on every start (idempotent).

## 4. Kavacham Lab Architecture

* Blueprint: `lab/__init__.py` (`lab_bp`, url_prefix `/lab`).
* Routes: `lab/routes.py` — pages, Section 49 JSON APIs, NAV_STRUCTURE.
* Services (one concern per module):
  `health.py`, `case_service.py`, `evidence_service.py`,
  `analysis_service.py`, `intel_service.py`, `risk_service.py`,
  `report_service.py`.
* Persistence: `lab/db.py` — schema, versioned migrations, helpers
  (`query`, `query_one`, `execute`, `transaction`, `bootstrap`).

## 5. Frontend Stack

* Jinja2 templates in `templates/lab/` extending `lab/base.html` (shell:
  header, sidebar, scrim, toasts).
* Vanilla JS in `static/js/lab_*.js`; `lab_shell.js` exposes
  `window.LAB` (`toast`, `renderError`, `emptyState`, `esc`, `fmtTs`,
  `refreshHeaderHealth`).
* CSS in `static/css/lab*.css` (design tokens in `lab.css`, shell in
  `lab_shell.css`, cases in `lab_cases.css`, risk in `lab_risk.css`,
  reporting in `lab_reports.css`).
* No external frameworks; fonts: Inter + JetBrains Mono.

## 6. Backend Stack

* Flask; Python stdlib (`sqlite3`, `hashlib`, `re`, `urllib`,
  `email`, `json`, `struct`, `base64`).
* No new third-party dependencies introduced by the Lab.

## 7. Database

* SQLite file: `kavacham_lab.db` (env `KAVACHAM_LAB_DB` overrides path for
  tests). Gitignored.
* Migrations: `lab/db.py MIGRATIONS` list; currently **version 4**.
  v1 = identity/RBAC tables + cases, evidence, chain_of_custody, analyses,
  analysis_findings, iocs, case_iocs, entities, case_entities,
  timeline_events, notes, reports, audit_logs, alerts.
  v2 = `iocs.status` column (OBSERVED/VERIFIED/FALSE_POSITIVE).
  v3 = `cases.risk_score`, `cases.risk_assessed_at` (risk snapshot).
  v4 = `export_packages` (export center, Sections 70/BG).
* `db.integrity_check()` runs `PRAGMA integrity_check`; `db.table_counts()`
  exposes real counts.

## 8. Authentication

* Not yet introduced. Audit/actor fields use a default actor
  (case_service `ACTOR_DEFAULT`). RBAC tables (`roles`, `permissions`,
  `role_permissions`, `users`) exist in schema v1; server-side RBAC
  enforcement is a pending phase (version2.txt BI).

## 9. Existing ML Models

* Product A: spam model (`app.model`, `metrics_data`) + phishing checker.
* Lab analysis pipeline reuses Product A analyzers (see section 15) as the
  single source of truth for classification scores. The local "ML analysis"
  stage probes real classifiers; a missing model reports UNAVAILABLE
  honestly (never fabricated scores).
* No Lab-specific models added yet.

## 10. Existing Integrations

* VirusTotal: `intel/virustotal_service.py` — used by analysis pipeline
  (SHA-256 + URL) and IOC detail when `VIRUSTOTAL_API_KEY` is configured.
  Unconfigured → honest `NOT CONFIGURED`/`unavailable` stages.
* Gmail (Product A), Gemini/ULTRA AI (Product A) — left intact.
* No AbuseIPDB/Shodan/Censys/URLScan/HIBP/WebRisk/RDAP providers wired yet
  (available surfaces report NOT CONFIGURED).

## 11. Existing API Routes

Lab routes follow Section 49: `{"success": true, "data": ..., "meta": ...}`
on success, `{"success": false, "error": {"code", "message"}}` on error.
Pages: `/lab`, `/lab/cases`, `/lab/cases/new`, `/lab/cases/<ref>`,
`/lab/audit`, `/lab/evidence...`, `/lab/analysis...`, `/lab/intel/*`,
`/lab/risk`, `/lab/reports`, `/lab/reports/<ref>`, `/lab/reports/exports`,
`/lab/reports/manifest`.
APIs: `/lab/api/cases`, `/lab/api/cases/meta`, `/lab/api/audit`,
`/lab/api/evidence...`, `/lab/api/analysis...`, `/lab/api/health`,
`/lab/api/alerts`, `/lab/api/command-center`, `/lab/api/meta`,
`/lab/api/intel/*`, `/lab/api/risk`, `/lab/api/reports...`,
`/lab/api/exports...`, `/lab/api/cases/<ref>/export`.

## 12. Existing Important Components

* `lab_shell.js` (`window.LAB` utilities, header health refresh, drawer).
* Design system in `lab.css`: badges (incl. `lab-badge-*` semantic colors),
  panels, tables (`lab-table`), tabs, wizard steps, states
  (`lab-state` empty/error), toasts, skeleton loading.
* Intel: `lab_intel.js`, `lab_graph.js`, `lab_chains.js`, `lab_correlation.js`.
* Risk: `lab_risk.js` + `lab_risk.css` (band scale, finding cards).
* Reporting: `lab_reports.js` + `lab_exports.js` + `lab_reports.css`
  (report document with print-to-PDF, export center, manifest page).

## 13. Environment Variables

* `KAVACHAM_LAB_DB` — test override for the Lab DB path.
* `KAVACHAM_LAB_STORAGE` — test override for `lab_storage` (reports JSON,
  export packages, evidence originals).
* `VIRUSTOTAL_API_KEY` — optional; enables real VT lookups for SHA-256/URL.
  **Is set globally on the dev machine** — tests pin it OFF for
  determinism; unpatched runs perform real network calls.
* `.env` exists with Product A secrets; never commit secrets.

## 14. Database Schema

See `lab/db.py` `SCHEMA`/`MIGRATIONS`. Normalized tables with FKs +
indexes. Notes:
* `analyses` has **no `evidence_ref` column** — join via
  `evidence(evidence_id)` (risk/intel queries must derive it).
* `analysis_findings` keys evidence via `evidence_ref` (not `evidence_id`).
* `iocs` unique `(ioc_type, value)`; status column OBSERVED/VERIFIED/FALSE_POSITIVE.
* `cases.risk_level` (v1) + `risk_score`/`risk_assessed_at` (v3) are
  snapshots written only by the risk engine when an assessment is computed.

## 15. Lab Modules

* health — real per-service checks (API, ML, spam/phishing engines, risk
  engine, VT, Gemini, Gmail, DB, storage, background jobs, monitoring).
* case_service — create/list/search/detail/update, notes, audit, timeline.
* evidence_service — intake (web+API), hashing (SHA-256/1, MD5), PE/ELF
  magic blocking, custody chain, integrity verification, originals dir.
* analysis_service — 10-type registry (EMAIL/PHISHING/SPAM/URL/FILE/HASH/
  QR/DOMAIN/SCAM/BEC), stage pipeline, findings persistence, honest
  ML/VT probe states.
* intel_service — IOC classify/extract/sync, ledger, status workflow,
  cross-case correlation, entity graph, attack chains.
* risk_service — central risk engine (see section 19).
* report_service — reports (`KAV-RPT` refs, BF 15 sections), export
  packages (`KAV-EXP`, Section 70), evidence manifest + integrity
  verification (Sections 43/BG).

## 16. Provider Architecture

* `intel/virustotal_service.py` is consumed through analysis_service
  `_vt_state()` + runners. Threat-intel is a *stage* in the pipeline:
  failure → `unavailable` stage, local analysis continues (CE).
* Provider abstraction (version2.txt X/Y: AbuseIPDB, Shodan, Censys,
  URLScan, HIBP, WebRisk, RDAP, DNS) not yet built; the risk engine +
  IOC intel surfaces already degrade gracefully when absent.

## 17. Evidence Architecture

* `evidence` rows + `lab_storage/originals/` (gitignored). Intake blocks
  executable magic (`MZ`/`ELF`) for FILE uploads; extensions must match
  registry; hashes computed at intake.
* `chain_of_custody` append-only events (ACQUIRED, HASHED, ATTACHED,
  VIEWED, ANALYZED, REVIEWED, EXPORTED) with hash-chained entries.
* Integrity: stored SHA-256 vs current file → VERIFIED / MISMATCH.
* Original evidence and derived analyses stay separate (never mutate
  originals).

## 18. Investigation Architecture

* Case → evidence linkage, IOCs (`case_iocs`), entities, timeline events.
* Entity graph: nodes/edges only when a real stored link exists.
* Attack chains: stages gated on supporting evidence; "insufficient
  evidence" reported honestly.
* Correlation: shared IOC across cases → POTENTIAL CORRELATION with precise
  language; correlation ≠ attribution (Sections 25/27/28).

## 19. Risk Architecture

* `lab/risk_service.py` — normalized 0–100 with bands LOW(0–30) /
  SUSPICIOUS(31–60) / HIGH(61–100).
* Independent classifications SPAM/PHISHING/MALWARE/SCAM/BEC/SECURITY_RISK
  reported alongside the score, never conflated (spam ≠ malicious).
* Score = `0.6*highest_analysis + 0.3*mean_analysis
  + 6*min(verified_iocs,4) + 3*min(observed_iocs,4)`, clamped 0–100;
  FALSE_POSITIVE IOCs contribute 0. Formula exposed in the API.
* Evidence-first findings in the BA shape WHAT/WHY/EVIDENCE/SOURCE/IMPACT/
  LIMITATION, traced to stored analysis refs + evidence refs.
* Snapshots (`cases.risk_level/risk_score/risk_assessed_at`) written only
  when an assessment is computed; empty vaults report 0/LOW with an
  "Insufficient data" explanation — never a guessed number.

## 20. Security Controls

* Evidence uploads: extension allowlist, magic-blocking, filename
  sanitization, size limits, no execution.
* SSRF: URL analysis validates target hosts; no arbitrary internal access.
* API errors never expose stack traces/filesystem paths/secrets.
* VT key stays server-side (`.env` / env var).
* Pending phases: server-side RBAC (BI), audit hardening (BH), rate limits,
  secure headers/CSRF review, frontend security review (BT).

## 21. Testing Strategy

* `test_lab.py` — isolated temp DB + storage (env overrides set before any
  lab import), services + HTTP via `app.test_client()`. Sections 1..8, 7C,
  7D, 7E, 7F cover migrations, cases, evidence, analysis pipeline,
  intelligence, risk, reporting, Product A regression baseline. VT env
  pinned OFF inside destructive-analysis and intel sections and restored
  after.
* Product A: `QA_test.py` baseline 50/51 (VT-key assertion is the known
  expectation).

## 22. Current Implementation Status

Phases done (old plan numbering): 1 Repository Audit → 9 Reporting.
New 14-phase plan: Phases 1-11 done (Reporting completed); Phase 12
Security pending, 13 Health & Observability, 14 QA. Global command
search (CTRL+K, version2.txt O) and case-view ENTITIES/ATTACK CHAIN
tabs (Q) still pending.

## 23. Completed Features

Lab shell + nav + return-to-AI; command center (real health/alerts/
counts/model health); case management (wizard 5 steps, status workflow,
notes, timeline, audit); evidence (intake, vault, hash, custody,
integrity); analysis (10 types, stage pipeline, honest ML/VT);
intelligence (IOC ledger, correlation, entity graph, attack chains);
**risk engine (register + case assessments + evidence-first findings)**;
**reporting (BF 15-section reports, `KAV-RPT` refs, print-to-PDF,
`KAV-EXP` export packages, BG manifest + SHA-256 integrity, IOC CSV)**;
docs context file.

## 24. Pending Features

audit-log event vocabulary + secret-free logging;
server-side RBAC (BI); SSRF file/URL hardening; rate limiting;
system-health provider/settings page (BO/BP); structured logging +
correlation IDs (BZ); command search CTRL+K (O); case-view ENTITIES +
ATTACK CHAIN tabs (Q); model registry/dataset registry surfaces (BD/BE).

## 25. Known Limitations

* No authentication/RBAC enforcement yet (tables exist).
* VT only provider wired; other providers report NOT CONFIGURED.
* Live DB is schema v4 but has no vault data beyond a small seed
  (1 case + evidence set) until a rescan/analysis runs.
* No global command search yet.
* Case-view REPORT tab lists generated reports; generation lives in the
  Report Center.

## 26. Architectural Decisions

* Lab = separate Flask Blueprint `/lab`; Product A untouched except the
  `app.py` bootstrap call.
* SQLite stdlib (no new deps); migrations versioned under lock;
  `lab_storage/` gitignored.
* Product A analyzers remain the single source of truth for
  URL/domain/file/QR structure scoring.
* Section 49 envelope for all Lab APIs; Product A flat-JSON APIs untouched.
* "Never infer relationships without evidence"; IQ surfaces render only
  stored facts; absence reported honestly (NOT CONFIGURED / NO DATA /
  ANALYSIS INCOMPLETE).
* Risk computed on the fly from stored records; only snapshots written
  back (stamped) so other surfaces never show stale/fabricated values.
* Tests pin VT OFF (machine has a global key) for deterministic off-line QA.
* Export packages are stdlib-zipped with a stored SHA-256 (DB + sidecar)
  that verify re-computes; "PDF" export is a print-optimized document the
  browser renders to PDF — no new dependencies (69, CM).

## 27. Important Files

* `version2.txt` — the spec (13-phase plan + detailed A..CO sections +
  new 14-phase plan). Scratch/untracked.
* `lab/db.py`, `lab/routes.py`, `lab/*_service.py`, `lab/health.py`.
* `templates/lab/*`, `static/js/lab_*.js`, `static/css/lab*.css`.
* `test_lab.py`, `app.py`, `QA_test.py`.
* `docs/KAVACHAM_LAB_CONTEXT.md` — this file.

## 28. Do-Not-Break Rules

* Never rewrite/remove Product A routes, pages, models, Gmail flow,
  phishing/spam behavior, settings, or APIs (B.1, CD).
* Never add fake data, dead nav, placeholder buttons, or dummy APIs
  (H, 81, CH).
* No new dependencies without checking the existing stack (CM).
* Evidence must never be silently modified; corrections create new events.
* Correlation is not attribution; risk is not proof.

## 29. Last Verified State

* Git `main` = `kavacham` (Kavacham-AI) = `origin` (Anweshak-AI).
  All commits GPG-signed (key `5359FC122398973E`, public key in
  `pubkey.asc`); the Risk milestone is commit `4620b92` and the
  Reporting milestone follows this doc update (see `git log -1`).
* Lab suite: **309/309 passing** — 275 after Phase 9 (Risk), +34 in
  Test 7F covering reports, export packages, manifest + integrity,
  audit events, route inventory and page renders.
* Product A regression: 50/51 (known VT-key assertion).
* Reporting milestone verified live over HTTP: report auto-generated on
  export, `KAV-EXP` package verified (`sha256` match + zip OK), manifest
  rows present for analysed cases, CSV + zip download stream correctly.
* All live checks rerun via `python test_lab.py` before every push;
  nothing unverified is pushed.

## 30. Future Work

Phase 12 Security (RBAC server-side per BI, audit-log vocabulary +
secret-free logging per BH, SSRF/upload reviews, rate limits),
Phase 13 Health & Observability (provider health page BO/BP, structured
logs + correlation IDs BZ), Phase 14 QA (full suite + browser/accessibility
pass), then global command search (O), case-view ENTITIES/ATTACK CHAIN
tabs (Q) and CONTEXT.md refresh per phase (CG).