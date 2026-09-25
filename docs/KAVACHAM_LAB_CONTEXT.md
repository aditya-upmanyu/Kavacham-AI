# KAVACHAM LAB — PROJECT CONTEXT

> Persistent architectural memory of the Kavacham Lab build.
> Read this file before any future architectural change (version2.txt D.1).
> Last updated: RDAP+DNS network intel (AG) — see section 29.

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
* Product A QA: no `QA_test.py` file exists in the repo — the earlier
  baseline note was aspirational. Product A regression is covered by
  `test_lab.py` Test 8 (imports, blueprint registration, route inventory)
  plus live HTTP checks (`/` and `/health` return 200).
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

* No LOGIN surface yet, so actors default to `analyst` and the RBAC gate
  resolves role via `security.current_role()` → default ANALYST (single
  adapter point; only this changes when auth lands).
* **RBAC is implemented and enforced server-side** (version2.txt BI):
  roles ADMIN / INVESTIGATOR / ANALYST / REVIEWER / READ_ONLY, an
  explicit permission matrix (`lab/security.py`), and a
  `_require_permission` decorator gating every mutating API. The roles,
  permissions and role_permissions rows are seeded into the schema-v1
  tables by `db.bootstrap()`.
* Frontend hiding is NOT authorization — all checks run on the backend.

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
`/lab/reports/manifest`, `/lab/health`, `/lab/settings`.
APIs: `/lab/api/cases`, `/lab/api/cases/meta`, `/lab/api/audit`,
`/lab/api/evidence...`, `/lab/api/analysis...`, `/lab/api/health`,
`/lab/api/alerts`, `/lab/api/command-center`, `/lab/api/meta`,
`/lab/api/providers`,
`/lab/api/intel/*`, `/lab/api/risk`, `/lab/api/reports...`,
`/lab/api/exports...`, `/lab/api/cases/<ref>/export`, `/lab/api/search`,
`/lab/api/intel/network`.

## 12. Existing Important Components

* `lab_shell.js` (`window.LAB` utilities incl. page `corrId`, header
  health refresh, drawer).
* Design system in `lab.css`: badges (incl. `lab-badge-*` semantic colors),
  panels, tables (`lab-table`), tabs, wizard steps, states
  (`lab-state` empty/error), toasts, skeleton loading.
* Intel: `lab_intel.js`, `lab_graph.js`, `lab_chains.js`, `lab_correlation.js`,
  `lab_bulk.js` (AN paste-to-case flow).
* Risk: `lab_risk.js` + `lab_risk.css` (band scale, finding cards).
* Reporting: `lab_reports.js` + `lab_exports.js` + `lab_reports.css`
  (report document with print-to-PDF, export center, manifest page).
* Health & observability: `lab_health.js` + `lab_settings.js` +
  `lab_health.css` (BO status/latency/error/configuration table, BP
  provider surface); command-center mission board via
  `lab_command_center.js` CURRENT OPERATIONS strip.
* Global search: `lab_search.js` CTRL+K palette (debounced, grouped,
  keyboard-navigable, focus-restoring dialog) backed by `/lab/api/search`.
* Case view: ENTITIES + ATTACK CHAIN tabs in `case_detail.html` /
  `lab_case_detail.js`, fed by the existing intel graph/chain APIs.

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

* health — 21 real per-service checks (core: API, ML, spam/phishing/
  scam engines, risk; integrations: VT, AbuseIPDB, Shodan, Censys,
  URLScan, HIBP, WebRisk, Gemini, Gmail; data: DB, storage; infra:
  background jobs, queue, workers, monitoring). Every row carries
  STATUS/LATENCY/LAST CHECK/ERROR/CONFIGURATION; unwired surfaces report
  NOT CONFIGURED with null latency.
* obs — BZ structured request logging (`request_id`/`service`/`operation`/
  `duration_ms`/`status`, no query strings/secrets) + correlation ids
  (inbound `X-Correlation-ID` threaded, `X-Request-ID` on every response).
* search_service — O global search over cases/evidence/analyses/IOCs/
  sender entities; exact-before-partial ranking, type filter, capped
  groups with real page links; empty/unknown queries return nothing.
* case_service — create/list/search/detail/update, notes, audit, timeline.
* evidence_service — intake (web+API), hashing (SHA-256/1, MD5), PE/ELF
  magic blocking, custody chain, integrity verification, originals dir.
* analysis_service — 11-type registry (EMAIL/PHISHING/SPAM/URL/FILE/HASH/
  QR/DOMAIN/SCAM/BEC/SMS), stage pipeline, findings persistence, honest
  ML/VT probe states; DOMAIN runs carry keyless DNS+RDAP network intel.
* network_intel — AG keyless DNS (DoH reads) + RDAP (IANA bootstrap),
  8s timeouts, honest available/unavailable/invalid states, never raises.
* intel_service — IOC classify/extract/sync, ledger, status workflow,
  cross-case correlation, entity graph, attack chains, bulk IOC
  paste-to-case (AN).
* risk_service — central risk engine (see section 19).
* report_service — reports (`KAV-RPT` refs, BF 15 sections), export
  packages (`KAV-EXP`, Section 70), evidence manifest + integrity
  verification (Sections 43/BG).
* security — BH audit vocabulary + secret redaction at the audit funnel,
  BI RBAC matrix, `seed_rbac()`, role resolution adapter (section 8).

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
* Audit (BH): event vocabulary (11 required types) recorded at every
  surface; `case_service.audit()` is the single funnel and redacts
  passwords / API keys / OAuth tokens / session secrets / DB credentials
  before persistence (never-log rules). LOGIN/LOGOUT/SETTINGS_CHANGED
  become recordable when their surfaces exist.
* RBAC (BI): 12 mutating APIs gated by `_require_permission` — denied
  roles get a Section 49 `FORBIDDEN` error.
* Pending: rate limits, secure headers/CSRF review, frontend security
  review (BT), secret-manager integration.

## 21. Testing Strategy

* `test_lab.py` — isolated temp DB + storage (env overrides set before any
  lab import), services + HTTP via `app.test_client()`. Sections 1..8, 7C,
  7D, 7E, 7F, 7G, 7H cover migrations, cases, evidence, analysis pipeline,
  intelligence, risk, reporting, security (audit vocabulary + redaction +
  RBAC enforcement), health & observability (BO/BP/BZ/BQ), QA security
  gap-fill (CC: IDOR, SQLi, XSS posture, SSRF posture, malformed input,
  open redirects, secret exposure) + accessibility guards (BV), global
  search + case-view tabs (O/Q), Product A
  regression baseline. VT env pinned OFF
  inside destructive-analysis and intel sections and restored after.
* Product A regression is covered by `test_lab.py` Test 8 + live HTTP
  checks (no separate QA file exists in the repo).

## 22. Current Implementation Status

Phases done (old plan numbering): 1 Repository Audit → 9 Reporting.
New 14-phase plan: Phases 1-14 done (**QA completed — the 14-phase plan
is complete**). version2.txt follow-ups done: global command
search (CTRL+K, O) and case-view ENTITIES/ATTACK CHAIN tabs (Q).
Still open: the BI tail (LOGIN/RBAC users, rate limits + secure
headers).

## 23. Completed Features

Lab shell + nav + return-to-AI; command center (real health/alerts/
counts/model health); case management (wizard 5 steps, status workflow,
notes, timeline, audit); evidence (intake, vault, hash, custody,
integrity); analysis (11 types incl. SMS/smishing, stage pipeline,
honest ML/VT);
intelligence (IOC ledger, bulk paste-to-case, correlation, entity graph,
attack chains);
**risk engine (register + case assessments + evidence-first findings)**;
**reporting (BF 15-section reports, `KAV-RPT` refs, print-to-PDF,
`KAV-EXP` export packages, BG manifest + SHA-256 integrity, IOC CSV)**;
**security (BH audit vocabulary + never-log redaction at the funnel,
BI RBAC matrix seeded + enforced server-side on 12 mutating APIs)**;
**health & observability (BO 21-service System Health page,
BP provider Settings surface with no secrets, BZ structured logging +
correlation ids, BQ CURRENT OPERATIONS mission board)**;
**QA (CC security gap-fill: IDOR/SQLi/XSS/SSRF/malformed/redirect/secret
posture; BV skip link + focus-visible + reduced motion; CD regression +
production readiness)**;
**global search (O CTRL+K palette over cases/evidence/analyses/IOCs/
entities, exact-before-partial, filters, keyboard navigation)**;
**case-view ENTITIES + ATTACK CHAIN tabs (Q, fed by the intel
graph/chain APIs)**;
docs context file.

## 24. Pending Features

rate limiting; secure headers/CSRF review; secret-manager integration;
frontend security review (BT); model
registry/dataset registry surfaces (BD/BE); RBAC users/LOGIN surface.

## 25. Known Limitations

* No LOGIN surface yet — RBAC enforcement runs server-side against the
  default ANALYST role (see section 8; adapter point documented).
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
* Audit funnel: every write passes `case_service.audit()` (or the same
  INSERT contract) which redacts secrets centrally — never-log rules are
  enforced at persistence time, not at call sites (BH).
* RBAC: permission matrix lives in `lab/security.py` and is mirrored into
  the schema-v1 tables; enforcement is a decorator on the route, never
  UI state (BI).
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
* `test_lab.py`, `app.py`.
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
  `pubkey.asc`); Risk milestone `4620b92`, Reporting milestone `e96946a`,
  Security milestone `1fd997e`, Health & Observability milestone `d0ca29e`,
  QA milestone `d7df0fe`, Global search + case-view tabs `ea948e8`,
  SMS + bulk IOC `4301e45`, RDAP+DNS `b01321d`.
* Lab suite: **444/444 passing** — +21 in Tests 7K/7L (AP: SMS registry,
  fraud/benign verdicts, dual-engine sources, incompatibility, API run;
  AN: preview counts, investigate-to-case with ledger links, blank-text
  rejection, page render; nav count 6), +7 in Test 7M (AG: invalid/dead
  domain honesty, timeout budget, DOMAIN payload + stage, API envelope).
* AP+AN verified live over HTTP: bulk page + preview/investigate round
  trip (case + evidence + ledger links), SMS in the analysis registry and
  Run Analysis options.
* AG verified live: dead domains degrade to unavailable/unavailable,
  11 analysis types served.
* O+Q verified live over HTTP: search returns grouped exact-first hits,
  palette + trigger render in the shell, case view carries both new tabs,
  graph/chain APIs return real per-case data.
* QA milestone verified live over HTTP: Product A `/` + `/health`
  return 200, skip link renders, live DB `PRAGMA integrity_check` ok at
  schema v4, no scratch files tracked.
* Security milestone verified live over HTTP: RBAC rows seeded
  (5 roles, 68 role_permissions), analyst create-case allowed, header
  role indicator + full audit filter vocabulary render.
* Health & Observability milestone verified live over HTTP: 21-service
  health page (STATUS/LATENCY/LAST CHECK/ERROR/CONFIGURATION), providers
  API (7 providers, no secret material), command-center mission board
  matching the ledger, `X-Request-ID` echoing an inbound
  `X-Correlation-ID`, structured `kavacham.obs` lines in server logs.
* Reporting milestone verified live: report auto-generation, `KAV-EXP`
  verify, manifest rows, CSV + zip download.
* Product A regression: Test 8 + live `/` and `/health` 200
  (no separate QA file exists in the repo).
* Reporting milestone verified live over HTTP: report auto-generated on
  export, `KAV-EXP` package verified (`sha256` match + zip OK), manifest
  rows present for analysed cases, CSV + zip download stream correctly.
* All live checks rerun via `python test_lab.py` before every push;
  nothing unverified is pushed.

## 30. Future Work

The 14-phase plan plus the O/Q follow-ups are complete. version2.txt
extensions done: SMS/smishing analysis (AP), bulk IOC investigation
(AN), keyless RDAP+DNS network intel (AG). Still open: model/dataset
registries (BD/BE), rate limits + secure headers + privacy settings
(BS/BR/BT), LOGIN/RBAC users (BI tail).