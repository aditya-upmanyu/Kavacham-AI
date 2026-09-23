# KAVACHAM LAB — Phase 1: Repository Audit

> Per `version2.txt` Section 0 — inspect before modifying.
> This document records the actual state of the repository at the start of the
> Lab build, so that later phases reuse existing systems instead of duplicating them.

---

## 1. Stack

| Layer | Technology | Notes |
| :--- | :--- | :--- |
| Backend | Flask >= 3.0 (single `app.py`, 912 lines) | Debug mode, dev server |
| Frontend | Vanilla HTML/CSS/JS, 3 templates | No framework, no build step |
| ML | scikit-learn Multinomial Naive Bayes + FeatureUnion | `models/kavacham_v2.pkl` |
| Auth | Flask `session` + Google OAuth 2.0 (Gmail read-only) | **No user accounts, no RBAC** |
| Database | **None** | History kept in `session["analysis_history"]` |
| Real-time | **None** | — |

## 2. Existing Routes (app.py)

Page routes: `/` (index SPA), `/dashboard`, `/authorize`, `/oauth2callback`, `/logout`.

API routes:
- `/predict`, `/analyze-email-simple`, `/ultra-analyze`
- `/api/analyze-email`, `/api/phishing-check`
- `/api/threat/{url,message,file}`, `/api/threat/status`
- `/api/virustotal-status`, `/api/gmail-status`, `/gemini-status`
- `/api/history` (GET/POST/DELETE), `/api/metrics` + `/model-info`, `/health`

**Response convention:** flat JSON objects, mostly unwrapped. No `{success, data, meta}`
envelope. Errors are `{"error": "..."}` with a 200/400/500 status.

## 3. Reusable Services (do NOT duplicate)

| Module | Provides | Lab reuse |
| :--- | :--- | :--- |
| `analyzer/risk_engine.py` | Central risk score + verdict + `top_reasons` | Phase 9 (central risk) |
| `analyzer/phishing_analyzer.py` | Phishing signals | Phase 7 |
| `analyzer/spam_analyzer.py` | Spam classification | Phase 7 |
| `analyzer/url_analyzer.py` | URL extraction + scoring | Phase 7 (URL pipeline) |
| `analyzer/attachment_analyzer.py` | Hash + MIME + extension risk | Phase 7 (file/hash) |
| `analyzer/qr_analyzer.py` | QR decode + quishing | Phase 7 (QR) |
| `analyzer/scam_analyzer.py` | Scam / social engineering | Phase 7 |
| `analyzer/bec_analyzer.py` | BEC / fraud | Phase 7 |
| `analyzer/header_analyzer.py` | Email header forensics | Phase 7 (header) |
| `analyzer/sender_analyzer.py` | Sender / spoof analysis | Phase 7 |
| `analyzer/email_analyzer.py` | Unified orchestrator | Phase 7 entry point |
| `analyzer/ai_explainer.py` | Gemini explanation | Optional, degrades gracefully |
| `intel/virustotal_service.py` | VT lookup + `availability_status()` | Phase 8 (TI) |
| `threat_service.py` | URL/file/message threat scoring | Phase 8 |
| `parsers/email_parser.py` | `build_normalized_email()` | Evidence intake |
| `gemini_service.py` | `analyze_with_gemini`, `get_gemini_status` | Phase 8 |
| `train_model.py` | `clean_text`, `clean_text_advanced` | — |

## 4. Identified Risks

1. **No persistence layer.** Cases, evidence, chain of custody and audit logs all
   require durable storage. Session storage is insufficient. → Introduce SQLite
   (stdlib, no new dependency) behind a small data layer.
2. **No authentication/authorization.** RBAC (Section 45) has no user model to
   build on. Must add users/roles before RBAC can be real.
3. **Monolithic `app.py`.** Adding ~60 Lab endpoints inline would make it
   unmanageable. → Use a Flask **Blueprint** so Lab code is isolated and the
   existing product is untouched.
4. **No response envelope.** Lab APIs should follow Section 49 while existing
   APIs keep their convention (Section 48: follow established convention, don't
   rewrite working APIs).
5. **Flat templates.** Only 3 templates exist; Lab needs its own shell + sub-
   templates to avoid touching the existing pages.
6. **Health data is thin.** `/health` reports model/vectorizer/credentials only.
   Section 13/51 require per-service real checks. → Add a health service that
   measures each dependency honestly and reports `SERVICE UNAVAILABLE` /
   `NOT CONFIGURED` rather than guessing.

## 5. Integration Points

- **Entry:** a single `ENTER LAB` control on the existing index page → `/lab`.
  Minimal change to Product A.
- **Return:** `RETURN TO KAVACHAM AI` in the Lab sidebar → `/`.
- **Analysis:** Lab analysis modules call the existing `analyzer/*` functions
  directly (in-process), never duplicating their logic.
- **Model:** Lab reads the same loaded `model`/`vectorizer` already initialised
  by `load_ml_components()`.
- **Threat intel:** Lab calls `intel.virustotal_service.availability_status()`
  to report honest availability instead of assuming a key exists.

## 6. Existing Tests

`test_engine.py` — 51-assertion QA suite, currently 50 pass / 1 known failure
(VirusTotal key assertion). This becomes the Phase 13 regression baseline and
must keep passing after every Lab phase.

---

**Conclusion:** Build the Lab as an isolated Flask Blueprint + its own templates
and static assets, backed by a new SQLite data layer, reusing every existing
`analyzer/*`, `intel/*` and `threat_service` module in-process. Product A
(KAVACHAM AI) stays visually and functionally intact except for the one entry
control.
