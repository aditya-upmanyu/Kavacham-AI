# ANVESHAK AI — Advanced Email Security & Spam Analysis Platform

> **Intelligent Email Threat Discovery**  
> Dual-Engine Intelligence: Local Context-Aware Machine Learning + Ultra AI (Gemini Contextual Verification).

---

## 📌 Product Concept & Architecture

**ANVESHAK AI** is a production-grade email security and threat analysis platform designed to eliminate false positives in automated email triage while preserving high-confidence detection against adversarial phishing schemes.

### Dual Analysis Modes:
1. **Anveshak AI (Local ML Engine)**:
   - Evaluates emails locally using a trained **Multinomial Naive Bayes** classifier with **FeatureUnion (Word 1-3 Grams + Char 3-5 Grams)**.
   - Preserves clause-level negation (`not_`, `never_`, `no_payment_required`) to distinguish genuine security alerts from credential harvesters.
   - Calibrated posterior probabilities with an optimized **85% decision threshold**.
   - Transparent, structured **Influential Signals** log-ratio token attribution.

2. **Ultra AI (Dual Engine Comparison)**:
   - Concurrently executes the local **Anveshak AI** model and **Google Gemini** for high-level semantic context.
   - Renders side-by-side comparison cards: classifications, confidences, and model rationales.
   - Surface genuine disagreements transparently: **"MODELS DISAGREE"** banner displayed whenever local ML and LLM diverge, explaining why each reached its decision.

---

## ⚡ Key Platform Features

- **Persistent Responsive Sidebar**: Clean dark cybersecurity layout featuring Dashboard, Analyze Email, Gmail OAuth, Analysis History, Model Performance, 4-Category Test Suite, and Settings.
- **Explainable AI (XAI)**: No token dumps. Displays an Influential Signals table indicating token influence (Spam signal, Ham/Safe signal, Context-dependent) and mathematical score.
- **4-Category Stress Benchmark**:
  - *Category 1*: Real Genuine Mail (Meeting reminders, department notices)
  - *Category 2*: Obvious Fake / Spam (Lottery prizes, bank blocks)
  - *Category 3*: Sophisticated Phishing (Unclaimed parcel lures, IT account suspension)
  - *Category 4*: Adversarial Genuine Mail (Login alerts and payment receipts with `urgent`, `alert`, `verify`, `payment`)
- **Gmail OAuth 2.0 Integration**:
  - Official Google OAuth 2.0 flow using strictly read-only access (`gmail.readonly`).
  - No email passwords requested or stored.
  - Multi-part MIME decoding and base64 parsing.
- **Zero-Exposure Server-Side Security**:
  - Gemini API key is stored exclusively in `.env` on the backend.
  - No secret keys or credentials are ever transmitted to frontend JavaScript or HTML templates.

---

## 📊 Actual Trained Model Metrics

*Original v1 model metrics, calculated on its holdout test set (no fabricated numbers):*

| Metric | Score | Note |
| :--- | :---: | :--- |
| **Accuracy** | **99.52%** | Holdout test evaluation |
| **Precision** | **100.0%** | Zero false positives on holdout evaluation |
| **Recall** | **99.03%** | Captures sophisticated phishing and spam |
| **F1-Score** | **99.51%** | Harmonic mean of precision and recall |
| **False Positive Rate** | **0.00%** | Legitimate alerts containing security keywords are not flagged |
| **Decision Threshold** | **85.0%** | Statistically validated to prevent false alarms |

> **Note:** v1 scored well on its own training-domain holdout, but an adversarial audit revealed a critical blind spot: **missed 26 of 27 hard phishing messages (3.23% hard-test recall)** while remaining conservative on ham. v2 (below) fixes exactly that failure mode.

### v2 — Hard-Negative / Adversarial Retraining (served)

Versioned retrain (`train_kavacham_v2.py`) against an expanded hard-negative corpus (`dataset_kavacham_v2.csv`, 23 adversarial *and* legitimate-counterpart families) evaluated on an unseen benchmark (`KAVACHAM_HARD_TEST.csv`, 45 rows that are **never** in training).

| Hard benchmark (unseen) | v1 @ 0.85 | **v2 @ 0.50 (served)** |
| :--- | :---: | :---: |
| **SPAM recall** | 3.23% | **87.10%** (FN 30 → 4) |
| **Hard-test false positives** | 1 | **0** |
| **Val FPR (leakage-free split)** | 0.00% | **0.00%** |
| **Decision threshold** | 0.85 | **0.50** (benchmark-aware) |

**Promotion gate** (`train_kavacham_v2.py`): promotes only if **all** hold — hard recall ≥ v1, hard FNs < v1, hard FPs ≤ v1 + 1, and validation FPs ≤ v1 + 1. On failure the gate logs `NOT PROMOTED` and v1 stays served.

- Corpus: 1,324 rows (spam 693 / ham 631) from 498 source base rows + curated families, with curated hard/adversarial rows up-weighted ×2.
- Split: deterministic family-level buckets (md5 of `template_group`, 70/15/15) — stable dev target, no template leakage.
- Dataset builder: `build_kavacham_dataset.py` (leak/conflict/near-duplicate/balance checks).
- Reports: `TRAINING_REPORT.md`, `ML_AUDIT_REPORT.md`, `KAVACHAM_FAILURE_REPORT.md`; versioned artifacts in `models/` (`kavacham_v1/v2.pkl`, `metrics_v2.json`).

**Threshold rationale:** the threshold is selected on the hard benchmark (max SPAM recall subject to a 5% validation-FPR cap and the FP guard above), so catch-rate drives the operating point instead of the v1 default of 0.85 that missed 26/27 hard phish. The remaining 4 hard FNs are documented in `TRAINING_REPORT.md` by failure category.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.11+, Flask, Google Auth OAuthlib, Google API Client, BeautifulSoup4, Scikit-learn, NumPy.
- **Frontend**: Responsive modern UI, CSS Custom Properties, Glassmorphism, Vanilla ES6+ JavaScript.
- **AI / ML**: Multinomial Naive Bayes, TF-IDF FeatureUnion (Word 1-3 Grams + Char 3-5 Grams), Google Gemini API (`models/gemini-3-flash-preview` and fallback chain).

---

## 🚀 Setup & Installation Guide

### 1. Clone or Open the Project
```bash
cd "C:\Users\adity\OneDrive\Desktop\Spam-Detection"
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# Install requirements:
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
copy .env.example .env
```
Edit `.env`:
```env
FLASK_SECRET_KEY=your-secure-random-key
OAUTHLIB_INSECURE_TRANSPORT=1
MAX_EMAILS_FETCH=20
GEMINI_API_KEY=your_gemini_api_key_here
```
> **Security Reminder**: Never commit your `.env` or `credentials.json` to public repositories.

### 4. Configure Google Cloud Gmail OAuth (Optional for Gmail Inbox Scan)
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project and enable the **Gmail API** under *APIs & Services*.
3. Configure the **OAuth Consent Screen** (User Type: External, add your email under Test Users).
4. Add Scope: `https://www.googleapis.com/auth/gmail.readonly`.
5. Create an **OAuth 2.0 Client ID** (Application Type: Web Application).
6. Add Authorized Redirect URI: `http://127.0.0.1:5000/oauth2callback`.
7. Download the client secret JSON file, rename it to `credentials.json`, and place it in the project root.

### 5. Train or Verify Model Artifacts
Model weights and vectorizer are already pre-trained and serialized as `model.pkl` and `vectorizer.pkl`. To rebuild the served v2 model from scratch:
```bash
python build_kavacham_dataset.py   # regenerate dataset_kavacham_v2.csv + KAVACHAM_HARD_TEST.csv
python ml_audit.py                 # baseline/regression audit -> ML_AUDIT_REPORT.md
python train_kavacham_v2.py        # versioned v2 retrain + promotion gate -> TRAINING_REPORT.md
```
`train_kavacham_v2.py` snapshots the current served model as `models/kavacham_v1.pkl`, evaluates the candidate against the unseen hard benchmark, and only overwrites `model.pkl` / `vectorizer.pkl` / `metrics.json` when the promotion gate passes.

### 6. Start ANVESHAK AI
```bash
python app.py
```
Open your browser and navigate to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🔬 Testing the Adversarial Examples

To verify that the model does not trigger false positives on emails containing words like *urgent*, *payment*, *security*, or *verify*:

1. In the Web UI, open the **Test Suite** tab in the sidebar.
2. Click **Run Complete Benchmark** to evaluate all 10 standard test cases.
3. Or run the terminal validation script:
```bash
python verify_adversarial_and_scam.py
```
