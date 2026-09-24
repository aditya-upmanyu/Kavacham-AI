"""
app.py
======
KAVACHAM AI — Production-style Intelligent Email Threat Discovery Platform.

Features:
- Official Google OAuth 2.0 flow with Gmail Read-only scope
- Recursive MIME multipart & base64url email decoding
- Context-aware preprocessing with clause-level negation preservation
- FeatureUnion (Word TF-IDF 1-3 grams + Char TF-IDF 3-5 grams)
- Multinomial Naive Bayes with optimized decision threshold (>= 0.85 for Spam)
- Explainable AI: Influential Signals with log-ratio attribution
- Ultra AI mode: local ML + Gemini contextual second opinion
- Analysis history (session-based)
- Model metrics endpoint, Gemini status endpoint
"""

import os
import re
import json
import pickle
import base64
import uuid
import joblib
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash
)
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Google Auth & Gmail API
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Import preprocessing from train_model
from train_model import clean_text_advanced, clean_text

# Import Gemini service (backend-only — key never exposed to frontend)
from gemini_service import analyze_with_gemini, get_gemini_status

# Import Threat Discovery service (phishing checker backend)
from threat_service import analyze_url as threat_analyze_url, analyze_file as threat_analyze_file, analyze_message as threat_analyze_message

# Import Unified Email Threat Analysis Engine (Task 2)
from parsers.email_parser import normalize_gmail_message, build_normalized_email
from analyzer.email_analyzer import analyze_email as unified_analyze_email
from intel.virustotal_service import availability_status as vt_availability_status

# Load environment configurations
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "dev-secret-key-spam-detector-2026-secure-session"

# --------------------------------------------------------------------------
# KAVACHAM LAB — isolated blueprint (Product B). Registered separately so
# Product A's routes, APIs and templates remain untouched.
# --------------------------------------------------------------------------
from lab import lab_bp  # noqa: E402
app.register_blueprint(lab_bp)

# Apply KAVACHAM LAB schema migrations at startup (idempotent, versioned).
from lab import db as lab_db  # noqa: E402
lab_db.bootstrap()

# Local testing OAuth allow HTTP transport
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT", "1")

# Strictly read-only Gmail scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
MODEL_FILE = os.path.join(os.path.dirname(__file__), "model.pkl")
VECTORIZER_FILE = os.path.join(os.path.dirname(__file__), "vectorizer.pkl")
METRICS_FILE = os.path.join(os.path.dirname(__file__), "metrics.json")

# Default threshold if not loaded from metrics
SPAM_DECISION_THRESHOLD = 0.85

# --------------------------------------------------------------------------
# Load Machine Learning Model, Vectorizer & Metrics
# --------------------------------------------------------------------------
model = None
vectorizer = None
metrics_data = {}

def load_ml_components():
    global model, vectorizer, metrics_data, SPAM_DECISION_THRESHOLD
    if os.path.exists(MODEL_FILE) and os.path.exists(VECTORIZER_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            vectorizer = joblib.load(VECTORIZER_FILE)
            print("[+] ML Model & Vectorizer loaded successfully.")
        except Exception as e:
            print(f"[!] Error loading ML artifacts: {e}")
    else:
        print("[*] Generating ML artifacts via train_model.py...")
        try:
            from train_model import train_and_evaluate
            train_and_evaluate()
            model = joblib.load(MODEL_FILE)
            vectorizer = joblib.load(VECTORIZER_FILE)
            print("[+] ML Model & Vectorizer trained and loaded.")
        except Exception as e:
            print(f"[!] Model training failed: {e}")

    # Load metrics metadata
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, "r") as f_met:
                metrics_data = json.load(f_met)
                SPAM_DECISION_THRESHOLD = metrics_data.get("decision_threshold", 0.85)
                print(f"[+] Loaded evaluation metrics. Decision threshold: {SPAM_DECISION_THRESHOLD}")
        except Exception as e:
            print(f"[!] Could not load metrics.json: {e}")

load_ml_components()

def analyze_influential_tokens(features, vectorizer, model):
    """
    Computes explainable token contributions.
    Categorizes features into 'Spam signal', 'Ham / Safe signal', or 'Neutral / Contextual'
    based on the Naive Bayes log-ratio of conditional probabilities.
    """
    signals = []
    try:
        feature_names = vectorizer.get_feature_names_out()
        non_zero_indices = features.nonzero()[1]

        # log P(feature | Spam) - log P(feature | Ham)
        log_prob_diff = model.feature_log_prob_[1] - model.feature_log_prob_[0]

        candidate_tokens = []
        for idx in non_zero_indices:
            name = feature_names[idx]
            clean_name = name.replace("word_tfidf__", "").replace("char_tfidf__", "")
            if name.startswith("char_tfidf__"):
                continue  # display word-level explanations only
            score = log_prob_diff[idx]
            candidate_tokens.append((clean_name, score))

        # Sort by absolute impact
        candidate_tokens.sort(key=lambda x: abs(x[1]), reverse=True)

        for name, score in candidate_tokens[:8]:
            if score > 0.4:
                status = "Spam signal"
            elif score < -0.4:
                status = "Ham / Safe signal"
            else:
                status = "Neutral / Contextual"
            signals.append({"token": name, "status": status, "score": round(float(score), 2)})
    except Exception:
        signals = []

    return signals

def predict_spam(raw_text: str):
    """
    Executes context-aware ML inference on raw text.
    Returns prediction dict with confidence, signals, and threshold.
    """
    if model is None or vectorizer is None:
        raise ValueError("ML model or vectorizer is not loaded.")

    cleaned = clean_text_advanced(raw_text)
    if not cleaned:
        cleaned = raw_text.lower().strip() if raw_text else "empty"

    features = vectorizer.transform([cleaned])
    probabilities = model.predict_proba(features)[0]
    classes = list(model.classes_)

    ham_idx = classes.index(0) if 0 in classes else 0
    spam_idx = classes.index(1) if 1 in classes else 1

    prob_spam = float(probabilities[spam_idx])
    prob_ham = float(probabilities[ham_idx])

    # Calibrate display confidence — never claim 100% certainty
    calibrated_prob_spam = min(99.4, max(0.6, prob_spam * 100))
    calibrated_prob_ham = min(99.4, max(0.6, prob_ham * 100))

    # Apply optimized decision threshold
    if prob_spam >= SPAM_DECISION_THRESHOLD:
        prediction = "Spam"
        display_confidence = round(calibrated_prob_spam, 2)
    else:
        prediction = "Not Spam"
        display_confidence = round(calibrated_prob_ham, 2)

    # Compute explainable signals
    signals = analyze_influential_tokens(features, vectorizer, model)
    matched_keywords = [s["token"] for s in signals[:6]]

    return {
        "prediction": prediction,
        "confidence": display_confidence,
        "probability_spam": round(prob_spam * 100, 2),
        "probability_ham": round(prob_ham * 100, 2),
        "decision_threshold": round(SPAM_DECISION_THRESHOLD * 100, 1),
        "influential_signals": signals,
        "matched_keywords": matched_keywords
    }

# --------------------------------------------------------------------------
# Analysis History (session-based, max 50 entries)
# --------------------------------------------------------------------------
def get_session_history():
    return session.get("analysis_history", [])

def add_to_session_history(entry: dict):
    history = session.get("analysis_history", [])
    history.insert(0, entry)
    if len(history) > 50:
        history = history[:50]
    session["analysis_history"] = history
    session.modified = True

# --------------------------------------------------------------------------
# Google OAuth 2.0 Helpers
# --------------------------------------------------------------------------
def has_valid_credentials_file() -> bool:
    """Verifies that credentials.json exists and does not contain placeholder strings."""
    if not os.path.exists(CREDENTIALS_FILE):
        return False
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            data = json.load(f)
            client_id = ""
            if "web" in data:
                client_id = data["web"].get("client_id", "")
            elif "installed" in data:
                client_id = data["installed"].get("client_id", "")
            if not client_id or "YOUR_GOOGLE_CLIENT_ID" in client_id:
                return False
            return True
    except Exception:
        return False

def get_google_credentials():
    """Builds google.oauth2.credentials.Credentials from the user session."""
    creds_data = session.get("credentials")
    if not creds_data:
        return None
    try:
        creds = Credentials(
            token=creds_data.get("token"),
            refresh_token=creds_data.get("refresh_token"),
            token_uri=creds_data.get("token_uri"),
            client_id=creds_data.get("client_id"),
            client_secret=creds_data.get("client_secret"),
            scopes=creds_data.get("scopes")
        )
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session["credentials"] = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": creds.scopes
            }
        return creds
    except Exception as e:
        print(f"[!] Error refreshing credentials: {e}")
        session.pop("credentials", None)
        return None

def get_gmail_service():
    """Returns an authenticated Gmail API service instance."""
    creds = get_google_credentials()
    if not creds or not creds.valid:
        return None
    return build("gmail", "v1", credentials=creds)

# --------------------------------------------------------------------------
# Robust Gmail MIME Multipart & Base64 Decoder
# --------------------------------------------------------------------------
def decode_base64url(data_str: str) -> str:
    if not data_str:
        return ""
    try:
        missing_padding = len(data_str) % 4
        if missing_padding != 0:
            data_str += "=" * (4 - missing_padding)
        decoded_bytes = base64.urlsafe_b64decode(data_str)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""

def extract_email_body_and_metadata(payload: dict) -> dict:
    if not payload:
        return {"body": "", "num_links": 0, "has_html": False}

    plain_text_parts = []
    html_text_parts = []
    total_links = 0
    has_html = False

    def walk_parts(part):
        nonlocal total_links, has_html
        mime_type = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data", "")

        if mime_type == "text/plain" and body_data:
            decoded = decode_base64url(body_data)
            if decoded.strip():
                plain_text_parts.append(decoded)
                total_links += len(re.findall(r"https?://\S+|www\.\S+", decoded))

        elif mime_type == "text/html" and body_data:
            has_html = True
            decoded = decode_base64url(body_data)
            if decoded.strip():
                try:
                    soup = BeautifulSoup(decoded, "html.parser")
                    total_links += len(soup.find_all("a"))
                    for element in soup(["script", "style", "meta", "noscript"]):
                        element.extract()
                    cleaned_html = soup.get_text(separator=" ", strip=True)
                    if cleaned_html:
                        html_text_parts.append(cleaned_html)
                except Exception:
                    html_text_parts.append(decoded)

        for subpart in part.get("parts", []):
            walk_parts(subpart)

    walk_parts(payload)

    final_body = " ".join(plain_text_parts).strip() if plain_text_parts else " ".join(html_text_parts).strip()
    return {"body": final_body, "num_links": total_links, "has_html": has_html}

def parse_email_message(msg_data: dict) -> dict:
    headers = msg_data.get("payload", {}).get("headers", [])
    headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers}

    sender = headers_dict.get("from", "Unknown Sender")
    subject = headers_dict.get("subject", "(No Subject)")
    date_str = headers_dict.get("date", "Unknown Date")
    snippet = msg_data.get("snippet", "")

    extracted = extract_email_body_and_metadata(msg_data.get("payload", {}))
    body_text = extracted["body"] or snippet

    return {
        "id": msg_data.get("id", ""),
        "sender": sender,
        "subject": subject,
        "date": date_str,
        "snippet": snippet,
        "body": body_text,
        "num_links": extracted["num_links"],
        "has_html": extracted["has_html"]
    }

def fetch_inbox_messages(service, max_results=20):
    try:
        results = service.users().messages().list(
            userId="me", labelIds=["INBOX"], maxResults=max_results
        ).execute()
        messages = results.get("messages", [])
        parsed_emails = []
        for m in messages:
            msg_id = m.get("id")
            try:
                msg_data = service.users().messages().get(
                    userId="me", id=msg_id, format="full"
                ).execute()
                email_item = parse_email_message(msg_data)
                parsed_emails.append(email_item)
            except Exception as item_err:
                print(f"[!] Warning fetching message {msg_id}: {item_err}")
                continue
        return parsed_emails
    except Exception as e:
        raise e

# --------------------------------------------------------------------------
# Flask Routes — Pages
# --------------------------------------------------------------------------

@app.route("/")
def index():
    """Main KAVACHAM AI application page (SPA)."""
    creds = get_google_credentials()
    is_authenticated = creds is not None and creds.valid
    credentials_configured = has_valid_credentials_file()
    return render_template(
        "index.html",
        is_authenticated=is_authenticated,
        credentials_configured=credentials_configured,
        model_ready=(model is not None and vectorizer is not None),
        metrics=metrics_data,
        session=session
    )

@app.route("/authorize")
def authorize():
    """Initiates Google OAuth 2.0 flow."""
    if not has_valid_credentials_file():
        flash("Gmail connection is temporarily unavailable. Please try again later.", "error")
        return redirect(url_for("index"))
    try:
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )
        session["state"] = state
        return redirect(authorization_url)
    except Exception as e:
        flash("Gmail connection could not be started. Please try again later.", "error")
        return redirect(url_for("index"))

@app.route("/oauth2callback")
def oauth2callback():
    """Handles OAuth 2.0 callback from Google."""
    error = request.args.get("error")
    if error:
        flash(f"Google Authorization was denied: {error}", "error")
        return redirect(url_for("index"))

    state = session.get("state")
    if not state or state != request.args.get("state"):
        flash("OAuth security state mismatch. Please try again.", "error")
        return redirect(url_for("index"))

    try:
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        session["credentials"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes
        }
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        session["user_email"] = profile.get("emailAddress", "Connected User")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"OAuth token exchange failed: {str(e)}", "error")
        return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    """Gmail Inbox scanning dashboard."""
    creds = get_google_credentials()
    if not creds or not creds.valid:
        flash("Please connect your Gmail account to access the dashboard.", "warning")
        return redirect(url_for("index"))

    service = get_gmail_service()
    if not service:
        flash("Unable to build Gmail API client. Session might have expired.", "error")
        return redirect(url_for("index"))

    emails_data = []
    fetch_error = None
    stats = {"total": 0, "spam": 0, "ham": 0, "avg_confidence": 0.0}

    try:
        raw_emails = fetch_inbox_messages(service, max_results=20)
        total_conf = 0.0
        for em in raw_emails:
            analyzed_text = f"Subject: {em['subject']}. Content: {em['body']}"
            pred_result = predict_spam(analyzed_text)
            em["prediction"] = pred_result["prediction"]
            em["confidence"] = pred_result["confidence"]
            em["matched_keywords"] = pred_result["matched_keywords"]
            em["influential_signals"] = pred_result.get("influential_signals", [])
            em["analyzed_text_sample"] = (analyzed_text[:300] + "...") if len(analyzed_text) > 300 else analyzed_text

            if em["prediction"] == "Spam":
                stats["spam"] += 1
            else:
                stats["ham"] += 1

            total_conf += em["confidence"]
            emails_data.append(em)

        stats["total"] = len(emails_data)
        if stats["total"] > 0:
            stats["avg_confidence"] = round(total_conf / stats["total"], 2)

    except HttpError as he:
        fetch_error = f"Gmail API error: {he.reason if hasattr(he, 'reason') else str(he)}"
    except Exception as e:
        fetch_error = f"Failed to fetch emails: {str(e)}"

    gmail_dash_data = {
        "stats": stats,
        "emails": emails_data
    }

    return render_template(
        "dashboard.html",
        user_email=session.get("user_email", "Connected User"),
        emails=emails_data,
        stats=stats,
        error=fetch_error,
        metrics=metrics_data,
        gmail_dash_data=gmail_dash_data
    )

@app.route("/logout")
def logout():
    """Clears user session and logs out."""
    session.clear()
    flash("Successfully disconnected Gmail account.", "info")
    return redirect(url_for("index"))

# --------------------------------------------------------------------------
# Flask Routes — API Endpoints
# --------------------------------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():
    """
    Manual Message Classification (Kavacham AI mode).
    Expects JSON: { "message": "Text..." }
    """
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "Request must be JSON"}), 400

        data = request.get_json(silent=True)
        if not data or "message" not in data:
            return jsonify({"success": False, "error": "Missing 'message' field"}), 400

        raw_message = data.get("message", "")
        if not isinstance(raw_message, str) or not raw_message.strip():
            return jsonify({"success": False, "error": "Message cannot be empty"}), 400

        res = predict_spam(raw_message)

        if res["prediction"] == "Spam":
            explanation = "This message exceeds the Spam decision threshold with patterns commonly found in phishing or promotional schemes."
        else:
            explanation = "This message satisfies legitimate communication characteristics and falls below the threat decision threshold."

        # Add to session history
        add_to_session_history({
            "id": str(uuid.uuid4()),
            "sender": data.get("sender", "—"),
            "subject": data.get("subject", "(No Subject)"),
            "classification": res["prediction"],
            "confidence": res["confidence"],
            "analysis_mode": "anveshak",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return jsonify({
            "success": True,
            "prediction": res["prediction"],
            "confidence": res["confidence"],
            "decision_threshold": res["decision_threshold"],
            "probability_spam": res["probability_spam"],
            "probability_ham": res["probability_ham"],
            "explanation": explanation,
            "matched_keywords": res["matched_keywords"],
            "influential_signals": res["influential_signals"]
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/analyze-email-simple", methods=["POST"])
def analyze_email_simple():
    """
    Kavacham AI analysis from structured email fields.
    Expects JSON: { subject, sender, body, urls (optional) }
    Returns structured result for the Analyze Email page.
    """
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "Request must be JSON"}), 400

        data = request.get_json(silent=True) or {}
        subject = data.get("subject", "").strip()
        sender = data.get("sender", "").strip()
        body = data.get("body", "").strip()
        urls = data.get("urls", "").strip()

        if not body and not subject:
            return jsonify({"success": False, "error": "Please provide at least a subject or body."}), 400

        # Build combined text for ML model
        parts = []
        if subject:
            parts.append(f"Subject: {subject}")
        if sender:
            parts.append(f"From: {sender}")
        if body:
            parts.append(body)
        if urls:
            parts.append(f"URLs: {urls}")
        combined_text = ". ".join(parts)

        res = predict_spam(combined_text)

        # Store in session history
        add_to_session_history({
            "id": str(uuid.uuid4()),
            "sender": sender or "—",
            "subject": subject or "(No Subject)",
            "classification": res["prediction"],
            "confidence": res["confidence"],
            "analysis_mode": "anveshak",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return jsonify({
            "success": True,
            "analysis_mode": "anveshak",
            "prediction": res["prediction"],
            "confidence": res["confidence"],
            "probability_spam": res["probability_spam"],
            "probability_ham": res["probability_ham"],
            "decision_threshold": res["decision_threshold"],
            "influential_signals": res["influential_signals"],
            "matched_keywords": res["matched_keywords"]
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ultra-analyze", methods=["POST"])
def ultra_analyze():
    """
    Ultra AI analysis — runs BOTH Kavacham AI (local ML) + Kavacham AI Pro (contextual AI).
    Expects JSON: { subject, sender, body, urls (optional) }
    SECURITY: Kavacham AI Pro API key is NEVER sent to frontend — only used server-side.
    """
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "Request must be JSON"}), 400

        data = request.get_json(silent=True) or {}
        subject = data.get("subject", "").strip()
        sender = data.get("sender", "").strip()
        body = data.get("body", "").strip()
        urls = data.get("urls", "").strip()

        if not body and not subject:
            return jsonify({"success": False, "error": "Please provide at least a subject or body."}), 400

        # 1. Kavacham AI — local ML model
        parts = []
        if subject:
            parts.append(f"Subject: {subject}")
        if sender:
            parts.append(f"From: {sender}")
        if body:
            parts.append(body)
        if urls:
            parts.append(f"URLs: {urls}")
        combined_text = ". ".join(parts)

        anveshak_result = predict_spam(combined_text)

        # 2. Kavacham AI Pro — contextual AI (gracefully degrades if unavailable)
        try:
            gemini_result = analyze_with_gemini(
                subject=subject,
                sender=sender,
                body=body,
                urls=urls
            )
        except Exception as gem_err:
            gemini_result = {"success": False, "error": str(gem_err)}

        # 3. Build comparison
        models_agree = False
        combined_assessment = ""

        if gemini_result.get("success"):
            anveshak_class = anveshak_result["prediction"]  # "Spam" or "Not Spam"
            gemini_class = gemini_result.get("classification", "Unknown")  # "Spam" or "Not Spam"

            anveshak_is_spam = (anveshak_class == "Spam")
            gemini_is_spam = (gemini_class == "Spam")
            models_agree = (anveshak_is_spam == gemini_is_spam)

            if models_agree:
                label = "Spam" if anveshak_is_spam else "Not Spam"
                combined_assessment = f"Both analysis engines classified this email as {label}. This agreement increases confidence in the result."
            else:
                combined_assessment = (
                    f"Analysis engines disagree. "
                    f"Kavacham AI says {anveshak_class} (local ML, threshold-based). "
                    f"Kavacham AI Pro says {gemini_class} (contextual semantic intelligence). "
                    f"Final verdict gives priority to Kavacham AI Pro."
                )
        else:
            models_agree = False
            combined_assessment = (
                f"Kavacham AI classified this email as {anveshak_result['prediction']}. "
                f"Kavacham AI Pro analysis was unavailable: {gemini_result.get('error', 'Service temporarily busy')}. "
                f"The Kavacham AI result is still valid and independent."
            )

        # Final verdict — Pro engine (Kavacham AI Pro) takes priority when available.
        if gemini_result.get("success"):
            final_verdict = gemini_result.get("classification", anveshak_result["prediction"])
            final_source = "Kavacham AI Pro"
            final_confidence = gemini_result.get("confidence", anveshak_result["confidence"])
            final_priority = "pro-first"
        else:
            final_verdict = anveshak_result["prediction"]
            final_source = "Kavacham AI"
            final_confidence = anveshak_result["confidence"]
            final_priority = "ml-only"

        # Store in session history
        add_to_session_history({
            "id": str(uuid.uuid4()),
            "sender": sender or "—",
            "subject": subject or "(No Subject)",
            "classification": anveshak_result["prediction"],
            "confidence": anveshak_result["confidence"],
            "analysis_mode": "ultra",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return jsonify({
            "success": True,
            "analysis_mode": "ultra",
            "anveshak": {
                "prediction": anveshak_result["prediction"],
                "confidence": anveshak_result["confidence"],
                "probability_spam": anveshak_result["probability_spam"],
                "probability_ham": anveshak_result["probability_ham"],
                "decision_threshold": anveshak_result["decision_threshold"],
                "influential_signals": anveshak_result["influential_signals"],
                "matched_keywords": anveshak_result["matched_keywords"]
            },
            "gemini": gemini_result,
            "models_agree": models_agree,
            "combined_assessment": combined_assessment,
            "final_verdict": final_verdict,
            "final_source": final_source,
            "final_confidence": final_confidence,
            "final_priority": final_priority
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ======================================================================
# THREAT DISCOVERY — Phishing Checker API
# ======================================================================

@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    """
    Unified Email Threat Analysis Engine (Task 2).

    Accepts:   { "message_id": "gmail_message_id", "ultra_ai": bool }
    Behavior:  validates the ID, confirms the Gmail connection, fetches the
               REAL message server-side, normalizes it once, runs every
               detection engine + risk engine + optional Gemini explanation,
               and returns the structured Security Report (spec §19).

    SECURITY:  never accepts arbitrary frontend content as a Gmail
               substitute; logs no tokens, keys, or full email bodies.
    """
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "Request must be JSON"}), 400

        data = request.get_json(silent=True) or {}
        message_id = (data.get("message_id") or "").strip()
        ultra_ai = bool(data.get("ultra_ai", False))

        if not message_id:
            return jsonify({"success": False, "error": "Missing 'message_id'."}), 400
        if not re.fullmatch(r"[A-Za-z0-9\-_]{1,128}", message_id):
            return jsonify({"success": False, "error": "Invalid message_id format."}), 400

        # 1. Confirm Gmail connection
        service = get_gmail_service()
        if not service:
            return jsonify({
                "success": False,
                "error": "Gmail connection required. Please connect your Gmail account."
            }), 401

        # 2. Fetch the real message (never frontend-supplied content)
        try:
            msg_data = service.users().messages().get(
                userId="me", id=message_id, format="full"
            ).execute()
        except HttpError as he:
            code = he.resp.status if hasattr(he, "resp") else None
            if code == 404:
                return jsonify({"success": False,
                                "error": "Message not found or inaccessible."}), 404
            return jsonify({"success": False,
                            "error": "Gmail could not retrieve this message. "
                                     "It may have been moved or deleted."}), 200
        except Exception as e:
            return jsonify({"success": False,
                            "error": "Gmail could not retrieve this message. "
                                     "Please try again."}), 200

        # 3. Normalize once, run unified pipeline (predict_spam injected)
        normalized = normalize_gmail_message(msg_data)
        report = unified_analyze_email(normalized, predict_spam_fn=predict_spam,
                                       ultra_ai=ultra_ai)

        # 4. Store a NON-SENSITIVE history entry (never the body)
        add_to_session_history({
            "id": str(uuid.uuid4()),
            "sender": report["message"]["sender"][:80],
            "subject": report["message"]["subject"][:80],
            "classification": report["classification"]["label"],
            "confidence": report["classification"]["confidence"],
            "analysis_mode": "unified-engine",
            "security_verdict": report["security"]["verdict"],
            "risk_score": report["security"]["risk_score"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return jsonify(report), 200

    except Exception as e:
        # Never leak raw backend errors to the user.
        return jsonify({
            "success": False,
            "error": "Analysis failed. Please try again."
        }), 200


@app.route("/api/virustotal-status", methods=["GET"])
def api_virustotal_status():
    """Backend-only VirusTotal configuration status (never the key)."""
    try:
        status = vt_availability_status()
        return jsonify({
            "configured": status.get("configured", False),
            "service": status.get("service", "VirusTotal"),
        }), 200
    except Exception as e:
        return jsonify({"configured": False, "service": "VirusTotal"}), 200


@app.route("/api/phishing-check", methods=["POST"])
def api_phishing_check():
    """
    Phishing Checker — local-ML-first email analysis.

    Accepts:  { "sender": str, "subject": str, "body": str,
                "urls": str, "ultra_ai": bool }

    The Kavacham AI ML model is ALWAYS the primary classifier. The unified
    deterministic analyzer stack (URL / sender / header / scam / BEC / risk
    engine) provides the phishing assessment, risk score and threat
    indicators. Gemini ("Kavacham AI Pro") is OPTIONAL and is only used for a
    plain-language explanation — it can never override the primary result.

    Non-sensitive history entry only; bodies/senders are truncated and never
    returned unmodified. Never leaks raw backend errors.
    """
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "Request must be JSON"}), 400

        data = request.get_json(silent=True) or {}
        sender = str(data.get("sender") or "").strip()
        subject = str(data.get("subject") or "").strip()
        body = str(data.get("body") or "").strip()
        urls = str(data.get("urls") or "").strip()
        ultra_ai = bool(data.get("ultra_ai", False))

        if not subject and not body:
            return jsonify({
                "success": False,
                "error": "Please enter at least an email subject or message content."
            }), 400

        if model is None or vectorizer is None:
            return jsonify({
                "success": False,
                "error": "Kavacham AI model is not loaded. Retraining or restart may be required."
            }), 503

        # Never trust anything but user-typed fields — build locally.
        normalized = build_normalized_email(
            sender=sender, subject=subject, body=body, urls=urls
        )
        report = unified_analyze_email(normalized, predict_spam_fn=predict_spam,
                                       ultra_ai=ultra_ai)

        # Non-sensitive history entry (truncated, never the full body)
        add_to_session_history({
            "id": str(uuid.uuid4()),
            "sender": (sender or "—")[:80],
            "subject": (subject or "(No Subject)")[:80],
            "classification": report["classification"]["label"],
            "confidence": report["classification"]["confidence"],
            "analysis_mode": "phishing-check",
            "security_verdict": report["security"]["verdict"],
            "risk_score": report["security"]["risk_score"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return jsonify(report), 200

    except Exception as e:
        # Never leak raw backend errors to the user.
        return jsonify({
            "success": False,
            "error": "Analysis failed. Please try again."
        }), 200


@app.route("/api/threat/url", methods=["POST"])
def api_threat_url():
    """Analyze a URL / domain for phishing indicators via the threat API."""
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        result = threat_analyze_url(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 200


@app.route("/api/threat/message", methods=["POST"])
def api_threat_message():
    """Analyze an email / SMS / chat message for phishing indicators."""
    try:
        data = request.get_json(silent=True) or {}
        message = (data.get("message") or "").strip()
        result = threat_analyze_message(message)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 200


@app.route("/api/threat/file", methods=["POST"])
def api_threat_file():
    """Analyze an uploaded file for threat indicators (metadata + hash + content)."""
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file uploaded."}), 200
        file = request.files["file"]
        result = threat_analyze_file(file, filename=file.filename or "")
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 200


@app.route("/api/threat/status", methods=["GET"])
def api_threat_status():
    """Returns connectivity of the threat-analysis API (Kavacham AI Pro)."""
    try:
        status = get_gemini_status()
        status.pop("api_key", None)
        return jsonify({"configured": status.get("configured", False),
                        "reachable": status.get("reachable", False),
                        "message": status.get("message", "")}), 200
    except Exception as e:
        return jsonify({"configured": False, "reachable": False, "message": str(e)}), 200


@app.route("/gemini-status", methods=["GET"])
def gemini_status():
    """Returns Gemini API connectivity status. Never exposes the API key."""
    try:
        status = get_gemini_status()
        # Explicitly strip API key from response if somehow present
        status.pop("api_key", None)
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"configured": False, "reachable": False, "message": str(e)}), 200


@app.route("/model-info", methods=["GET"])
@app.route("/api/metrics", methods=["GET"])
def model_info():
    """Returns actual trained model architecture and evaluation metrics."""
    return jsonify({"status": "success", "model": metrics_data})


@app.route("/api/gmail-status", methods=["GET"])
def gmail_status():
    """Returns Gmail connection status."""
    creds = get_google_credentials()
    is_connected = creds is not None and creds.valid
    return jsonify({
        "connected": is_connected,
        "user_email": session.get("user_email") if is_connected else None,
        "credentials_configured": has_valid_credentials_file()
    })


@app.route("/api/history", methods=["GET"])
def get_history():
    """Returns analysis history from session."""
    history = get_session_history()
    return jsonify({"history": history})


@app.route("/api/history", methods=["POST"])
def add_history():
    """Adds an entry to session analysis history (called from frontend)."""
    try:
        data = request.get_json(silent=True) or {}
        entry = data.get("entry", {})
        if entry:
            add_to_session_history(entry)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """Clears analysis history from session."""
    session["analysis_history"] = []
    session.modified = True
    return jsonify({"success": True})


@app.route("/health", methods=["GET"])
def health():
    """Health check for model status, credentials, and threshold."""
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None,
        "credentials_configured": has_valid_credentials_file(),
        "decision_threshold": SPAM_DECISION_THRESHOLD
    })


if __name__ == "__main__":
    import threading
    def _shutdown():
        func = request.environ.get('werkzeug.server.shutdown')
        if func: func()
    app.add_url_rule('/_shutdown', '_shutdown', _shutdown, methods=['GET'])
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    print("\n==================================================================")
    print("[*] KAVACHAM AI - Threat Intelligence Engine running at http://127.0.0.1:5000")
    print(f"[*] Configured Spam Decision Threshold: {SPAM_DECISION_THRESHOLD * 100:.0f}%")
    print("[*] Ultra AI: Gemini model loaded from server-side .env")
    print("==================================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
