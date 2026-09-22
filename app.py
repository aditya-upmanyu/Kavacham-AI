"""
app.py
======
Production-style, demo-ready Gmail Spam Detection & Threat Intelligence ML Web Application (ANVESHAK AI).

Features:
- Official Google OAuth 2.0 flow with Gmail Read-only scope (gmail.readonly)
- Recursive MIME multipart & base64url email decoding with link and structural inspection
- Context-aware preprocessing with clause-level negation preservation
- FeatureUnion (Word TF-IDF unigrams/bigrams/trigrams + Char TF-IDF 3-5 ngrams)
- Multinomial Naive Bayes model with optimized decision threshold (>= 0.85 for Spam)
- Explainable AI: Influential Signals categorizing tokens into Spam signals vs Contextual/Neutral signals
- Model specifications and evaluation metrics route (/model-info)
- Manual message classification endpoint (/predict)
"""

import os
import re
import string
import base64
import json
import pickle
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash
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

# Load environment configurations
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "dev-secret-key-spam-detector-2026-secure-session"

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
            with open(MODEL_FILE, "rb") as fm:
                model = pickle.load(fm)
            with open(VECTORIZER_FILE, "rb") as fv:
                vectorizer = pickle.load(fv)
            print("[+] ML Model & Vectorizer loaded successfully.")
        except Exception as e:
            print(f"[!] Error loading ML artifacts: {e}")
    else:
        print("[*] Generating ML artifacts via train_model.py...")
        try:
            from train_model import train_and_evaluate
            train_and_evaluate()
            with open(MODEL_FILE, "rb") as fm:
                model = pickle.load(fm)
            with open(VECTORIZER_FILE, "rb") as fv:
                vectorizer = pickle.load(fv)
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
    Computes explainable token contributions:
    Categorizes features into 'Spam signal' vs 'Neutral / Contextual'
    based on the Naive Bayes log-ratio of conditional probabilities.
    """
    signals = []
    try:
        feature_names = vectorizer.get_feature_names_out()
        non_zero_indices = features.nonzero()[1]
        
        # log P(feature | Spam) - log P(feature | Ham)
        log_prob_diff = model.feature_log_prob_[1] - model.feature_log_prob_[0]
        
        # Filter down to meaningful word features (skipping raw character ngrams for display)
        candidate_tokens = []
        for idx in non_zero_indices:
            name = feature_names[idx]
            # If from FeatureUnion, clean prefix
            clean_name = name.replace("word_tfidf__", "").replace("char_tfidf__", "")
            if name.startswith("char_tfidf__"):
                continue  # display clean word-level explanations
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
    except Exception as e:
        signals = []
        
    return signals

def predict_spam(raw_text: str):
    """
    Executes context-aware ML inference on raw text.
    Returns:
    {
        'prediction': 'Spam' | 'Not Spam',
        'confidence': float,
        'probability_spam': float,
        'probability_ham': float,
        'decision_threshold': float,
        'influential_signals': list,
        'matched_keywords': list
    }
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

    # Calibrate display confidence to never show misleading 100.0% certainty
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

        # Refresh token if expired
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
    """Safely decodes Gmail base64url encoded strings."""
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
    """
    Recursively navigates MIME payload tree.
    Extracts plain text, HTML text, link count, and attachment indicators.
    """
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
                # Count URLs in plain text
                total_links += len(re.findall(r"https?://\S+|www\.\S+", decoded))
                
        elif mime_type == "text/html" and body_data:
            has_html = True
            decoded = decode_base64url(body_data)
            if decoded.strip():
                try:
                    soup = BeautifulSoup(decoded, "html.parser")
                    # Count anchors in HTML
                    total_links += len(soup.find_all("a"))
                    for element in soup(["script", "style", "meta", "noscript"]):
                        element.extract()
                    cleaned_html = soup.get_text(separator=" ", strip=True)
                    if cleaned_html:
                        html_text_parts.append(cleaned_html)
                except Exception:
                    html_text_parts.append(decoded)

        # Recursively inspect multipart subparts
        for subpart in part.get("parts", []):
            walk_parts(subpart)

    walk_parts(payload)

    final_body = " ".join(plain_text_parts).strip() if plain_text_parts else " ".join(html_text_parts).strip()
    return {
        "body": final_body,
        "num_links": total_links,
        "has_html": has_html
    }

def parse_email_message(msg_data: dict) -> dict:
    """Extracts headers, snippet, body text, and structural features from Gmail message."""
    headers = msg_data.get("payload", {}).get("headers", [])
    headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers}

    sender = headers_dict.get("from", "Unknown Sender")
    subject = headers_dict.get("subject", "(No Subject)")
    date_str = headers_dict.get("date", "Unknown Date")
    snippet = msg_data.get("snippet", "")

    # Extract deep body text & structural details
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
    """Fetches recent messages from Gmail INBOX using users.messages.list & get."""
    try:
        results = service.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=max_results
        ).execute()

        messages = results.get("messages", [])
        parsed_emails = []

        for m in messages:
            msg_id = m.get("id")
            try:
                msg_data = service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="full"
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
# Flask Routes
# --------------------------------------------------------------------------

@app.route("/")
def index():
    """Landing / Login page explaining read-only permission & AI model."""
    creds = get_google_credentials()
    is_authenticated = creds is not None and creds.valid
    credentials_configured = has_valid_credentials_file()

    return render_template(
        "login.html",
        is_authenticated=is_authenticated,
        credentials_configured=credentials_configured,
        metrics=metrics_data
    )

@app.route("/authorize")
def authorize():
    """Initiates Google OAuth 2.0 flow."""
    if not has_valid_credentials_file():
        flash("Google OAuth credentials.json is missing or not configured. Follow setup instructions in README.", "error")
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
        flash(f"Failed to initiate OAuth flow: {str(e)}", "error")
        return redirect(url_for("index"))

@app.route("/oauth2callback")
def oauth2callback():
    """Handles OAuth 2.0 callback from Google."""
    error = request.args.get("error")
    if error:
        flash(f"Google Authorization was denied or encountered an error: {error}", "error")
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
    """
    Authenticated Gmail Inbox scanning dashboard.
    Fetches real inbox emails, combines subject + body + structural details,
    runs ML classification, and renders results.
    """
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
    stats = {
        "total": 0,
        "spam": 0,
        "ham": 0,
        "avg_confidence": 0.0
    }

    try:
        raw_emails = fetch_inbox_messages(service, max_results=20)
        total_conf = 0.0

        for em in raw_emails:
            # Combine subject + body appropriately
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

    return render_template(
        "dashboard.html",
        user_email=session.get("user_email", "Connected User"),
        emails=emails_data,
        stats=stats,
        error=fetch_error,
        metrics=metrics_data
    )

@app.route("/logout")
def logout():
    """Clears user session and logs out."""
    session.clear()
    flash("Successfully disconnected Gmail account.", "info")
    return redirect(url_for("index"))

@app.route("/predict", methods=["POST"])
def predict():
    """
    Manual Message Classification Endpoint.
    Expects JSON: { "message": "Text..." }
    Returns JSON:
    {
      "success": true,
      "prediction": "Spam" | "Not Spam",
      "confidence": float,
      "decision_threshold": float,
      "explanation": str,
      "matched_keywords": list,
      "influential_signals": list
    }
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

        return jsonify({
            "success": True,
            "prediction": res["prediction"],
            "confidence": res["confidence"],
            "decision_threshold": res["decision_threshold"],
            "explanation": explanation,
            "matched_keywords": res["matched_keywords"],
            "influential_signals": res["influential_signals"]
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/model-info", methods=["GET"])
def model_info():
    """Returns actual trained model architecture and evaluation metrics."""
    return jsonify({
        "status": "success",
        "model": metrics_data
    })

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
    print("\n==================================================================")
    print("[*] ANVESHAK AI - Threat Intelligence Engine running at http://127.0.0.1:5000")
    print(f"[*] Configured Spam Decision Threshold: {SPAM_DECISION_THRESHOLD * 100:.0f}%")
    print("==================================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
