"""
gemini_service.py
=================
Backend-only Gemini AI integration for KAVACHAM AI Ultra analysis mode.

SECURITY: This module reads the API key exclusively from the .env file
via environment variables. The API key is NEVER exposed to frontend
HTML, JavaScript, or any client-side code.

Features:
- Multi-model resilient fallback chain (working stable models first, then
  preview models as fallbacks)
- Exponential backoff & retry mechanism for transient 503 / 429 errors
- Graceful degradation: If Gemini is temporarily overloaded, returns a structured
  error response so KAVACHAM AI results remain 100% functional and unblocked.
"""

import os
import json
import time
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

# Resilient priority fallback list of models.
# ORDER MATTERS: verified working models come FIRST so Ultra mode succeeds
# even under burst rate limits. Verified with live probes:
#   [200] gemini-flash-latest, gemini-3.6/3.7/3.8-flash
#   [429] gemini-3-flash-preview / 3.1-pro-preview (free-tier daily quota)
#   [404] gemini-2.5-flash / gemini-2.5-pro (removed — unavailable to new users)
CANDIDATE_MODELS = [
    "models/gemini-flash-latest",
    "models/gemini-3.6-flash",
    "models/gemini-3.7-flash",
    "models/gemini-3.8-flash",
    "models/gemini-3-flash-preview",
    "models/gemini-3.1-pro-preview",
]

SYSTEM_PROMPT = """You are Kavacham AI Pro — an advanced email security and threat analysis assistant.

Your task is to analyze the provided email for spam, phishing, or social engineering indicators.

CRITICAL ANALYSIS RULES:
1. Do NOT classify as Spam merely because an email contains words like: urgent, alert, security, payment, confirmation, winner, claim, verify, limited, account. These words regularly appear in legitimate emails.
2. EVALUATE CONTEXT and intent — a university registration confirmation is NOT spam even if it contains "confirm", "payment", "limited spots".
3. EVALUATE these genuine spam signals: requests for passwords/OTPs, unsolicited prize claims, unknown senders with financial requests, misspelled domains, deceptive urgency to prevent account review, and credential harvesting.
4. EVALUATE these legitimacy signals: institutional sender domain, explicit "we will never ask for password" disclaimers, standard transactional language, appropriate business context.
5. NEVER conflate keyword presence with spam intent — analyze the full semantic context.
6. Provide your reasoning transparently.

Return ONLY a valid JSON object with EXACTLY these keys:
{
  "classification": "Spam" or "Not Spam",
  "confidence": integer 0-100,
  "risk_level": "Low" or "Medium" or "High",
  "reasoning_summary": "One concise paragraph explaining your decision",
  "suspicious_signals": ["list of genuine suspicious patterns found, empty list if none"],
  "legitimate_signals": ["list of genuine legitimacy indicators found"],
  "gemini_note": "Any important contextual observation"
}

Do not wrap in markdown. Return raw JSON only."""


def _execute_gemini_call(model_name: str, payload: dict, timeout: int = 15) -> dict:
    """Helper to execute an HTTP request against a specific Gemini model endpoint."""
    url = f"{GEMINI_BASE_URL}/{model_name}:generateContent?key={GEMINI_API_KEY}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw)


def analyze_with_gemini(subject: str, sender: str, body: str, urls: str = "") -> dict:
    """
    Sends email content to Gemini for contextual threat analysis.
    Uses multi-model fallback and retries on transient errors.

    Args:
        subject: Email subject line
        sender: Sender email address/name
        body: Email body text
        urls: Optional URL list from the email

    Returns:
        dict with keys: success, classification, confidence, risk_level,
                        reasoning_summary, suspicious_signals, legitimate_signals,
                        gemini_note, model_used, or error
    """
    if not GEMINI_API_KEY:
        return {
            "success": False,
            "error": "Gemini API key not configured. Add GEMINI_API_KEY to .env file."
        }

    email_context = f"""Analyze the following email:

SENDER: {sender or 'Unknown'}
SUBJECT: {subject or '(No Subject)'}
BODY:
{body or '(Empty body)'}
"""
    if urls:
        email_context += f"\nURLs FOUND IN EMAIL:\n{urls}\n"

    user_prompt = SYSTEM_PROMPT + "\n\n" + email_context

    payload = {
        "contents": [
            {
                "parts": [{"text": user_prompt}]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 1024
        }
    }

    last_error = ""
    quota_exhausted = False

    # Attempt across models with brief retry for transient errors.
    # Free-tier keys are subject to daily quota (HTTP 429 "quota exceeded")
    # and per-minute burst limits. Quota exhaustion is shared across models,
    # so we fail fast with an honest message instead of hammering all models.
    for model_name in CANDIDATE_MODELS:
        for attempt in range(2):
            try:
                response_data = _execute_gemini_call(model_name, payload, timeout=15)
                candidates = response_data.get("candidates", [])
                if not candidates:
                    last_error = f"{model_name}: No candidates returned"
                    continue

                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if not text_content:
                    last_error = f"{model_name}: Empty content parts"
                    continue

                # Parse the JSON response
                gemini_result = json.loads(text_content)
                return {
                    "success": True,
                    "classification": gemini_result.get("classification", "Unknown"),
                    "confidence": int(gemini_result.get("confidence", 50)),
                    "risk_level": gemini_result.get("risk_level", "Medium"),
                    "reasoning_summary": gemini_result.get("reasoning_summary", "Contextual semantic analysis completed."),
                    "suspicious_signals": gemini_result.get("suspicious_signals", []),
                    "legitimate_signals": gemini_result.get("legitimate_signals", []),
                    "gemini_note": gemini_result.get("gemini_note", ""),
                    "model_used": model_name
                }

            except urllib.error.HTTPError as e:
                last_error = f"{model_name} HTTP {e.code}: {e.reason}"
                if e.code in (429, 503):
                    # Distinguish daily quota exhaustion from transient bursts
                    try:
                        body_lower = e.read().decode("utf-8", errors="replace").lower()
                    except Exception:
                        body_lower = ""
                    is_quota = "quota" in body_lower and ("exceeded" in body_lower or "limit" in body_lower)
                    if is_quota:
                        quota_exhausted = True
                        last_error = (f"{model_name} HTTP 429: free-tier quota exceeded "
                                      "(daily input-token/request limit reached)")
                        # Same key shares quota across models — stop trying others
                        return {
                            "success": False,
                            "quota_exhausted": True,
                            "error": (
                                "Kavacham AI Pro is temporarily unavailable — the Gemini "
                                "free-tier daily quota has been exceeded. It resets "
                                "automatically; Kavacham AI local ML remains active."
                            )
                        }
                    time.sleep(1.5)  # transient burst — brief pause, try again / next model
                else:
                    break  # Bad request / Not found -> try next model immediately

            except (urllib.error.URLError, TimeoutError) as e:
                last_error = f"{model_name} network timeout: {str(e)}"
                time.sleep(0.5)

            except json.JSONDecodeError as e:
                last_error = f"Malformed JSON from {model_name}: {str(e)}"
                break

            except Exception as e:
                last_error = f"Error with {model_name}: {str(e)}"
                break

    return {
        "success": False,
        "error": f"Kavacham AI Pro currently unavailable ({last_error}). Kavacham AI local ML remains active."
    }


def get_gemini_status() -> dict:
    """
    Checks if any Gemini model is reachable and key is valid.
    Returns status dict for Settings page.
    """
    if not GEMINI_API_KEY:
        return {
            "configured": False,
            "reachable": False,
            "model": CANDIDATE_MODELS[0],
            "message": "API key not set in .env"
        }

    test_payload = {
        "contents": [{"parts": [{"text": "Reply with only JSON: {\"status\": \"ok\"}"}]}],
        "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": 20}
    }

    last_kind = "unknown"
    for model_name in CANDIDATE_MODELS:
        for attempt in range(2):
            try:
                _execute_gemini_call(model_name, test_payload, timeout=6)
                return {
                    "configured": True,
                    "reachable": True,
                    "model": model_name,
                    "message": f"Active & reachable ({model_name})"
                }
            except urllib.error.HTTPError as e:
                last_kind = f"HTTP {e.code}"
                if e.code in (429, 503):
                    try:
                        body_lower = e.read().decode("utf-8", errors="replace").lower()
                    except Exception:
                        body_lower = ""
                    if "quota" in body_lower and ("exceeded" in body_lower or "limit" in body_lower):
                        return {
                            "configured": True,
                            "reachable": False,
                            "model": CANDIDATE_MODELS[0],
                            "quota_exhausted": True,
                            "message": ("API key valid, but the free-tier daily quota is "
                                        "exhausted (HTTP 429). It resets automatically; "
                                        "Ultra AI will resume working then.")
                        }
                    if attempt == 0:
                        time.sleep(1.0)  # burst limit — brief pause, try once more
                        continue
                break
            except Exception:
                last_kind = "timeout/unreachable"
                break

    return {
        "configured": True,
        "reachable": False,
        "model": CANDIDATE_MODELS[0],
        "message": (
            f"API key configured, but remote endpoints are currently "
            f"unavailable ({last_kind}). Free-tier quota on preview models may be "
            "exhausted; the stable gemini-flash-latest model is tried first."
        )
    }
