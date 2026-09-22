"""
gemini_service.py
=================
Backend-only Gemini AI integration for ANVESHAK AI Ultra analysis mode.

SECURITY: This module reads the API key exclusively from the .env file
via environment variables. The API key is NEVER exposed to frontend
HTML, JavaScript, or any client-side code.

Uses model: models/gemini-3-flash-preview (confirmed working)
"""

import os
import json
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "models/gemini-3-flash-preview"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

SYSTEM_PROMPT = """You are Anveshak AI Ultra — an advanced email security and threat analysis assistant.

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


def analyze_with_gemini(subject: str, sender: str, body: str, urls: str = "") -> dict:
    """
    Sends email content to Gemini for contextual threat analysis.

    Args:
        subject: Email subject line
        sender: Sender email address/name
        body: Email body text
        urls: Optional URL list from the email

    Returns:
        dict with keys: success, classification, confidence, risk_level,
                        reasoning_summary, suspicious_signals, legitimate_signals,
                        gemini_note, error (if any)
    """
    if not GEMINI_API_KEY:
        return {
            "success": False,
            "error": "Gemini API key not configured. Add GEMINI_API_KEY to .env file."
        }

    # Build the email context for analysis
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

    url = f"{GEMINI_BASE_URL}/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            response_data = json.loads(raw)

        # Extract the text content from Gemini's response
        candidates = response_data.get("candidates", [])
        if not candidates:
            return {"success": False, "error": "Gemini returned no candidates."}

        text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        if not text_content:
            return {"success": False, "error": "Gemini returned empty content."}

        # Parse the JSON result
        gemini_result = json.loads(text_content)

        return {
            "success": True,
            "classification": gemini_result.get("classification", "Unknown"),
            "confidence": int(gemini_result.get("confidence", 50)),
            "risk_level": gemini_result.get("risk_level", "Medium"),
            "reasoning_summary": gemini_result.get("reasoning_summary", "No reasoning provided."),
            "suspicious_signals": gemini_result.get("suspicious_signals", []),
            "legitimate_signals": gemini_result.get("legitimate_signals", []),
            "gemini_note": gemini_result.get("gemini_note", ""),
            "model_used": GEMINI_MODEL
        }

    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")[:300]
        except Exception:
            pass
        return {
            "success": False,
            "error": f"Gemini API HTTP {e.code}: {error_body or str(e)}"
        }
    except urllib.error.URLError as e:
        return {
            "success": False,
            "error": f"Gemini API network error: {str(e)}"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Failed to parse Gemini JSON response: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error during Gemini analysis: {str(e)}"
        }


def get_gemini_status() -> dict:
    """
    Checks if Gemini API is reachable and key is valid.
    Returns status dict for Settings page.
    """
    if not GEMINI_API_KEY:
        return {"configured": False, "reachable": False, "model": GEMINI_MODEL, "message": "API key not set"}

    try:
        test_payload = {
            "contents": [{"parts": [{"text": "Reply with only valid JSON: {\"status\": \"ok\"}"}]}],
            "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": 20}
        }
        url = f"{GEMINI_BASE_URL}/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
        req = urllib.request.Request(
            url,
            data=json.dumps(test_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return {"configured": True, "reachable": True, "model": GEMINI_MODEL, "message": "Gemini API is active"}
    except Exception as e:
        return {"configured": True, "reachable": False, "model": GEMINI_MODEL, "message": str(e)}
