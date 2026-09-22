"""
threat_service.py
=================
Threat Discovery backend for the Phishing Checker workspace.

Uses the project's configured threat-analysis API (Kavacham AI Pro, powered
by the existing gemini_service fallback chain). There is NO VirusTotal
integration and no fabricated threat intelligence: every score, risk level
and indicator comes from the actual API response.

SECURITY: The API key is read exclusively from the .env file server-side
and is NEVER exposed to the browser/frontend code.

Graceful degradation: if the threat-analysis API is unavailable, every
function returns {"success": False, "error": ...} so the UI can display
"Analysis unavailable" instead of an invented result.
"""

import os
import json
import time
import hashlib
import urllib.request
import urllib.error

from gemini_service import _execute_gemini_call, CANDIDATE_MODELS, GEMINI_API_KEY

# ---------------------------------------------------------------------------
# Threat-analysis prompt: instructs the model to return strict JSON only.
# ---------------------------------------------------------------------------

THREAT_SYSTEM_PROMPT = """You are Kavacham AI Pro — an advanced cybersecurity threat-analysis engine.

Analyze the provided input for PHISHING, credential-theft, malware, and social-engineering indicators.

CRITICAL ANALYSIS RULES:
1. Do NOT label something a threat merely because it is promotional, urgent, or contains words like "free", "offer", "winner", "verify".
2. EVALUATE genuine phishing signals: credential harvesting pages, deceptive urgency demanding passwords/OTPs, spoofed/impersonated domains, misspelled brand domains (e.g. paypa1.com), suspicious redirect chains, executable attachments, encoded payloads, requests for money/one-time passwords.
3. EVALUATE legitimate signals: official-looking institutional domains that really resolve to the claimed brand, standard transactional language, no credential requests, no deceptive urgency.
4. Score objectively from 0 (completely safe) to 100 (critical threat).
5. respond ONLY with valid JSON, no markdown, no explanation outside JSON.

Return EXACTLY this JSON shape:
{
  "threat_level": "SAFE" or "LOW RISK" or "SUSPICIOUS" or "HIGH RISK" or "CRITICAL",
  "threat_score": integer 0-100,
  "classification": "short label e.g. PHISHING DETECTED or SUSPICIOUS or SAFE",
  "is_phishing": true or false,
  "indicators": ["short string indicators found, empty list if none"],
  "url_reputation": "short assessment of the URL/domain reputation",
  "domain_risk": "LOW" or "MEDIUM" or "HIGH",
  "phishing_probability": integer 0-100,
  "content_risk": "short assessment of the content",
  "summary": "one concise paragraph explaining the verdict"
}
"""

EXPECTED_KEYS = [
    "threat_level", "threat_score", "classification", "is_phishing",
    "indicators", "url_reputation", "domain_risk", "phishing_probability",
    "content_risk", "summary"
]


def _call_threat_api(content_text: str, timeout: int = 20) -> dict:
    """
    Sends content to the model via the fallback chain and parses JSON.
    Returns a normalized dict with success flag.
    """
    if not GEMINI_API_KEY:
        return {
            "success": False,
            "error": "Threat-analysis API key not configured. Add GEMINI_API_KEY to the .env file."
        }

    user_prompt = THREAT_SYSTEM_PROMPT + "\n\nINPUT TO ANALYZE:\n" + content_text

    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 1200
        }
    }

    last_error = ""

    for model_name in CANDIDATE_MODELS:
        for attempt in range(2):
            try:
                response_data = _execute_gemini_call(model_name, payload, timeout=timeout)
                candidates = response_data.get("candidates", [])
                if not candidates:
                    last_error = f"{model_name}: No candidates returned"
                    continue
                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if not text_content:
                    last_error = f"{model_name}: Empty content parts"
                    continue

                parsed = json.loads(text_content)
                return {
                    "success": True,
                    "threat_level": str(parsed.get("threat_level", "SUSPICIOUS")).upper(),
                    "threat_score": int(parsed.get("threat_score", 50)),
                    "classification": str(parsed.get("classification", "SUSPICIOUS")),
                    "is_phishing": bool(parsed.get("is_phishing", False)),
                    "indicators": [str(i) for i in (parsed.get("indicators") or [])][:12],
                    "url_reputation": str(parsed.get("url_reputation", "")),
                    "domain_risk": str(parsed.get("domain_risk", "MEDIUM")).upper(),
                    "phishing_probability": int(parsed.get("phishing_probability", 50)),
                    "content_risk": str(parsed.get("content_risk", "")),
                    "summary": str(parsed.get("summary", "")),
                    "model_used": model_name
                }

            except urllib.error.HTTPError as e:
                last_error = f"{model_name} HTTP {e.code}: {e.reason}"
                if e.code in (429, 503):
                    time.sleep(1.0)
                else:
                    break

            except (urllib.error.URLError, TimeoutError, OSError) as e:
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
        "error": "Threat-analysis API unavailable. " + (f"({last_error})" if last_error else "Service temporarily unavailable.")
    }


# ---------------------------------------------------------------------------
# Public analyzers
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """Analyzes a URL / domain for phishing indicators."""
    if not url or not url.strip():
        return {"success": False, "error": "Please provide a URL to analyze."}
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    content = f"URL TO ANALYZE:\n{url}\n"
    result = _call_threat_api(content)
    result["target"] = url
    return result


def analyze_message(message: str) -> dict:
    """Analyzes an email / SMS / chat message for phishing & social engineering."""
    if not message or not message.strip():
        return {"success": False, "error": "Please provide a message to analyze."}
    snippet = message.strip()
    if len(snippet) > 4000:
        snippet = snippet[:4000] + "\n[TRUNCATED]"
    content = f"MESSAGE TO ANALYZE:\n{snippet}\n"
    result = _call_threat_api(content)
    result["target"] = snippet[:80]
    return result


def analyze_file(file_storage, filename: str = "") -> dict:
    """
    Analyzes an uploaded file: computes SHA-256 hash, detects type/size,
    extracts a bounded text sample (if text-like) and runs threat analysis.
    """
    filename = filename or (file_storage.filename if file_storage else "")
    if not file_storage or not filename:
        return {"success": False, "error": "Please choose a file to analyze."}

    raw = file_storage.read()
    size = len(raw)
    if size == 0:
        return {"success": False, "error": "The selected file is empty."}

    sha256 = hashlib.sha256(raw).hexdigest()

    ext = os.path.splitext(filename)[1].lower()
    mime = getattr(file_storage, "mimetype", "") or "application/octet-stream"

    # Binary vs text detection: try decoding a sample.
    text_sample = ""
    is_binary = False
    sample_bytes = raw[:8192]
    try:
        text_sample = sample_bytes.decode("utf-8")
        # If most bytes are printable, treat as text
        printable = sum(1 for b in sample_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        if len(sample_bytes) > 0 and printable / len(sample_bytes) < 0.7:
            is_binary = True
            text_sample = ""
    except UnicodeDecodeError:
        is_binary = True
        text_sample = ""

    # Include a bounded content sample if it looks like text source
    if text_sample and len(raw) > 8192:
        try:
            text_sample = raw[:20000].decode("utf-8", errors="ignore")
        except Exception:
            pass

    content_parts = [
        f"FILE NAME: {filename}",
        f"FILE TYPE: {mime or 'Unknown'}",
        f"FILE SIZE: {size} bytes",
        f"SHA-256: {sha256}",
        f"BINARY: {'yes' if is_binary else 'no'}",
    ]
    if text_sample:
        content_parts.append(f"TEXT SAMPLE:\n{text_sample[:4000]}")
    else:
        content_parts.append("NO TEXT CONTENT EXTRACTED (binary or encrypted). Analyze based on file metadata, name, and hash.")

    result = _call_threat_api("\n".join(content_parts))
    result["target"] = filename
    result["file_meta"] = {
        "name": filename,
        "type": mime or "Unknown",
        "size": size,
        "sha256": sha256,
        "extension": ext,
        "binary": is_binary
    }
    return result