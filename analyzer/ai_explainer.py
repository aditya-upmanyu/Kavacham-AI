"""
analyzer/ai_explainer.py
========================
Optional Ultra AI explanation layer.

Receives the COMPACT structured analysis (verdict, factor scores, top
indicators, top reasons — plus only a sanitized snippet of email content) and
asks Gemini to explain *why* the message was classified, what to verify, and
what the user should do next.

Gemini output NEVER overrides the deterministic findings — it is wrapped in
"explanation" and "verification_steps" only. Any failure (timeout, 429/503,
malformed JSON) returns a graceful `{"success": False}` payload and the normal
security analysis still stands.
"""

import json
import time
import urllib.error

from gemini_service import _execute_gemini_call, CANDIDATE_MODELS, GEMINI_API_KEY

MAX_SNIPPET_CHARS = 600  # privacy: never send the entire mailbox/body

_EXPLAIN_PROMPT = """You are KAVACHAM AI PRO — the Ultra explanation layer of an email security engine.

Below is a STRUCTURED machine-generated analysis of a Gmail message. Do NOT
change the verdict or risk score. Your job is to explain the evidence clearly
to a regular user and tell them what to verify.

Return ONLY a JSON object with EXACTLY these keys:
{
  "explanation": "2-3 sentences explaining why this message received its verdict, based only on the signals below",
  "what_to_verify": ["concrete user-verifiable steps, e.g. check sender domain in Gmail"],
  "recommended_actions": ["safe actions, e.g. do not click the link"],
  "confidence": "Low|Medium|High"
}

STRUCTURED ANALYSIS:
{payload}

Do not wrap in markdown. Return raw JSON only."""


def _truncate_snippet(text: str, limit: int = MAX_SNIPPET_CHARS) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def explain_with_gemini(report: dict, email=None) -> dict:
    """Generate an Ultra AI explanation from the structured security report."""
    if not GEMINI_API_KEY:
        return {"success": False, "error": "Gemini API key not configured."}

    try:
        payload_parts = {
            "sender": report.get("message", {}).get("sender", "Unknown"),
            "subject": report.get("message", {}).get("subject", "Unknown"),
            "classification": (report.get("classification") or {}).get("label", "Unknown"),
            "spam_confidence": (report.get("classification") or {}).get("confidence"),
            "security_verdict": (report.get("security") or {}).get("verdict", "UNKNOWN"),
            "risk_score": (report.get("security") or {}).get("risk_score", 0),
            "risk_factors": report.get("risk_factors", {}),
            "top_reasons": [r.get("reason", "") for r in report.get("top_reasons", [])],
            "threats": report.get("threats", []),
        }
        # Only send a sanitized snippet of body text for context (never the
        # full message). Nothing else sensitive leaves the server.
        if email is not None:
            snippet = _truncate_snippet(getattr(email, "body_text", "") or
                                        getattr(email, "snippet", ""))
            payload_parts["body_snippet"] = snippet

        serialized = json.dumps(payload_parts, ensure_ascii=False, default=str)
        user_prompt = _EXPLAIN_PROMPT.format(payload=serialized)

        generation = {
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2,
                "maxOutputTokens": 1024,
            },
        }

        last_error = ""
        for model_name in CANDIDATE_MODELS:
            for attempt in range(2):
                try:
                    response_data = _execute_gemini_call(model_name, generation, timeout=20)
                    candidates = response_data.get("candidates", [])
                    if not candidates:
                        last_error = f"{model_name}: no candidates"
                        continue
                    text_content = (candidates[0].get("content", {}).get("parts", [{}])
                                    [0].get("text", ""))
                    if not text_content:
                        last_error = f"{model_name}: empty content"
                        continue
                    parsed = json.loads(text_content)
                    return {
                        "success": True,
                        "explanation": parsed.get("explanation", ""),
                        "what_to_verify": parsed.get("what_to_verify", []),
                        "recommended_actions": parsed.get("recommended_actions", []),
                        "ai_confidence": parsed.get("confidence", "Medium"),
                        "model_used": model_name,
                    }
                except urllib.error.HTTPError as e:
                    last_error = f"{model_name}: HTTP {e.code}"
                    if e.code in (429, 503):
                        try:
                            body_lower = e.read().decode("utf-8", errors="replace").lower()
                        except Exception:
                            body_lower = ""
                        if "quota" in body_lower and ("exceeded" in body_lower or "limit" in body_lower):
                            return {
                                "success": False,
                                "quota_exhausted": True,
                                "error": ("Ultra AI explanation unavailable — Gemini "
                                          "free-tier daily quota exceeded. It resets "
                                          "automatically; the local security report is unaffected.")
                            }
                        time.sleep(1.0)
                    else:
                        break
                except Exception as e:
                    last_error = f"{model_name}: {str(e)}"
                    if "429" in str(e) or "503" in str(e):
                        time.sleep(1.0)
                    else:
                        break

        return {
            "success": False,
            "error": f"Ultra AI explanation currently unavailable ({last_error}). "
                     "The local security analysis remains valid."
        }
    except Exception as e:
        return {"success": False,
                "error": f"Ultra AI explanation unavailable: {str(e)}"}