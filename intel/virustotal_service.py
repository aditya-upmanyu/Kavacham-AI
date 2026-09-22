"""
intel/virustotal_service.py
===========================
Backend-only VirusTotal integration for the unified analysis engine.

Responsibilities:
- URL reputation lookup
- File hash (SHA-256) reputation lookup
- Response normalization
- API timeout handling
- Rate-limit (HTTP 429 / 204) handling

SECURITY:
- The API key is read ONLY from the environment / .env file.
- The key is NEVER exposed to the frontend.
- If the API key is missing or the service is unreachable, every function
  returns an "unavailable" payload so Kavacham's local engines still run.
"""

import os
import json
import base64
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
VT_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 10  # seconds


def _vt_request(path: str) -> dict:
    """Low-level VT request. Returns {} on any failure / non-JSON response."""
    if not VIRUSTOTAL_API_KEY:
        return {"__unavailable": True, "error": "VIRUSTOTAL_API_KEY not configured"}
    url = f"{VT_BASE}/{path}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", VIRUSTOTAL_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return {"__rate_limited": True, "error": "VirusTotal rate limit exceeded (HTTP 429)"}
        if e.code == 204:
            return {"__rate_limited": True, "error": "VirusTotal quota exhausted (HTTP 204)"}
        if e.code == 404:
            return {"__not_found": True, "error": "Not found in VirusTotal"}
        return {"__error": True, "error": f"VirusTotal HTTP {e.code}: {e.reason}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"__unavailable": True, "error": f"VirusTotal unreachable: {str(e)}"}
    except Exception as e:
        return {"__error": True, "error": str(e)}


def _normalize_analysis(attr: dict) -> dict:
    """Normalize a VT `last_analysis_stats`-style object."""
    stats = attr.get("last_analysis_stats", {}) or {}
    results = attr.get("last_analysis_results", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    verdict = "unknown"
    if total == 0:
        verdict = "no-data"
    elif malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "suspicious"
    elif harmless >= 1:
        verdict = "clean"

    # Grab up to 5 named engine flags for evidence
    flagged = []
    for engine, res in list(results.items())[:12]:
        cat = (res or {}).get("category", "")
        if cat in ("malicious", "suspicious"):
            flagged.append(engine)
            if len(flagged) >= 5:
                break

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": len(results),
        "flagged_by": flagged,
        "reputation": attr.get("reputation", 0),
        "last_analysis_date": attr.get("last_analysis_date"),
    }


def lookup_url(url: str) -> dict:
    """
    URL reputation lookup. Never used when the key is unset.
    Returns standard envelope: {available, verdict, data, note}.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": "Threat intelligence unavailable (VIRUSTOTAL_API_KEY not configured)."}
    # VT v3 URLs are base64url-encoded (unpadded).
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    resp = _vt_request(f"urls/{url_id}")
    if "error" in resp:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": f"Threat intelligence unavailable — {resp['error']}"}
    attr = resp.get("data", {}).get("attributes", {})
    norm = _normalize_analysis(attr)
    return {"available": True, "verdict": norm["verdict"], "data": norm,
            "note": f"VirusTotal engines: {norm['total_engines']} total, {norm['malicious']} malicious."}


def lookup_hash(sha256: str) -> dict:
    """
    SHA-256 file hash reputation. Responds "unavailable" gracefully when the
    key is unset, the hash is unknown, or the API times out.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": "Threat intelligence unavailable (VIRUSTOTAL_API_KEY not configured)."}
    if not sha256 or not re_hex_sha(sha256):
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": "No hash available for lookup."}
    resp = _vt_request(f"files/{sha256}")
    if "error" in resp:
        return {"available": False, "verdict": "unavailable",
                "data": None, "note": f"Threat intelligence unavailable — {resp['error']}"}
    attr = resp.get("data", {}).get("attributes", {})
    norm = _normalize_analysis(attr)
    return {"available": True, "verdict": norm["verdict"], "data": norm,
            "note": f"VirusTotal engines: {norm['total_engines']} total, {norm['malicious']} malicious."}


def re_hex_sha(sha256: str) -> bool:
    if not sha256:
        return False
    return len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256.lower())


def availability_status() -> dict:
    """For UI: whether the threat intel backend is configured."""
    return {
        "configured": bool(VIRUSTOTAL_API_KEY),
        "service": "VirusTotal",
    }