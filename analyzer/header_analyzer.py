"""
analyzer/header_analyzer.py
===========================
Email header / authentication analyzer.

Parses the available authentication evidence (Authentication-Results,
Received-SPF, DKIM, DMARC, Return-Path, Message-ID, Received) and reports the
states that actually exist. Missing headers are reported as
"Authentication information unavailable" — never silently fabricated.
"""

import re

from . import build_result, severity_from_score

RFC_STATES = ("pass", "fail", "softfail", "neutral", "temperror", "permerror", "none")


def _clean_state(value: str, default="none") -> str:
    v = (value or "").strip().lower()
    for s in RFC_STATES:
        if s in v:
            return s.upper()
    return default.upper()


def _parse_authentication_results(value: str) -> dict:
    """Parse 'Authentication-Results' into spf/dkim/dmarc state maps."""
    out = {"raw": value, "spf": None, "dkim": None, "dmarc": None, "header_from": None}
    if not value:
        return out
    m = re.search(r"header\.from\s*=\s*([^;\s]+)", value, re.IGNORECASE)
    if m:
        out["header_from"] = m.group(1)
    for m in re.finditer(r"\bspf=([A-Za-z]+)", value, re.IGNORECASE):
        out["spf"] = m.group(1).upper()
        break
    for m in re.finditer(r"\bdkim=([A-Za-z]+)", value, re.IGNORECASE):
        out["dkim"] = m.group(1).upper()
        break
    for m in re.finditer(r"\bdmarc=([A-Za-z]+)", value, re.IGNORECASE):
        out["dmarc"] = m.group(1).upper()
        break
    return out


def analyze(email):
    """Build authentication signal summary from available headers."""
    headers = email.headers or {}
    indicators = []
    available = {}

    auth_results_raw = (headers.get("authentication-results") or "").strip()
    received_spf_raw = (headers.get("received-spf") or "").strip()

    ar = _parse_authentication_results(auth_results_raw)
    if auth_results_raw:
        available["authentication_results"] = {
            "raw": auth_results_raw[:300],
            "spf": ar["spf"], "dkim": ar["dkim"], "dmarc": ar["dmarc"],
            "header_from": ar["header_from"],
        }
    if received_spf_raw:
        spf_from_header = _clean_state(received_spf_raw.split(" ")[0])
        available.setdefault("authentication_results", {})["spf"] = spf_from_header
        if "spf" not in available.setdefault("authentication_results", {}):
            available["authentication_results"]["spf"] = spf_from_header

    # Received-SPF direct header fallback
    if received_spf_raw and ar.get("spf") is None:
        ar["spf"] = _clean_state(received_spf_raw.split(" ")[0])

    # Message-ID / Received presence
    available["message_id"] = (headers.get("message-id") or "").strip() or None
    received_lines = headers.get("received")
    available["received_count"] = (received_lines.count("\n") + 1) if received_lines else 0

    # At least Return-Path / From / Reply-To
    available["from"] = (headers.get("from") or "")[:200]
    available["reply_to"] = (headers.get("reply-to") or "")[:200]
    available["return_path"] = (headers.get("return-path") or "").strip()

    if not auth_results_raw and not received_spf_raw:
        return build_result(
            "clean", "none", 0, [],
            "Authentication information unavailable — the fetched message contains no SPF/DKIM/DMARC evidence.",
            authentication=available,
        )

    # Severity scoring from actual states
    fail_count = 0
    softfail = False
    for key in ("spf", "dkim", "dmarc"):
        state = ar.get(key)
        if not state:
            continue
        if state in ("FAIL", "PERMERROR"):
            fail_count += 1
            indicators.append({
                "type": f"{key}_fail",
                "evidence": f"{key.upper()} authentication {state} for this message.",
                "severity": "high", "category": "authentication",
            })
        elif state in ("SOFTFAIL", "TEMPERROR", "NEUTRAL"):
            softfail = True
            indicators.append({
                "type": f"{key}_{state.lower()}",
                "evidence": f"{key.upper()} authentication result: {state}.",
                "severity": "medium" if state in ("SOFTFAIL",) else "low",
                "category": "authentication",
            })
        elif state == "PASS":
            indicators.append({
                "type": f"{key}_pass",
                "evidence": f"{key.upper()} authentication passed.",
                "severity": "low", "category": "authentication",
            })
        else:  # NONE / UNKNOWN are informational
            indicators.append({
                "type": f"{key}_{state.lower()}",
                "evidence": f"{key.upper()} result: {state} (no authentication claim).",
                "severity": "low", "category": "authentication",
            })

    score = 0
    score += min(40, 26 * fail_count)
    if softfail:
        score += 14
    # a PASS on all three should not inflate risk
    if fail_count == 0 and not softfail:
        score = min(score, 5)

    if fail_count >= 2:
        status, severity = "malicious", "high"
        summary = "Multiple authentication failures (SPF/DKIM/DMARC) — strong spoofing indicator."
    elif fail_count == 1:
        status, severity = "suspicious", "medium"
        summary = "One authentication mechanism failed; header evidence is inconsistent."
    else:
        status, severity = "clean", "none"
        summary = "Available authentication results show no failures."

    return build_result(status, severity if severity != "none" else "none",
                        score, indicators, summary, authentication=available)