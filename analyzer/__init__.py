"""
analyzer/__init__.py
====================
Detection & scoring engines for the Unified Email Threat Analysis Engine.

Every analyzer receives the `NormalizedEmail` object from `parsers/email_parser`
and returns a consistent envelope:

    {
      "status": "clean" | "suspicious" | "malicious" | "unavailable",
      "severity": "none" | "low" | "medium" | "high" | "critical",
      "score": 0-100,
      "detected": bool,
      "indicators": [{ "type", "evidence", "severity", "category" }],
      "summary": "..."
    }
"""

# Severity -> scoring weight (deterministic)
SEVERITY_POINTS = {"low": 10, "medium": 20, "high": 30, "critical": 40}


def build_result(status, severity, score, indicators, summary, **extra):
    """Normalize an analyzer result envelope."""
    return {
        "status": status,
        "severity": severity,
        "score": int(max(0, min(100, score))),
        "detected": status in ("suspicious", "malicious"),
        "indicators": indicators,
        "summary": summary,
        **extra,
    }


def severity_from_score(score):
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "none"


def status_from_score(score):
    if score >= 50:
        return "malicious"
    if score >= 20:
        return "suspicious"
    return "clean"


def sum_indicators(indicator_scores, cap=100):
    """Deterministic additive scoring with a hard cap."""
    total = 0
    for sev in indicator_scores:
        total += SEVERITY_POINTS.get(sev, 5)
    return min(cap, total)