"""
analyzer/risk_engine.py
=======================
Unified, fully deterministic risk engine.

Takes the outputs of every analyzer and produces:

* five visible factor scores (URL / Sender / Content / Authentication /
  Attachment)
* a single 0-100 risk score computed ONLY from real evidence
* a security verdict: SAFE (0-30) / SUSPICIOUS (31-60) / HIGH RISK (61-100)
* the top reasons that drove the score

The security verdict is intentionally independent from the ML SPAM/HAM
classification — a ham-looking email can still carry a suspicious URL.
"""

# Fixed factor weights (deterministic, sum = 1.00)
FACTOR_WEIGHTS = {
    "url": 0.22,
    "sender": 0.16,
    "content": 0.30,
    "authentication": 0.15,
    "attachment": 0.17,
}

# analyzer result key -> risk factor key
RESULT_FACTOR_MAP = {
    "spam": "content", "phishing": "content", "scam": "content", "bec": "content",
    "url": "url", "sender": "sender", "header": "authentication",
    "attachment": "attachment", "qr": "attachment",
}


def _content_factor(phishing, scam, bec):
    """Blend content-based detectors; corroboration raises risk."""
    active = [s for s in (phishing.get("score", 0), scam.get("score", 0),
                          bec.get("score", 0)) if s >= 20]
    if not active:
        return 0
    top = max(active)
    extra = sum(active) - top
    return min(100, int(top + 0.35 * extra))


def _spam_bonus(spam_result):
    """High-confidence ML spam adds a small, capped, deterministic bonus."""
    if spam_result.get("classification") != "Spam":
        return 0
    prob = spam_result.get("probability_spam", 0) or 0
    if prob >= 90:
        return 8
    return 5


def _top_reasons(results, factor_scores):
    """Collect the most severe concrete evidence across all detectors."""
    reasons = []
    ordered = []
    for key, res in results.items():
        if not isinstance(res, dict):
            continue
        for ind in res.get("indicators", []) or []:
            ordered.append((ind.get("severity", "low"), ind.get("type", ""),
                            ind.get("evidence", ""), key))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered.sort(key=lambda t: sev_order.get(t[0], 9))

    seen_types = set()
    for sev, itype, evidence, src in ordered:
        key = (sev, itype)
        if key in seen_types:
            continue
        seen_types.add(key)
        reasons.append({"reason": evidence or f"{itype} signal detected.",
                        "severity": sev, "type": itype,
                        "factor": RESULT_FACTOR_MAP.get(src, "content")})
        if len(reasons) >= 7:
            break
    return reasons


def compute_risk(results: dict) -> dict:
    """
    results: dict of analyzer envelopes:
        spam, phishing, url, sender, header, scam, bec, attachment, qr
    """
    spam = results.get("spam") or {}
    phishing = results.get("phishing") or {}
    url = results.get("url") or {}
    sender = results.get("sender") or {}
    header = results.get("header") or {}
    scam = results.get("scam") or {}
    bec = results.get("bec") or {}
    attachment = results.get("attachment") or {}
    qr = results.get("qr") or {}

    factor_scores = {
        "url": int(url.get("score", 0) or 0),
        "sender": int(sender.get("score", 0) or 0),
        "content": _content_factor(phishing, scam, bec),
        "authentication": int(header.get("score", 0) or 0),
        "attachment": max(int(attachment.get("score", 0) or 0),
                          int(qr.get("score", 0) or 0)),
    }

    weighted = sum(factor_scores[k] * w for k, w in FACTOR_WEIGHTS.items())
    bonus = _spam_bonus(spam)
    risk_score = min(100, int(round(weighted)) + bonus)

    # Deterministic escalation floor: a concrete, evidence-based threat signal
    # (factor score >= 25) means the message cannot be rated SAFE, and a
    # high-severity signal (>= 50) keeps it firmly in the Suspicious band.
    # This intentionally does NOT push a single detector to HIGH RISK — it
    # requires corroboration across factors for that (per spec §15).
    worst_factor = max(factor_scores.values())
    if worst_factor >= 50:
        risk_score = max(risk_score, 51)
        floor_note = ("A high-severity threat signal was detected in one factor; "
                      "the score is held above SAFE until corroborated by other evidence.")
    elif worst_factor >= 25:
        risk_score = max(risk_score, 31)
        floor_note = ("A concrete suspicious threat signal was detected; "
                      "the message cannot be rated SAFE.")
    else:
        floor_note = None

    if risk_score <= 30:
        verdict, risk_level = "SAFE", "Low Risk"
    elif risk_score <= 60:
        verdict, risk_level = "SUSPICIOUS", "Suspicious"
    else:
        verdict, risk_level = "HIGH_RISK", "High Risk"

    reasons = _top_reasons(results, factor_scores)
    if floor_note:
        reasons.insert(0, {
            "reason": floor_note,
            "severity": "medium", "type": "risk_escalation", "factor": "content",
        })
    if spam.get("classification") == "Spam" and bonus:
        reasons.insert(0, {
            "reason": (f"ML model classified the message as SPAM "
                       f"({spam.get('probability_spam', 0)}% spam probability)."),
            "severity": "high", "type": "spam_classification", "factor": "content",
        })
    if not reasons:
        reasons.append({
            "reason": "No concrete threat indicators were detected across any engine.",
            "severity": "none", "type": "no_indicators", "factor": "content",
        })

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_factors": factor_scores,
        "weights": FACTOR_WEIGHTS,
        "spam_bonus": bonus,
        "top_reasons": reasons[:7],
    }