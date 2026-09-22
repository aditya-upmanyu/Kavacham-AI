"""
analyzer/email_analyzer.py
==========================
Master orchestrator for the Unified Email Threat Analysis Engine.

Runs every analyzer against a `NormalizedEmail`, deduplicates external
intelligence calls per run, computes the unified risk verdict, and (optionally)
attaches an Ultra AI explanation. Every component fails independently —
external failures degrade the section, never the whole analysis.
"""

from datetime import datetime, timezone

from . import spam_analyzer, phishing_analyzer, url_analyzer, sender_analyzer
from . import header_analyzer, scam_analyzer, bec_analyzer, attachment_analyzer
from . import qr_analyzer, risk_engine, ai_explainer

from intel.virustotal_service import lookup_url as vt_lookup_url, \
    lookup_hash as vt_lookup_hash, availability_status as vt_status
from parsers.url_extractor import analyze_url_structure, normalize_url


class AnalysisContext:
    """Per-run state so identical URLs/hashes are scanned at most once."""

    def __init__(self):
        self.url_cache = {}
        self.hash_cache = {}


# Threat label mapping for the human-readable "threats" section.
THREAT_LABELS = {
    "suspicious_url": "Suspicious URL",
    "url_ip_host": "Suspicious URL (IP host)",
    "anchor_mismatch": "Masked link (anchor text ≠ destination)",
    "brand_impersonation": "Sender impersonation",
    "reply_to_mismatch": "Reply-To mismatch",
    "return_path_mismatch": "Return-Path mismatch",
    "brand_free_mail_mismatch": "Brand claimed from free-mail domain",
    "lookalike_domain": "Lookalike domain",
    "spf_fail": "SPF authentication failure",
    "dkim_fail": "DKIM authentication failure",
    "dmarc_fail": "DMARC authentication failure",
    "credential_harvesting": "Credential harvesting request",
    "otp_request": "OTP / verification-code request",
    "payment_request": "Payment / invoice request",
    "account_suspension": "Account suspension threat",
    "risky_attachment": "Suspicious attachment",
    "qr_phishing": "QR phishing",
    "vt_malicious": "VirusTotal: malicious",
    "vt_suspicious": "VirusTotal: suspicious",
}


def _threat_label(itype: str) -> str:
    return THREAT_LABELS.get(itype, itype.replace("_", " ").title())


def _collect_threats(analyzer_results: dict) -> list:
    threats, seen = [], set()
    for _, res in analyzer_results.items():
        if not isinstance(res, dict):
            continue
        for ind in res.get("indicators", []) or []:
            key = (ind.get("type"), ind.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            sev = ind.get("severity", "low")
            if sev not in ("medium", "high", "critical"):
                continue
            threats.append({
                "label": _threat_label(ind.get("type", "")),
                "severity": sev,
                "category": ind.get("category", "general"),
                "evidence": ind.get("evidence", ""),
            })
    return threats[:12]


def _extract_evidence(analyzer_results: dict) -> list:
    """Flat, deduped evidence list from all analyzer indicators."""
    evidence, seen = [], set()
    for _, res in analyzer_results.items():
        if not isinstance(res, dict):
            continue
        for ind in res.get("indicators", []) or []:
            ev = (ind.get("evidence") or "").strip()
            if not ev or ev in seen:
                continue
            seen.add(ev)
            evidence.append({
                "type": ind.get("type", "indicator"),
                "evidence": ev,
                "severity": ind.get("severity", "low"),
                "category": ind.get("category", "general"),
            })
    return evidence


def analyze_email(email, predict_spam_fn, ultra_ai: bool = False) -> dict:
    """Run the full pipeline on a normalized email and return §19 schema."""
    ctx = AnalysisContext()

    # --- 1. Existing ML spam classifier (primary, unchanged) ---
    spam = spam_analyzer.analyze(email, predict_spam_fn)

    # --- Threat intelligence callables (backend only; graceful unavailability) ---
    vt_cfg = vt_status().get("configured", False)
    url_intel = vt_lookup_url if vt_cfg else None
    hash_intel = vt_lookup_hash if vt_cfg else None

    # --- 2. Detection engines (each fails independently) ---
    phishing = phishing_analyzer.analyze(email)
    url_res = url_analyzer.analyze(email, vt_lookup=url_intel, cache=ctx.url_cache)
    sender = sender_analyzer.analyze(email)
    header = header_analyzer.analyze(email)
    scam = scam_analyzer.analyze(email)
    bec = bec_analyzer.analyze(email)
    attachment = attachment_analyzer.analyze(email, vt_hash_lookup=hash_intel,
                                             cache=ctx.hash_cache)
    qr = qr_analyzer.analyze(email)

    results = {
        "spam": spam, "phishing": phishing, "url": url_res, "sender": sender,
        "header": header, "scam": scam, "bec": bec, "attachment": attachment,
        "qr": qr,
    }

    # --- 3. Unified risk engine (deterministic, evidence-based) ---
    risk = risk_engine.compute_risk(results)

    label = str(spam.get("classification", "Unavailable"))
    classification_label = "SPAM" if label == "Spam" else ("HAM" if label == "Not Spam" else "UNAVAILABLE")

    report = {
        "success": True,
        "message": {
            "id": email.id,
            "sender": email.sender_raw,
            "subject": email.subject,
            "date": email.date,
        },
        "classification": {
            "label": classification_label,
            "confidence": spam.get("confidence", 0.0),
            "probability_spam": spam.get("probability_spam", 0.0),
            "probability_ham": spam.get("probability_ham", 0.0),
            "decision_threshold": spam.get("decision_threshold"),
            "influential_signals": spam.get("influential_signals", []),
            "matched_keywords": spam.get("matched_keywords", []),
        },
        "security": {
            "verdict": risk["verdict"],
            "risk_level": risk["risk_level"],
            "risk_score": risk["risk_score"],
        },
        "risk_factors": risk["risk_factors"],
        "risk_weights": risk["weights"],
        "spam_bonus": risk["spam_bonus"],
        "top_reasons": risk["top_reasons"],
        "threats": _collect_threats(results),
        "urls": url_res.get("analyzed", []),
        "sender_analysis": sender,
        "header_analysis": header,
        "attachments": attachment.get("attachments", []),
        "scam_analysis": scam,
        "bec_analysis": bec,
        "qr_analysis": qr,
        "phishing_analysis": phishing,
        "spam_analysis": {"summary": spam.get("summary", ""),
                          "probability_spam": spam.get("probability_spam", 0.0),
                          "influential_signals": spam.get("influential_signals", [])},
        "evidence": _extract_evidence(results),
        "intel_status": {
            "virustotal_configured": vt_cfg,
            "virustotal_note": ("Threat intelligence unavailable"
                                if not vt_cfg else "VirusTotal enabled"),
        },
        "ai_explanation": None,
        "metadata": {
            "engine": "KAVACHAM AI — Unified Email Threat Analysis Engine",
            "ultra_ai": bool(ultra_ai),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    # --- 4. Optional Ultra AI explanation (never overrides findings) ---
    if ultra_ai:
        report["ai_explanation"] = ai_explainer.explain_with_gemini(report, email=email)

    return report