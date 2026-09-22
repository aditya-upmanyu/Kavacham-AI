"""
analyzer/phishing_analyzer.py
=============================
Phishing detection engine — analyzes content indicators (credential requests,
login/OTP/payment asks, suspension threats, urgency, KYC, prize bait) and
link indicators (anchor-vs-URL mismatch, obfuscation, IP hosts, shorteners).

No single weak indicator is enough to declare phishing: scoring requires
multiple corroborating signals, and verdicts are derived deterministically.
"""

import re
from urllib.parse import urlparse

from . import build_result, sum_indicators, status_from_score, severity_from_score
from parsers.url_extractor import analyze_url_structure, normalize_url, URL_SHORTENERS

# ---------------------------------------------------------------------------
# Content indicator categories (weight = deterministic point contribution)
# ---------------------------------------------------------------------------

CONTENT_CATEGORIES = [
    {
        "type": "credential_harvesting",
        "weight": 34,
        "label": "Credential harvesting language",
        "patterns": [
            r"verify your (password|account|identity|login)",
            r"confirm your (password|credentials|login)",
            r"enter your (password|username|credentials|pin)",
            r"your password.*expir",
            r"update your (banking|login) details",
            r"click here to (verify|confirm|update) your (account|password)",
            r"provide your (password|otp|pin)",
            r"unusual sign[ -]?in",
            r"sign[ -]?in to (verify|confirm)",
        ],
    },
    {
        "type": "otp_request",
        "weight": 28,
        "label": "One-time password / verification code request",
        "patterns": [
            r"\botp\b", r"one[ -]?time (password|code|pin|otp)",
            r"verification code", r"security code", r"6[ -]?digit (code|pin)",
            r"share.{0,20}(code|otp|pin)",
        ],
    },
    {
        "type": "login_request",
        "weight": 24,
        "label": "Login / sign-in request",
        "patterns": [
            r"log[ -]?in to your account", r"sign[ -]?in to your account",
            r"account.{0,20}(locked|blocked|suspended)", r"unlock your account",
            r"re[ -]?activate your account", r"restore your account",
        ],
    },
    {
        "type": "password_reset",
        "weight": 24,
        "label": "Password reset request",
        "patterns": [
            r"reset your password", r"change your password",
            r"password.{0,20}(expired|expire)", r"recover your password",
        ],
    },
    {
        "type": "payment_request",
        "weight": 26,
        "label": "Payment / invoice request",
        "patterns": [
            r"confirm your payment", r"payment.{0,20}(failed|declined|pending)",
            r"update your (payment|billing) (method|details|info)",
            r"invoice.{0,20}(attached|pending|due)", r"pay.{0,20}immediately",
            r"refund.{0,20}(due|pending|process)",
        ],
    },
    {
        "type": "account_suspension",
        "weight": 24,
        "label": "Account suspension / closure threat",
        "patterns": [
            r"account.{0,20}(suspended|will be suspended|will be closed|deactivated)",
            r"close your account", r"terminat.{0,20}account",
            r"within 24 hours", r"within 48 hours",
        ],
    },
    {
        "type": "urgent_verification",
        "weight": 20,
        "label": "Urgent verification demand",
        "patterns": [
            r"urgently.{0,30}(verify|update|confirm)",
            r"immediately.{0,30}(verify|update|confirm)",
            r"action required", r"respond.{0,15}immediately",
            r"immediate action", r"act now",
        ],
    },
    {
        "type": "kyc_request",
        "weight": 20,
        "label": "Suspicious KYC request",
        "patterns": [
            r"\bkyc\b", r"know your customer", r"kyc (update|verification)",
            r"re[ -]?verification", r"upload.{0,25}(id|identity|passport|pan|aadhaar)",
        ],
    },
    {
        "type": "reward_bait",
        "weight": 16,
        "label": "Reward / prize bait",
        "patterns": [
            r"you (have )?won", r"congratulations.{0,20}(winner|prize|reward)",
            r"claim your (prize|reward|gift)", r"lucky winner", r"cash prize",
            r"free (gift|reward|iphone|prize)",
        ],
    },
    {
        "type": "unusual_urgency",
        "weight": 12,
        "label": "Unusual pressure language",
        "patterns": [
            r"\b(urgent|immediately|asap|right now|hurry)\b",
            r"limited (time|period)", r"before it's too late", r"last chance",
            r"expires? (today|soon|tonight)",
        ],
    },
]

# ---------------------------------------------------------------------------
# Link-anomaly helpers
# ---------------------------------------------------------------------------

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "icloud.com", "zoho.com", "gmx.com", "yandex.com",
    "mail.com", "rediffmail.com", "live.com",
}


def _anchor_mismatches(email) -> list:
    """Compare anchor text vs resulting href host to catch masked links."""
    mismatches = []
    for pair in (email.anchor_map or []):
        href = (pair.get("href") or "").strip()
        text = (pair.get("text") or "").strip()
        if not href or not href.startswith(("http://", "https://")):
            continue
        try:
            shown_host = urlparse(text if "://" in text else "https://" + text.strip()).hostname or ""
        except Exception:
            shown_host = ""
        try:
            actual_host = urlparse(href).hostname or ""
        except Exception:
            actual_host = ""
        if shown_host and actual_host and shown_host != actual_host:
            mismatches.append({
                "type": "anchor_mismatch",
                "evidence": f"Link text '...{text[:60]}' points to '{href[:80]}' (host '{actual_host}'), not the shown host '{shown_host}'.",
                "severity": "high", "category": "phishing-link",
            })
    return mismatches


def _link_indicators(email) -> list:
    """Structural link signals: IP hosts, punycode, encoding, shorteners."""
    indicators = []
    seen = set()
    for url in (email.urls or []):
        structure = analyze_url_structure(url)
        hostname = structure.get("hostname", "")
        if not hostname or hostname in seen:
            continue
        seen.add(hostname)
        if structure.get("is_ip"):
            indicators.append({
                "type": "ip_url",
                "evidence": f"URL host {hostname} is a raw IP address (often used to bypass domain reputation checks).",
                "severity": "high", "category": "phishing-link",
            })
        if structure.get("is_punycode"):
            indicators.append({
                "type": "idn_homograph",
                "evidence": f"URL uses internationalized (punycode) host '{hostname}' which can spoof a well-known brand.",
                "severity": "medium", "category": "phishing-link",
            })
        if structure.get("is_encoded"):
            indicators.append({
                "type": "encoded_url",
                "evidence": f"URL '{url[:70]}' contains heavy percent-encoding (obfuscation indicator).",
                "severity": "medium", "category": "phishing-link",
            })
        if structure.get("is_shortened"):
            indicators.append({
                "type": "shortened_url",
                "evidence": f"URL is shortened through {hostname}; destination is obscured.",
                "severity": "low", "category": "phishing-link",
            })
        if structure.get("suspicious_tld"):
            indicators.append({
                "type": "suspicious_tld",
                "evidence": f"URL host '{hostname}' uses a frequently-abused TLD.",
                "severity": "medium", "category": "phishing-link",
            })
    return indicators


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def analyze(email):
    """Run phishing detection on a normalized email."""
    text = " ".join(p for p in [email.subject or "", email.body_text or ""] if p).lower()
    indicators = []

    matched_types = set()
    for cat in CONTENT_CATEGORIES:
        evidence = []
        for pat in cat["patterns"]:
            for m in re.finditer(pat, text):
                evidence.append(" ".join(m.group(0).replace("\n", " ").split())[:140])
                if len(evidence) >= 2:
                    break
            if evidence:
                break
        if evidence:
            matched_types.add(cat["type"])
            indicators.append({
                "type": cat["type"],
                "evidence": f"{cat['label']}: \"{evidence[0]}\"",
                "severity": severity_from_score(cat["weight"]),
                "category": "phishing-content",
            })

    indicators.extend(_link_indicators(email))
    indicators.extend(_anchor_mismatches(email))

    # Deterministic additive scoring from indicator severities.
    # Single weak indicators must never reach "suspicious" on their own.
    score = sum_indicators([i["severity"] for i in indicators], cap=100)

    # Gating: need at least two corroborating signals, OR one strong
    # credential-harvesting/OTP/payment signal combined with a link anomaly.
    link_sigs = [i for i in indicators if i["category"] == "phishing-link"]
    strong_content = [i for i in indicators if i["type"] in
                      ("credential_harvesting", "otp_request", "payment_request")]

    corroborated = len(indicators) >= 2 or (strong_content and link_sigs)
    if not corroborated:
        score = 0  # a lone weak indicator is treated as noise

    if score >= 50 and corroborated:
        status = "malicious"
    elif score >= 25 and corroborated:
        status = "suspicious"
    else:
        status = "clean"
        score = min(score, 15)

    summary = ""
    if status == "malicious":
        summary = "Phishing detected: credential/OTP harvesting language combined with suspicious or masked links."
    elif status == "suspicious":
        summary = "Suspicious phishing indicators found; not conclusive on its own."
    else:
        summary = "No significant phishing indicators detected."

    return build_result(status, severity_from_score(score), score, indicators, summary,
                        matched_categories=sorted(matched_types))