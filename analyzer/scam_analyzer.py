"""
analyzer/scam_analyzer.py
=========================
Scam / social-engineering engine.

Uses weighted indicators across known scam families (KYC, refund, job,
lottery/prize, account suspension, payment, OTP, credential harvesting,
digital-arrest, fake support, fake delivery/refund). A single keyword is
never enough — the combination of URGENT + MONEY + IDENTITY + CREDENTIAL
produces a much stronger signal than any individual keyword.
"""

import re

from . import build_result, severity_from_score

SCAM_CATEGORIES = [
    {
        "type": "kyc_scam",
        "label": "KYC / identity verification scam",
        "weight": 22,
        "patterns": [
            r"kyc.{0,25}(expired|expire|update|verification|fail)",
            r"your kyc will be (blocked|suspended)",
            r"update your kyc", r"re.?activate your account.{0,30}kyc",
            r"know your customer",
        ],
    },
    {
        "type": "refund_scam",
        "label": "Refund scam",
        "weight": 20,
        "patterns": [
            r"claim your (refund|tax refund)", r"refund.{0,25}(pending|due|process)",
            r"tax refund.{0,25}(claim|eligible)", r"unclaimed refund",
            r"you are eligible.{0,30}refund",
        ],
    },
    {
        "type": "job_scam",
        "label": "Job / work-from-home scam",
        "weight": 18,
        "patterns": [
            r"work from home.{0,30}(earn|income|salary)",
            r"(make|earn) \$?\d+ per (day|week).{0,20}(easy|simple|just)",
            r"no experience.{0,20}(earn|salary|income)",
            r"mystery shopper", r"receive money.{0,20}keep.{0,20}send",
        ],
    },
    {
        "type": "lottery_prize",
        "label": "Lottery / prize scam",
        "weight": 20,
        "patterns": [
            r"you have won.{0,30}(lottery|prize|cash)",
            r"(lottery|prize).{0,25}(claim|winner)",
            r"winning (amount|sum|cash)", r"congratulations.{0,25}winner",
            r"ballot.{0,20}(claim|winner)",
        ],
    },
    {
        "type": "account_suspension",
        "label": "Account suspension threat",
        "weight": 18,
        "patterns": [
            r"account.{0,25}(suspended|blocked|closed|deactivated)",
            r"will be (suspended|blocked|closed).{0,25}(hours|days)",
            r"immediate action.{0,25}(account|suspension)",
            r"final notice.{0,25}(account|suspension)",
        ],
    },
    {
        "type": "payment_scam",
        "label": "Payment / money transfer scam",
        "weight": 22,
        "patterns": [
            r"transfer.{0,20}(money|funds)|wire.{0,20}(money|funds)",
            r"send.{0,20}(money|payment|bitcoin|crypto).{0,20}(immediately|now|today)",
            r"payment.{0,15}(confirm|verify).{0,20}link",
            r"bank account.{0,30}(updated|changed|new)",
        ],
    },
    {
        "type": "otp_request",
        "label": "OTP / one-time password request",
        "weight": 22,
        "patterns": [
            r"share.{0,25}(otp|one.?time password|code)",
            r"(otp|one.?time password).{0,25}(confirm|verify|sent)",
            r"forward.{0,20}(otp|code)",
        ],
    },
    {
        "type": "credential_harvesting",
        "label": "Credential harvesting request",
        "weight": 26,
        "patterns": [
            r"enter your (password|username|credentials|login)",
            r"verify your (password|credentials|identity)",
            r"confirm your (password|login|credentials)",
            r"update your (password|login|account)", r"password.{0,20}(expired|reset)",
        ],
    },
    {
        "type": "digital_arrest",
        "label": "Digital-arrest / legal intimidation scam",
        "weight": 28,
        "patterns": [
            r"digital arrest", r"cyber crime.{0,20}(arrest|court)",
            r"arrest warrant", r"(court|police).{0,25}(notice|citation)",
            r"legal action.{0,25}immediate",
        ],
    },
    {
        "type": "fake_support",
        "label": "Fake customer support",
        "weight": 18,
        "patterns": [
            r"customer (support|care).{0,30}(urgent|immediate)",
            r"contact support.{0,20}(immediately|now)",
            r"support.{0,15}(not reachable|unavailable)",
        ],
    },
    {
        "type": "fake_delivery",
        "label": "Fake delivery / courier scam",
        "weight": 18,
        "patterns": [
            r"package.{0,25}(held|delivery|deliver)", r"parcel.{0,25}(held|delivery)",
            r"delivery.{0,20}(failed|reschedule|fee)|shipping.{0,20}(fee|charge)",
            r"your (package|parcel).{0,25}(waiting|blocked)",
        ],
    },
]

# Pivot signals that amplify other categories
URGENT_PATTERN = re.compile(r"\b(urgent|immediately|asap|right now|hurry|today only)\b", re.IGNORECASE)
MONEY_PATTERN = re.compile(r"\b(money|payment|funds|transfer|bitcoin|rupees?|dollars?|usd|inr)\b", re.IGNORECASE)
IDENTITY_PATTERN = re.compile(r"\b(account|bank|identity|kyc|aadhaar|pan|credit card)\b", re.IGNORECASE)


def analyze(email):
    text = " ".join(p for p in [email.subject or "", email.body_text or ""] if p)
    lower = text.lower()

    indicators = []
    score = 0

    for cat in SCAM_CATEGORIES:
        evidence = []
        for pat in cat["patterns"]:
            m = re.search(pat, lower)
            if m:
                evidence.append(" ".join(m.group(0).split())[:140])
                break
        if evidence:
            score += cat["weight"]
            indicators.append({
                "type": cat["type"],
                "evidence": f"{cat['label']}: \"{evidence[0]}\"",
                "severity": "high" if cat["weight"] >= 25 else
                            ("medium" if cat["weight"] >= 19 else "low"),
                "category": "scam",
            })

    # Combination amplification: URGENT + MONEY + IDENTITY dramatically raises
    # the risk of a social-engineering attack.
    combo = 0
    if URGENT_PATTERN.search(lower):
        combo += 1
    if MONEY_PATTERN.search(lower):
        combo += 1
    if IDENTITY_PATTERN.search(lower):
        combo += 1
    if combo >= 3:
        score += 25
        indicators.append({
            "type": "coercive_combo",
            "evidence": "Message combines urgency + financial references + identity/account claims — a classic social-engineering cocktail.",
            "severity": "high", "category": "scam",
        })
    elif combo == 2:
        score += 10

    score = min(100, score)
    status = "malicious" if score >= 55 else ("suspicious" if score >= 25 else "clean")

    summary = ""
    if indicators:
        top = indicators[0]["type"].replace("_", " ")
        summary = f"Possible social-engineering pattern detected ({top}) with {len(indicators)} supporting signal(s)."
    else:
        summary = "No significant scam / social-engineering indicators found."

    return build_result(status, severity_from_score(score), score, indicators, summary,
                        combo_signals=combo)