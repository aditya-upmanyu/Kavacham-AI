"""
analyzer/bec_analyzer.py
========================
Business Email Compromise / impersonation engine.

Looks for executive/HR/finance/bank/vendor impersonation and BEC request
patterns (urgent payment, bank account change, invoice manipulation,
confidential requests, gift cards, OTP/password asks).
"""

import re

from . import build_result, severity_from_score

BEC_CATEGORIES = [
    {
        "type": "executive_impersonation",
        "label": "Executive impersonation",
        "weight": 26,
        "patterns": [
            r"\b(cfo|ceo|president|director|founder|managing director)\b.{0,40}(urgent|request|please|payment|transfer)",
            r"(ceo|cfo|president).{0,30}(need|request|ask).{0,30}(help|transfer|confidential)",
        ],
    },
    {
        "type": "finance_impersonation",
        "label": "Finance impersonation",
        "weight": 26,
        "patterns": [
            r"\b(finance|accounts|treasury|payroll)\b.{0,30}(urgent|payment|transfer|disbursement)",
            r"(accounts payable|accounts receivable).{0,30}(due|payment|invoice)",
        ],
    },
    {
        "type": "hr_impersonation",
        "label": "HR impersonation",
        "weight": 18,
        "patterns": [
            r"\bhr\b.{0,30}(salary|bonus|appraisal|confidential)",
            r"human resources.{0,30}(urgent|confidential)",
        ],
    },
    {
        "type": "bank_impersonation",
        "label": "Bank impersonation",
        "weight": 24,
        "patterns": [
            r"(bank|banking).{0,30}(account|otp|verify|update|debit|credit)",
            r"fraud department.{0,30}(verify|confirm|transfer)",
        ],
    },
    {
        "type": "vendor_impersonation",
        "label": "Vendor / supplier impersonation",
        "weight": 20,
        "patterns": [
            r"(vendor|supplier|invoice).{0,30}(payment|bank|account|confirm)",
            r"updated (bank|remittance) details.{0,30}(payment|invoice)",
        ],
    },
    {
        "type": "urgent_payment",
        "label": "Urgent payment request",
        "weight": 24,
        "patterns": [
            r"urgent.{0,60}(payment|transfer|pay)",
            r"payment.{0,15}(must|has to).{0,15}(be made|today|now)",
            r"kindly.{0,25}transfer.{0,25}(today|now|immediately)",
            r"overdue.{0,20}(invoice|payment)",
            r"transfer.{0,60}(payment|today|now|immediately)",
            r"please (transfer|make the payment).{0,40}(today|now|immediately)",
            r"pay.{0,30}(today|now|immediately).{0,40}(invoice|vendor|supplier)",
        ],
    },
    {
        "type": "bank_account_change",
        "label": "Bank account modification request",
        "weight": 28,
        "patterns": [
            r"bank (details|account).{0,30}(changed|updated|new)",
            r"please update.{0,30}(bank|remittance) (details|account)",
            r"kindly update.{0,30}bank account",
            r"our bank (account|details) has (changed|been updated)",
        ],
    },
    {
        "type": "invoice_manipulation",
        "label": "Invoice manipulation",
        "weight": 22,
        "patterns": [
            r"revised (invoice|payment).{0,30}(new|changed|different)",
            r"replace.{0,20}(invoice|payment details)",
            r"invoice.{0,30}(changed|amended|revised)",
        ],
    },
    {
        "type": "confidential_request",
        "label": "Confidential / private request",
        "weight": 16,
        "patterns": [
            r"confidential.{0,30}(request|business|transaction)",
            r"private matter.{0,30}(request|help)",
            r"do not.{0,20}(share|disclose).{0,30}(this|with anyone)",
        ],
    },
    {
        "type": "gift_card_request",
        "label": "Gift-card purchasing push",
        "weight": 26,
        "patterns": [
            r"gift cards?.{0,40}(buy|purchase|need|can you)",
            r"purchase.{0,20}gift cards", r"apple (gift cards|itunes cards)",
        ],
    },
    {
        "type": "otp_password_request",
        "label": "OTP/password request to employee",
        "weight": 28,
        "patterns": [
            r"send me.{0,25}(otp|password|credentials)",
            r"share your.{0,25}(otp|password|login)",
            r"need your.{0,25}(password|login credentials)",
        ],
    },
]


def analyze(email):
    text = " ".join(p for p in [email.subject or "", email.body_text or ""] if p)
    lower = text.lower()

    indicators = []
    score = 0

    for cat in BEC_CATEGORIES:
        m = None
        for pat in cat["patterns"]:
            m = re.search(pat, lower)
            if m:
                break
        if m:
            score += cat["weight"]
            indicators.append({
                "type": cat["type"],
                "evidence": f"{cat['label']}: \"{' '.join(m.group(0).split())[:130]}\"",
                "severity": "high" if cat["weight"] >= 25 else
                            ("medium" if cat["weight"] >= 19 else "low"),
                "category": "bec",
            })

    # Cross-check: BEC is far stronger when sender identity looks off.
    if indicators and email.sender_domain:
        dn = (email.sender_name or "").lower()
        domain = email.sender_domain.lower()
        if any(k in dn for k in ("ceo", "cfo", "director", "finance", "accounts",
                                 "vendor", "supplier", "hr", "payroll")):
            score += 12
            indicators.append({
                "type": "claimed_role_sender_mismatch",
                "evidence": (
                    f"Display name '{email.sender_name}' claims an authoritative role "
                    f"while the sending domain is '{domain}'."
                ),
                "severity": "medium", "category": "bec",
            })

    score = min(100, score)
    status = "malicious" if score >= 55 else ("suspicious" if score >= 25 else "clean")

    if indicators:
        summary = (
            f"Possible {indicators[0]['type'].replace('_', ' ')} detected — "
            f"finance/impersonation pressure patterns present."
        )
    else:
        summary = "No BEC / executive-impersonation patterns detected."

    return build_result(status, severity_from_score(score), score, indicators, summary)