"""
test_engine.py
==============
QA suite for the Unified Email Threat Analysis Engine (Task 2).

Covers the 12 required scenarios from the specification:

  1. Normal Ham          -> HAM, Low Risk, SAFE
  2. Obvious Spam        -> SPAM + real model confidence
  3. Phishing            -> phishing indicators + elevated risk
  4. Sender spoofing     -> identity mismatch
  5. Suspicious URL      -> URL extracted and analyzed
  6. Malicious attachment-> attachment flagged, hash examined
  7. Scam                -> social-engineering indicators
  8. BEC                 -> impersonation indicators
  9. QR phishing         -> QR destination analyzed (graceful if no lib)
 10. External API failure-> local analysis still completes
 11. Gemini failure      -> normal analysis still completes
 12. Mixed signals       -> HAM (ML) but SUSPICIOUS/HIGH security

Unused-feature note: analyzers run against constructed `NormalizedEmail`
objects, so no Gmail traffic or real VirusTotal calls are made here.

Run:  python test_engine.py
"""

import sys

from parsers.email_parser import NormalizedEmail, EmailAttachment
from analyzer.email_analyzer import analyze_email

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  [PASS] {name}")
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name} {('— ' + detail) if detail else ''}")


def make_predict(prediction="Not Spam", confidence=99.0, prob_spam=None):
    """Deterministic stub honoring the real predict_spam() contract."""
    if prob_spam is None:
        prob_spam = 95.0 if prediction == "Spam" else 5.0
    prob_ham = 100.0 - prob_spam

    def _predict(text):
        return {
            "prediction": prediction,
            "confidence": confidence,
            "probability_spam": round(prob_spam, 2),
            "probability_ham": round(prob_ham, 2),
            "decision_threshold": 85.0,
            "influential_signals": [],
            "matched_keywords": ["stub-token"],
        }
    return _predict


def build_email(**kwargs):
    defaults = dict(
        id="test123",
        sender_raw="Sender Name <sender@example.com>",
        sender_name="Sender Name",
        sender_email="sender@example.com",
        sender_domain="example.com",
        subject="(No Subject)",
        date="Wed, 01 Jan 2026 12:00:00 +0000",
        body_text="",
        body_html="",
        headers={},
        urls=[],
        anchor_map=[],
        attachments=[],
        qr_codes=[],
    )
    defaults.update(kwargs)
    return NormalizedEmail(**defaults)


# ---------------------------------------------------------------------------
# Test 1 — Normal Ham
# ---------------------------------------------------------------------------
def test_normal_ham():
    print("\nTest 1 — Normal Ham")
    email = build_email(
        subject="Appointment follow-up",
        body_text=("Hi Alex, the meeting is scheduled for tomorrow afternoon "
                   "in the office. Please confirm at your earliest convenience. "
                   "Regards, Priya."),
        headers={"from": "Priya <priya@example.com>",
                 "to": "alex@example.com",
                 "authentication-results": "spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass",
                 "return-path": "<bounce@example.com>"},
    )
    report = analyze_email(email, make_predict("Not Spam", 97.0))
    check("HAM classification", report["classification"]["label"] == "HAM")
    check("SAFE verdict", report["security"]["verdict"] == "SAFE",
          report["security"]["verdict"])
    check("Low risk (<=30)", report["security"]["risk_score"] <= 30,
          str(report["security"]["risk_score"]))
    check("No threats", len(report["threats"]) == 0)
    check("Schema present", all(k in report for k in (
        "message", "classification", "security", "threats", "urls",
        "sender_analysis", "header_analysis", "attachments", "scam_analysis",
        "bec_analysis", "qr_analysis", "evidence", "ai_explanation")))


# ---------------------------------------------------------------------------
# Test 2 — Obvious Spam
# ---------------------------------------------------------------------------
def test_obvious_spam():
    print("\nTest 2 — Obvious Spam")
    email = build_email(
        subject="You have WON a cash prize!",
        body_text=("Congratulations! You have won $5000 cash in our lucky "
                   "draw. Click the link immediately to claim your prize "
                   "before it expires today."),
        headers={"from": "Prize Dept <noreply@winning-offers.xyz>",
                 "authentication-results": "spf=fail; dkim=neutral; dmarc=fail"},
    )
    report = analyze_email(email, make_predict("Spam", 96.0, prob_spam=96.0))
    check("SPAM classification", report["classification"]["label"] == "SPAM")
    check("Real model confidence", report["classification"]["confidence"] == 96.0,
          str(report["classification"]["confidence"]))
    check("Risk elevated (>30)", report["security"]["risk_score"] > 30,
          str(report["security"]["risk_score"]))
    check("Threats detected", len(report["threats"]) >= 1)


# ---------------------------------------------------------------------------
# Test 3 — Phishing Email
# ---------------------------------------------------------------------------
def test_phishing():
    print("\nTest 3 — Phishing Email")
    email = build_email(
        subject="URGENT: Your account has been suspended",
        body_text=("Dear customer, your account will be suspended within 24 "
                   "hours unless you verify your password immediately. Click "
                   "here to confirm your login: http://account-verify.xyz/login "
                   "Please enter your credentials and one-time code."),
        urls=["http://account-verify.xyz/login"],
        headers={"from": "Security <security@account-verify.xyz>",
                 "authentication-results": "spf=fail"},
    )
    report = analyze_email(email, make_predict("Spam", 94.0))
    phish = report["phishing_analysis"]
    check("Phishing detected", phish["detected"] is True or phish["status"] in (
        "suspicious", "malicious"), f"status={phish['status']}")
    check("Credential indicator", any(i["type"] == "credential_harvesting"
                                      for i in phish["indicators"]))
    check("Elevated risk", report["security"]["risk_score"] > 30,
          str(report["security"]["risk_score"]))
    check("URLs analyzed", len(report["urls"]) >= 1)
    check("Suspicious URL flagged", any(u["risk"] in ("medium", "high", "critical")
                                        for u in report["urls"]))


# ---------------------------------------------------------------------------
# Test 4 — Sender Spoofing
# ---------------------------------------------------------------------------
def test_sender_spoofing():
    print("\nTest 4 — Sender Spoofing")
    email = build_email(
        sender_raw="Microsoft Support <support@random-verify-now.com>",
        sender_name="Microsoft Support",
        sender_email="support@random-verify-now.com",
        sender_domain="random-verify-now.com",
        reply_to_raw="replies <reply@unrelated-affiliate.net>",
        reply_to_email="reply@unrelated-affiliate.net",
        reply_to_domain="unrelated-affiliate.net",
        return_path="<bounce@unknown-mailer.net>",
        subject="Your Microsoft account needs verification",
        body_text="Verify your password immediately to keep your account.",
        headers={"from": "Microsoft Support <support@random-verify-now.com>",
                 "reply-to": "replies <reply@unrelated-affiliate.net>",
                 "return-path": "<bounce@unknown-mailer.net>"},
    )
    report = analyze_email(email, make_predict("Spam", 90.0))
    snd = report["sender_analysis"]
    types = {i["type"] for i in snd["indicators"]}
    check("Brand impersonation", "brand_impersonation" in types, str(types))
    check("Reply-To mismatch", "reply_to_mismatch" in types, str(types))
    check("Return-Path mismatch", "return_path_mismatch" in types, str(types))
    check("Sender risk elevated", snd["score"] >= 50, str(snd["score"]))


# ---------------------------------------------------------------------------
# Test 5 — Suspicious URL
# ---------------------------------------------------------------------------
def test_suspicious_url():
    print("\nTest 5 — Suspicious URL")
    email = build_email(
        subject="Check this link",
        body_text="Open the attachment link now: http://192.168.1.1/update.php"
                  " and http://tinyurl.com/abcdef",
        urls=["http://192.168.1.1/update.php", "http://tinyurl.com/abcdef"],
        headers={"from": "Helpdesk <help@secure-updates.tk>"},
    )
    report = analyze_email(email, make_predict("Not Spam", 88.0))
    check("URLs extracted", len(report["urls"]) >= 2)
    urls = report["urls"]
    check("IP-host URL flagged", any("raw IP address" in " ".join(u.get("findings") or [])
                                     for u in urls), str(urls))
    check("Shortener noted", any("shortened" in " ".join(u.get("findings") or [])
                                 for u in urls))


# ---------------------------------------------------------------------------
# Test 6 — Malicious Attachment
# ---------------------------------------------------------------------------
def test_malicious_attachment():
    print("\nTest 6 — Malicious Attachment")
    email = build_email(
        subject="Invoice",
        body_text="Please find the attached invoice.",
        attachments=[EmailAttachment(
            filename="invoice_final.pdf.exe",
            mime_type="application/octet-stream",
            size=2048,
            sha256="a" * 64,
            extension=".exe",
        )],
        headers={"from": "Billing <billing@vendor-secure.com>"},
    )
    report = analyze_email(email, make_predict("Not Spam", 80.0))
    check("Attachment flagged critical", any(a["risk"] == "critical"
                                             for a in report["attachments"]),
          str(report["attachments"]))
    check("Attachment risk reason present",
          any(a.get("risk_reason") for a in report["attachments"]))
    check("Hash available", report["attachments"][0]["sha256"] == "a" * 64)
    check("No execution attempted", all("executed" not in a.get("risk_reason", "")
                                        for a in report["attachments"]))


# ---------------------------------------------------------------------------
# Test 7 — Scam
# ---------------------------------------------------------------------------
def test_scam():
    print("\nTest 7 — Scam / Social Engineering")
    email = build_email(
        subject="URGENT: KYC update required",
        body_text=("URGENT: Your KYC will be blocked within 24 hours unless "
                   "you update your KYC. Please share the OTP sent to your "
                   "mobile and transfer the money to the safe account "
                   "immediately to avoid suspension."),
        headers={"from": "Support <support@kyc-update.xyz>"},
    )
    report = analyze_email(email, make_predict("Spam", 92.0))
    scam = report["scam_analysis"]
    types = {i["type"] for i in scam["indicators"]}
    check("Scam detected", scam["detected"] is True, str(types))
    check("KYC scam", "kyc_scam" in types, str(types))
    check("OTP request", "otp_request" in types, str(types))
    check("Coercive combo", "coercive_combo" in types, str(types))


# ---------------------------------------------------------------------------
# Test 8 — BEC
# ---------------------------------------------------------------------------
def test_bec():
    print("\nTest 8 — BEC / Impersonation")
    email = build_email(
        sender_raw="Ramesh Kumar, CFO <ramesh@vendor-supplier.net>",
        sender_name="Ramesh Kumar, CFO",
        sender_email="ramesh@vendor-supplier.net",
        sender_domain="vendor-supplier.net",
        subject="URGENT: Updated bank details for payment",
        body_text=("URGENT: Our bank account details have been changed. Please "
                   "transfer the outstanding payment to the new account today. "
                   "This is confidential — do not share with anyone."),
        headers={"from": "Ramesh Kumar, CFO <ramesh@vendor-supplier.net>",
                 "authentication-results": "spf=softfail"},
    )
    report = analyze_email(email, make_predict("Not Spam", 70.0))
    bec = report["bec_analysis"]
    types = {i["type"] for i in bec["indicators"]}
    check("BEC detected", bec["detected"] is True, str(types))
    check("Bank account change", "bank_account_change" in types, str(types))
    check("Urgent payment", "urgent_payment" in types, str(types))
    check("Confidential request", "confidential_request" in types, str(types))


# ---------------------------------------------------------------------------
# Test 9 — QR Phishing
# ---------------------------------------------------------------------------
def test_qr_phishing():
    print("\nTest 9 — QR Phishing")
    email = build_email(
        subject="Verify your account",
        body_text="Scan the QR code attached to verify.",
        anchor_map=[],
        qr_codes=[{"source": "qr_image.png", "url": "http://qrcode-verify.xyz/login"}],
        headers={"from": "Security <security@qrcode-verify.xyz>"},
    )
    report = analyze_email(email, make_predict("Not Spam", 60.0))
    qr = report["qr_analysis"]
    check("QR decoded & listed", len(qr.get("decoded", [])) >= 1)
    check("QR destination risk medium+", any(d["risk"] in ("medium", "high")
                                             for d in qr.get("decoded", [])))
    check("QR signal produced", any(i["type"] == "qr_phishing"
                                    for i in qr["indicators"]))

    # Graceful degradation when no QR content is available
    no_qr_email = build_email(subject="Plain email", body_text="Hello there, no QR here.",
                              qr_codes=[])
    no_qr_report = analyze_email(no_qr_email, make_predict("Not Spam", 90.0))
    check("QR unavailable handled gracefully",
          no_qr_report["qr_analysis"]["status"] in ("unavailable", "clean"))
    check("Pipeline continues without QR",
          no_qr_report["classification"]["label"] == "HAM")


# ---------------------------------------------------------------------------
# Test 10 — External API (VirusTotal) Unavailable
# ---------------------------------------------------------------------------
def test_vt_unavailable():
    print("\nTest 10 — VirusTotal Unavailable")
    email = build_email(
        subject="Re: Project update",
        body_text="The project status report is attached for your review.",
        attachments=[EmailAttachment(filename="report.pdf", mime_type="application/pdf",
                                     size=1024, sha256="b" * 64, extension=".pdf")],
        urls=["https://example.com/projects/status"],
        headers={"from": "Priya <priya@example.com>"},
    )
    report = analyze_email(email, make_predict("Not Spam", 95.0))
    check("Analysis completes", report["success"] is True)
    check("Intel reported unavailable", report["intel_status"]["virustotal_configured"] is False)
    check("URLs still analyzed", len(report["urls"]) >= 1)
    check("Attachments still reviewed", len(report["attachments"]) >= 1)
    check("Verdict still computed", report["security"]["verdict"] in (
        "SAFE", "SUSPICIOUS", "HIGH_RISK"))


# ---------------------------------------------------------------------------
# Test 11 — Gemini (Ultra AI) Failure
# ---------------------------------------------------------------------------
def test_gemini_failure():
    print("\nTest 11 — Gemini / Ultra AI Failure")
    import analyzer.ai_explainer as ai_module
    original = ai_module.GEMINI_API_KEY
    try:
        ai_module.GEMINI_API_KEY = ""  # simulate unconfigured Ultra AI
        email = build_email(
            subject="Meeting reschedule",
            body_text="Can we move tomorrow's meeting to 3pm? Let me know.",
            headers={"from": "Priya <priya@example.com>"},
        )
        report = analyze_email(email, make_predict("Not Spam", 97.0), ultra_ai=True)
        check("AI explanation graceful failure",
              report["ai_explanation"] is not None and
              report["ai_explanation"].get("success") is False)
        check("Normal analysis intact", report["classification"]["label"] == "HAM")
        check("Security verdict intact", report["security"]["verdict"] == "SAFE")
    finally:
        ai_module.GEMINI_API_KEY = original


# ---------------------------------------------------------------------------
# Test 12 — Mixed Signals (HAM + Suspicious URL)
# ---------------------------------------------------------------------------
def test_mixed_signals():
    print("\nTest 12 — Mixed HAM + Suspicious URL")
    email = build_email(
        subject="Weekly team digest",
        body_text=("Here is the weekly digest. Please review the dashboard "
                   "metrics before the sync: http://metrics-review.xyz/track "
                   "Best, Alex."),
        urls=["http://metrics-review.xyz/track"],
        headers={"from": "Alex <alex@corp.example.com>",
                 "authentication-results": "spf=pass; dkim=pass; dmarc=pass"},
    )
    report = analyze_email(email, make_predict("Not Spam", 91.0))
    check("ML says HAM", report["classification"]["label"] == "HAM")
    check("Security independent", report["security"]["verdict"] in (
        "SUSPICIOUS", "HIGH_RISK"),
          f"verdict={report['security']['verdict']} score={report['security']['risk_score']}")
    check("URL analyzed", len(report["urls"]) >= 1)
    check("Threat surfaced", len(report["threats"]) >= 1)


# ---------------------------------------------------------------------------
# Negative check — a single weak keyword must NOT create a phishing verdict
# ---------------------------------------------------------------------------
def test_no_false_positive_single_keyword():
    print("\nNegative check — single 'urgent' keyword")
    email = build_email(
        subject="Urgent: please respond",
        body_text="Please respond to my earlier message about the schedule change. Thanks!",
        headers={"from": "Priya <priya@example.com>"},
    )
    phish = analyze_email(email, make_predict("Not Spam", 93.0))["phishing_analysis"]
    check("Not flagged as phishing", phish["status"] == "clean",
          phish["status"])


def main():
    print("=" * 64)
    print("KAVACHAM AI — Unified Email Threat Analysis Engine QA Suite")
    print("=" * 64)
    tests = [test_normal_ham, test_obvious_spam, test_phishing,
             test_sender_spoofing, test_suspicious_url, test_malicious_attachment,
             test_scam, test_bec, test_qr_phishing, test_vt_unavailable,
             test_gemini_failure, test_mixed_signals, test_no_false_positive_single_keyword]
    for t in tests:
        try:
            t()
        except Exception as e:
            FAILED.append(t.__name__)
            print(f"  [ERROR] {t.__name__}: {e}")
    print("\n" + "=" * 64)
    print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    print("=" * 64)
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())