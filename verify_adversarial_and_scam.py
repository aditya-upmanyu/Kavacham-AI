"""
verify_adversarial_and_scam.py
Runs the complete adversarial test cases and actual scam test cases.
"""
from app import predict_spam

tests = [
    ("Security verification email", "Security Alert: A new login was detected from Chrome on Windows. If this was you, please verify your identity by confirming your session. We will never ask you to provide your password or OTP over email. No payment is required."),
    ("Payment confirmation", "Payment Confirmation: Your payment of $49.99 for Order #84920 has been received and confirmed. Attached is your official invoice receipt. If you have questions regarding this charge, contact customer service. No further claim or action is required."),
    ("Project selection email", "Congratulations! You have been selected to join the Robotics Research Project team for the upcoming semester. Please attend the orientation meeting tomorrow at 10 AM. Urgent submissions are not required."),
    ("Password expiration notice", "IT Security Alert: Your corporate password will expire in 5 days. Please update your credentials using the official internal portal. Remember: IT will never send direct links asking for your secret passphrase."),
    ("Student workshop newsletter", "Department Workshop Newsletter: Register for the Annual AI and Data Science Seminar held this Friday in Room 302. Snacks and certificates provided. Free entry for all students."),
    ("Registration confirmation", "Event Registration Confirmation: Your ticket registration for the Tech Summit has been confirmed. Please claim your name badge at the reception desk upon arrival. This is an urgent reminder to bring your student ID.")
]

print("=== EVALUATION OF 6 ADVERSARIAL LEGITIMATE EMAILS ===")
for name, text in tests:
    res = predict_spam(text)
    pred = res["prediction"]
    conf = res["confidence"]
    signals = [(s["token"], s["status"]) for s in res.get("influential_signals", [])[:3]]
    print(f"{name:<32} -> Pred: {pred:<8} (Confidence: {conf:5.2f}%) | Signals: {signals}")

print("\n=== EVALUATION OF GENUINE SCAMS / PHISHING ===")
scams = [
    ("Urgent Account Suspended Phishing", "URGENT: Your bank account will be suspended within 24 hours. Verify your login credentials immediately to restore access."),
    ("Lottery Prize Scam", "Congratulations! You won a $1,000 cash prize reward. Click the link now to claim your exclusive reward before it expires!"),
    ("Parcel Delivery Lure", "Dear customer, you have an unclaimed parcel waiting at our depot. Pay the $2.99 fee immediately to reschedule delivery.")
]
for name, text in scams:
    res = predict_spam(text)
    pred = res["prediction"]
    conf = res["confidence"]
    signals = [(s["token"], s["status"]) for s in res.get("influential_signals", [])[:3]]
    print(f"{name:<32} -> Pred: {pred:<8} (Confidence: {conf:5.2f}%) | Signals: {signals}")
