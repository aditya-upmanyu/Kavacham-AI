"""
generate_contextual_dataset.py
Enriches the synthetic dataset with diverse legitimate institutional, security, notification,
receipt, academic, and business ham emails that naturally use words like:
- security, alert, verify, verification, confirmation, claim, payment, urgent, limited, account
This directly resolves the dataset keyword bias where these words only existed in spam templates.
"""

import pandas as pd
import random

# Load current unique records from data.pdf extraction
df_existing = pd.read_csv("dataset.csv").drop_duplicates(subset=["message"]).copy()
print(f"Loaded existing unique rows: {len(df_existing)}")
print(df_existing["label"].value_counts())

# Representative legitimate (ham) messages containing contextual words (security, verify, payment, alert, claim, confirmation, urgent, account, etc.)
LEGITIMATE_CONTEXTUAL_HAM = [
    # Security alerts & verification (Legitimate IT / Services)
    "Security Alert: A new login to your student account was detected from Chrome on Windows. If this was you, please verify your session in account settings. We will never ask you to email your password or OTP.",
    "IT Security Notice: Your university single sign-on password will expire in 5 days. Please update your credentials through the internal intranet portal. Do not share your password with anyone.",
    "Two-Factor Authentication: Your verification code is 492015. This code expires in 10 minutes. For your security, never provide this code to anyone over phone or email.",
    "Account Security Update: We updated our privacy and security policy. No payment or action is required from your side. You can review the changes on our official settings dashboard.",
    "Security Team Advisory: Phishing warning: please be cautious of suspicious emails asking for credentials. Legitimate staff will never ask for your verification code or bank details.",
    "Google Account Security: We noticed a new sign-in from a new device. If this was not you, check your recent security activity and verify your account recovery options.",
    "Campus Wi-Fi Security Notice: Please reinstall the eduroam security certificate before the semester starts to maintain secure wireless network access.",
    "System Alert: Scheduled server maintenance will occur this Saturday between 2 AM and 4 AM. Services will resume automatically, no password verification required.",

    # Payment confirmations, receipts & invoicing (Legitimate Ham)
    "Payment Confirmation: Your tuition fee payment of $1,250.00 has been processed successfully. Transaction ID: TXN-89214. The official invoice receipt is attached for your records.",
    "Order & Payment Receipt: We have received your payment for the textbooks order #58210. Your order has been confirmed and estimated delivery is Thursday. No further payment needed.",
    "Monthly Subscription Receipt: Your payment of $12.99 was successfully charged to your credit card. You can view or download the invoice from your billing account page.",
    "Payment Received: Thank you for your payment towards the annual department library dues. The account statement is now up to date. Reply if you need a printed receipt.",
    "Vendor Invoice Confirmation: Your vendor payment of $340.00 for lab equipment supplies has been scheduled for direct deposit on Monday. Confirmation number is 77312.",
    "Refund Confirmation: Your refund payment of $45.00 for the cancelled seminar ticket has been credited back to your original payment method. Please allow 3-5 business days.",

    # Registrations, confirmations & bookings (Legitimate Ham)
    "Event Registration Confirmation: Your registration for the National Science Symposium has been confirmed. Please claim your attendee badge and kit at the registration desk upon arrival.",
    "Registration Confirmation: You are registered for CS402 Machine Learning for the Fall semester. Verify your class schedule on the portal before Friday.",
    "Workshop Registration: Confirmation of your seat in the Python & Data Science Bootcamp. Free admission for university students. Bring your laptop and student ID.",
    "Conference Ticket Confirmed: Your booking confirmation for PyCon 2026 is complete. Please verify your dietary preferences and print your badge before attending.",
    "Appointment Confirmation: Your appointment with Dr. Sharma has been confirmed for tomorrow at 3:30 PM. Please arrive 10 minutes early to verify insurance details.",
    "Lab Seat Confirmation: Your reservation for the High Performance Computing Lab has been confirmed for Tuesday morning. Let us know if you need to reschedule.",

    # Selections, awards & project updates (Legitimate Ham)
    "Congratulations! You have been selected for the Summer Research Internship in the AI Laboratory. Please attend the orientation meeting tomorrow at 11 AM to meet your mentor.",
    "Project Selection Notification: Your team has been selected to present the final year capstone project at the college innovation expo. Please confirm your project poster dimensions.",
    "Scholarship Award Committee: Congratulations on being selected for the Department Merit Scholarship. The award letter and terms are attached for your signature.",
    "Club Selection Results: Congratulations! You have been selected as a core coordinator for the Robotics Student Chapter. Our first planning meeting is this Wednesday evening.",
    "Paper Acceptance: Congratulations! Your research paper submission has been accepted for presentation at the IEEE student conference. Registration instructions are below.",

    # Urgent academic & operational notices (Legitimate Ham)
    "Urgent Academic Reminder: Tomorrow is the final deadline for course registration add/drop. Please verify your selected elective courses with your faculty advisor immediately.",
    "Urgent Notice: The campus library will close early today at 5 PM due to severe weather conditions. All borrowed materials due today will be automatically renewed.",
    "Urgent Action Required: Please submit your signed internship verification form to the department office by 4 PM today to avoid grading delays.",
    "Exam Schedule Urgent Update: The venue for the Operating Systems midterm exam has been moved from Hall A to Room 304. Please inform your classmates.",
    "Urgent Lab Notice: All students must back up their project code from the lab workstations before Friday maintenance when machines will be formatted.",

    # Claims, travel & expense reimbursements (Legitimate Ham)
    "Expense Claim Approved: Your travel reimbursement claim #CLM-401 for attending the conference has been verified and approved by the finance department.",
    "Lost and Found Claim: A black backpack was turned in to campus security. If this is yours, you can claim your property at the student center security desk with valid ID.",
    "Health Insurance Claim Status: Your claim for the medical consultation on Sept 14 has been processed. Claim statement is available on the student wellness portal.",
    "Warranty Claim Confirmation: Your replacement battery request has been verified and shipped under warranty. No payment is required for this replacement.",

    # Limited availability & deadline reminders (Legitimate Ham)
    "Limited Seats Available: Registration for the Deep Learning Hands-on Workshop is now open. Seats are limited to 40 participants on a first-come, first-served basis.",
    "Limited Availability: The department has 10 complimentary student passes available for the tech summit. Reply to this email if you would like to attend.",
    "Limited Time Library Access: Extended night study hours at the science library are available for a limited time during final examination week.",
    "Office Hours Limited Notice: Professor office hours will be limited to 1 hour this Thursday due to the faculty senate meeting. Please book a slot in advance."
]

# Generate variations to expand coverage
enhanced_ham = []
for msg in LEGITIMATE_CONTEXTUAL_HAM:
    enhanced_ham.append(msg)
    # Add light variations
    enhanced_ham.append(f"Department Notice: {msg}")
    enhanced_ham.append(f"{msg} Thank you for your cooperation.")

print(f"Generated {len(enhanced_ham)} rich contextual ham examples.")

# Build balanced dataset:
# Combine existing unique data from PDF with diverse contextual ham and spam
spam_rows = df_existing[df_existing["label"] == "spam"].copy()
ham_rows = df_existing[df_existing["label"] == "ham"].copy()

context_ham_df = pd.DataFrame([{"label": "ham", "message": m} for m in enhanced_ham])

# Repeat diverse contextual samples so the model has ample support for legitimate uses of these words
combined_ham = pd.concat([ham_rows, context_ham_df, context_ham_df, context_ham_df], ignore_index=True)

# Balance spam count to match ham count
num_ham = len(combined_ham)
combined_spam = spam_rows.sample(n=num_ham, replace=True, random_state=42).reset_index(drop=True)

final_df = pd.concat([combined_ham, combined_spam], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
print(f"Final balanced dataset shape: {final_df.shape}")
print(final_df["label"].value_counts())

final_df.to_csv("dataset_balanced.csv", index=False)
print("Saved to dataset_balanced.csv successfully!")
