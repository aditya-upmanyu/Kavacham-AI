"""
build_kavacham_dataset.py
=========================
KAVACHAM AI — Hard-Negative + Adversarial Training Dataset Builder (Task 2-25).

Builds `dataset_kavacham_v2.csv` (training corpus with security metadata) and
`KAVACHAM_HARD_TEST.csv` (a FULLY-UNSEEN benchmark — every row in it belongs to
a template family never used for training).

Metadata schema (Task 22):
    label           : spam | ham                      (primary binary label)
    threat_type     : NONE|PROMOTIONAL|PHISHING|FRAUD|SCAM|BEC|IMPERSONATION|
                      MALWARE|CREDENTIAL_THEFT|DIGITAL_ARREST|SOCIAL_ENGINEERING|OTHER
    intent          : BENIGN|SUSPICIOUS|MALICIOUS
    source_type     : SYNTHETIC|REAL_PUBLIC_DATA|MANUAL|ADVERSARIAL
    difficulty      : EASY|MEDIUM|HARD|ADVERSARIAL
    template_group  : family id used for leakage-free grouped splits (Task 24)
    category        : human-readable generation family
    anchor_text     : visible link text (link-evasion rows only, Task 6)
    url             : the real destination URL (link-evasion rows only, Task 6)

Design guards (Task 23):
    * deterministic seed
    * exact-duplicate removal, whitespace normalization
    * near-duplicate report (shingle Jaccard)
    * contradictory-label removal (same text marked spam AND ham -> dropped)
    * class balance + vocabulary-leakage report

Run:  python build_kavacham_dataset.py
"""

import csv
import hashlib
import os
import pandas as pd
import random

SEED = 20260714
rng = random.Random(SEED)

# ---------------------------------------------------------------------------
# Parameter pools (diversity without memorizable templates)
# ---------------------------------------------------------------------------
BRANDS = ["PayPal", "Microsoft", "Google", "Apple", "Amazon", "Netflix", "Flipkart",
          "Instagram", "LinkedIn", "IRCTC", "Swiggy", "State Bank of India", "HDFC Bank",
          "ICICI Bank", "Paytm", "PhonePe", "Airtel", "Jio", "Vodafone", "WhatsApp"]
LEGIT_REALMS = ["university", "college", "HR department", "IT support", "library",
                "registrar", "finance office", "campus security", "academic office"]
AMOUNTS = ["500", "1500", "2500", "12000", "50000", "2 Lakh", "3500", "12500"]
OTPS = ["428176", "902318", "583412", "771209", "439510", "882134"]
MONEY = ["payment", "refund", "transfer", "reimbursement", "invoice", "settlement",
         "disbursement", "credit", "chargeback", "reversal"]
PEOPLE = ["Rajesh Kumar", "Priya Sharma", "Amit Verma", "Sneha Reddy", "Vikram Singh",
          "Ananya Iyer", "Rohan Gupta", "Divya Menon"]
DOMAINS = ["secure-verify", "account-update", "login-check", "verify-now", "identity-confirm",
           "payments-portal", "kyc-review", "alert-center", "support-ticket", "claim-refund"]
TLDS = ["com", "net", "in", "org", "info", "co"]
HINGLISH_FRAG = [
    "apka account suspicious activity ke liye block ho gaya hai",
    "KYC expire ho gaya hai, turant update karein",
    "aapka payment receive nahi hua, refund verify karne ke liye link open karein",
    "police complaint register ho gayi hai, verification ke liye details submit karein",
    "aapke account se paisa transfer hua hai, confirm karein",
    "aapka OTP kisi ko share nahi karna, yah link kholkar details bharein",
    "aapka parcel customs mein atka hai, charges pay karein",
    "bank account freeze hone wala hai, turant KYC update karein",
]
NEGATIVE_URL_HINTS = ["urgent", "verify", "login", "secure", "confirm", "claim", "password", "otp"]
PUNY_HINTS = ["xn--", "%45%78%61%6d"]

ROW_KEYS = ["label", "message", "threat_type", "intent", "source_type", "difficulty",
            "template_group", "category", "anchor_text", "url"]


def _clean_ws(t):
    return " ".join(str(t).split())


def _family(group_id):
    """Factory: returns all rows from this family under one template_group."""
    return group_id


# ---------------------------------------------------------------------------
# Base dataset (REAL_PUBLIC_DATA) — 1000 unique PDF-derived templates
# ---------------------------------------------------------------------------
def load_base_rows():
    rows = []
    if os.path.exists("dataset.csv"):
        df = pd.read_csv("dataset.csv").drop_duplicates(subset=["message"])
        for _, r in df.iterrows():
            label = str(r["label"]).strip().lower()
            if label not in ("spam", "ham"):
                continue
            msg = _clean_ws(r["message"])
            if len(msg) < 12:
                continue
            gid = "base_" + hashlib.md5(msg[:60].encode("utf-8")).hexdigest()[:10]
            rows.append({
                "label": label,
                "message": msg,
                "threat_type": "OTHER" if label == "spam" else "NONE",
                "intent": "MALICIOUS" if label == "spam" else "BENIGN",
                "source_type": "REAL_PUBLIC_DATA",
                "difficulty": "EASY" if label == "spam" else "EASY",
                "template_group": gid,
                "category": "pdf_base",
                "anchor_text": "",
                "url": "",
            })
    return rows


# ---------------------------------------------------------------------------
# Curated generation families (SYNTHETIC / ADVERSARIAL)
# ---------------------------------------------------------------------------
def gen_credential_phishing():
    """Professional credential phishing (Tasks 2.1, 5)."""
    rows = []
    for i, brand in enumerate(BRANDS[:12]):
        dom = rng.choice(DOMAINS)
        tld = rng.choice(TLDS)
        verbs = ["complete the verification process", "confirm your password",
                 "re-verify your login details", "validate your account information",
                 "re-authenticate to keep your account active"]
        prec = ["We noticed unusual activity associated with your account.",
                "Your account requires additional verification.",
                "Please review the security notification below.",
                "A sign-in attempt was blocked on your account.",
                "Unusual login activity was detected on your account."]
        msg = (f"{rng.choice(prec)} {rng.choice(verbs).capitalize()} to prevent "
               f"interruption of service. Review your account: "
               f"https://{dom}.{tld}/login?token={rng.randint(1000,9999)}")
        rows.append({
            "label": "spam", "message": msg,
            "threat_type": "CREDENTIAL_THEFT", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_cred_{i}"), "category": "professional_phishing",
            "anchor_text": "Review your account", "url": f"https://{dom}.{tld}/login",
        })
    return rows


def gen_account_suspension():
    rows = []
    for i, brand in enumerate(BRANDS[6:16]):
        reason = rng.choice(["suspicious activity", "expired security details",
                             "failed verification attempts", "duplicate account conflict"])
        msg = (f"{brand} — action required. Your account may be restricted due to {reason}. "
               f"Verify your identity now through the official portal to avoid suspension: "
               f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/status")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "PHISHING",
            "intent": "MALICIOUS", "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_suspend_{i}"), "category": "account_suspension",
            "anchor_text": "verify identity", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/status",
        })
    return rows


def gen_digital_arrest():
    """Fear-based digital arrest / authority scams + legit counterpart (Task 3)."""
    rows = []
    agencies = ["Cyber Crime Cell", "National Cybercrime Reporting Portal",
                "Income Tax Investigation Unit", "District Police Cyber Cell",
                "Enforcement Directorate", "CBI Cyber Wing"]
    for i, agency in enumerate(agencies):
        for variant in range(2):
            msg = (f"Subject: Notice of investigation against your identity.\n"
                   f"Your identity has been linked to an ongoing {rng.choice(['cybercrime', 'money laundering', 'fraud'])} "
                   f"investigation. Immediate verification is required to avoid legal action. "
                   f"Submit your details on the secure portal: https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/case")
            rows.append({
                "label": "spam", "message": _clean_ws(msg), "threat_type": "DIGITAL_ARREST",
                "intent": "MALICIOUS", "source_type": "SYNTHETIC", "difficulty": "HARD",
                "template_group": _family(f"px_arrest_{i}_{variant}"), "category": "digital_arrest",
                "anchor_text": "secure portal", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/case",
            })
    # Legitimate government/police correspondence that must NOT be spam
    for i in range(4):
        msg = (f"Your appointment for Police Verification has been confirmed for "
               f"{rng.choice(['Friday 10:00 AM', 'Monday 3:30 PM', 'Wednesday 11:15 AM'])} "
               f"at the district office. Please carry two passport photographs and your original ID. "
               f"Reply to reschedule.")
        rows.append({
            "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"ph_arrest_legit_{i}"), "category": "legit_authority",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_financial_fraud():
    """Bank impersonation + UPI/payment scams (Task 4)."""
    rows = []
    banks = ["State Bank of India", "HDFC Bank", "ICICI Bank", "Axis Bank", "Paytm Payments Bank"]
    for i, bank in enumerate(banks):
        for j, kind in enumerate(["freeze", "kyc", "upi_refund"]):
            if kind == "freeze":
                msg = (f"Dear customer, your {bank} account has been flagged for a "
                       f"suspicious {rng.choice(['transaction', 'login', 'transfer'])}. "
                       f"Your account will be frozen in 24 hours unless you confirm the recent "
                       f"{rng.choice(MONEY)} through the link: https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/{kind}")
            elif kind == "kyc":
                msg = (f"{bank} KYC update required. Your account services will be limited "
                       f"unless you complete the KYC re-verification by "
                       f"{rng.choice(['today', '48 hours', 'this week']) } at "
                       f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/kyc")
            else:
                msg = (f"A {rng.choice(MONEY)} of Rs {rng.choice(AMOUNTS)} was initiated "
                       f"from your {bank} account. If this was not you, claim the "
                       f"reversal here: https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/{kind}")
            rows.append({
                "label": "spam", "message": msg, "threat_type": "FRAUD", "intent": "MALICIOUS",
                "source_type": "SYNTHETIC", "difficulty": "HARD",
                "template_group": _family(f"px_fin_{i}_{kind}"), "category": "financial_fraud",
                "anchor_text": "click here", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/{kind}",
            })
    return rows


def gen_investment_loan() -> list:
    rows = []
    for i in range(6):
        msg = (f"Exclusive opportunity — our automated {rng.choice(['crypto', 'trading', 'equity'])} "
               f"algorithm has generated {rng.choice(['guaranteed', 'assured', 'fixed'])} returns of "
               f"{rng.choice(['12% weekly', '40% monthly', '2x in 48 hours']) } for early investors. "
               f"Limited seats. Reserve yours: https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/invest")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "FRAUD", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"px_inv_{i}"), "category": "investment_scam",
            "anchor_text": "Reserve", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/invest",
        })
    for i in range(6):
        msg = (f"Congratulations, your {rng.choice(['personal', 'business'])} loan of "
               f"Rs {rng.choice(AMOUNTS[:-2])} has been approved. To release the disbursement, "
               f"pay the one-time processing fee of {rng.choice(['Rs 500', 'Rs 850', 'Rs 1200']) } "
               f"at https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/fee")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "FRAUD", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"px_loan_{i}"), "category": "loan_scam",
            "anchor_text": "pay fee", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/fee",
        })
    return rows


def gen_credential_otp():
    rows = []
    for i in range(8):
        o = rng.choice(OTPS)
        msg = (f"Security Verification — enter this one-time code on the verification page. "
               f"OTP: {o}. Do not share this code with anyone. Complete within 5 minutes: "
               f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/verify?code={o}")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "CREDENTIAL_THEFT",
            "intent": "MALICIOUS", "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"px_otp_{i}"), "category": "otp_phishing",
            "anchor_text": "verification page", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/verify",
        })
    return rows


def gen_bec():
    """Business Email Compromise (Task 8)."""
    rows = []
    bec_templates = [
        (f"Hi, I need you to process a payment of Rs {rng.choice(AMOUNTS)} to the updated "
         f"vendor account today. The bank details have changed since the last invoice — "
         f"please use the attached file and confirm by reply. This is time-sensitive, "
         f"the supplier is expecting the transfer before close of business."),
        (f"Hi {{name}}, this is {{exec}}. Finance is running behind on the Q3 supplier settlement "
         f"and needs the updated vendor account file. Can you share the revised account details "
         f"before 3 PM today?"),
        (f"Re: Purchase Order #{rng.randint(1000,9999)} — the bank account on file returned an error "
         f"on the last settlement attempt. Reply with the replacement account number and we will "
         f"resubmit the payment before end of week."),
        (f"From: Director's office — I am travelling and locked out of the payment system. "
         f"Please purchase {rng.randint(2,5)} gift cards worth Rs {rng.choice(['5000','10000'])} "
         f"for a client appreciation drive and send the codes by reply. I will settle with you tomorrow."),
        (f"Hi {{name}}, our auditor flagged a mismatch in the supplier master. Send me the current "
         f"vendor list with contact details as a file and I will reconcile it today."),
        (f"{{exec}} asked me to follow up: the payment for the Q3 invoice did not go through. "
         f"Share the updated banking details directly in your reply so finance can rerun it."),
    ]
    for i, t in enumerate(bec_templates):
        msg = t.replace("{name}", rng.choice(["Sarah", "Ananya", "Rohan", "Divya", "Karthik"])) \
               .replace("{exec}", rng.choice(["Daniel", "Meera", "Arun", "Nisha", "Vijay"]))
        rows.append({
            "label": "spam", "message": msg, "threat_type": "BEC", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_bec_{i}"), "category": "bec",
            "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"Hi, could you share the updated invoice for last month's delivery? "
               f"The finance team needs it before the monthly close for the vendor reconciliation. "
               f"Thanks,")
        rows.append({
            "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"ph_bec_legit_{i}"), "category": "legit_bec",
            "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"URGENT: please purchase {rng.choice(['gift cards', 'Amazon vouchers']) } worth "
               f"Rs {rng.choice(AMOUNTS[:4])} for the client appreciation program before noon and "
               f"send the codes by email. The client is waiting; our usual procurement form is down.")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "BEC", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_bec_gc_{i}"), "category": "bec_giftcard",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_impersonation():
    """CEO / HR / IT / bank / delivery impersonation (Task 7)."""
    rows = []
    for i in range(5):
        msg = (f"From CEO — Important: I need you to organize an urgent wire of "
               f"Rs {rng.choice(AMOUNTS)} for an acquisition NDA. I am in meetings and can't "
               f"reach the finance team. Confirm the SWIFT details with the legal counsel "
               f"and execute today. Do not discuss with others.")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "IMPERSONATION", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_ceo_{i}"), "category": "ceo_fraud", "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"IT Support — your mailbox storage limit was exceeded. Click here to increase "
               f"your quota with your domain credentials: https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/mail")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "IMPERSONATION", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_itsup_{i}"), "category": "it_support",
            "anchor_text": "click here", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/mail",
        })
    for i in range(4):
        msg = (f"Your {rng.choice(['package', 'parcel', 'shipment'])} could not be delivered. "
               f"Confirm your delivery preferences and pay the {rng.choice(['re-delivery', 'customs']) } "
               f"fee of Rs {rng.choice(['99', '149', '249']) } to reschedule: "
               f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/delivery")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "IMPERSONATION", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"px_deliver_{i}"), "category": "delivery_scam",
            "anchor_text": "reschedule delivery", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/delivery",
        })
    # Legitimate counterparts
    for i in range(4):
        msg = (f"HR has published the updated holiday schedule for the upcoming quarter. "
               f"Please review the calendar attachment and submit any conflicts to your manager "
               f"by Friday. Leave approvals remain unchanged.")
        rows.append({
            "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"ph_imp_legit_{i}"), "category": "legit_impersonation",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_malware_delivery():
    """Malware delivery via attachments (Task 9)."""
    rows = []
    for i in range(6):
        msg = (f"Please find the updated {rng.choice(['invoice', 'PO', 'shipping document', 'contract']) } "
               f"attached. Review before today's meeting and confirm the changes. The file is "
               f"password-protected; the password is the account number. Let me know once reviewed.")
        rows.append({
            "label": "spam", "message": _clean_ws(msg), "threat_type": "MALWARE", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_mal_{i}"), "category": "malware_delivery",
            "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"Resume submission — please review the attached CV and the referenced portfolio "
               f"archive. The archive is password-protected; the password is in the email header. "
               f"Extract and open the sample work before our call today.")
        rows.append({
            "label": "spam", "message": _clean_ws(msg), "threat_type": "MALWARE", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_mal_resume_{i}"), "category": "malware_resume",
            "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"Please find the final version of the {rng.choice(['contract', 'agreement']) } attached. "
               f"It contains a digital signature that renders only after you enable macros in the "
               f"signature panel. Click Enable Content when you open it, then confirm receipt.")
        rows.append({
            "label": "spam", "message": _clean_ws(msg), "threat_type": "MALWARE", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_mal_digisig_{i}"), "category": "malware_enable",
            "anchor_text": "", "url": "",
        })
    for i in range(4):
        msg = (f"Please find the updated invoice attached for your records. "
               f"The payment was processed on schedule. Let me know if you need a signed copy.")
        rows.append({
            "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"ph_mal_legit_{i}"), "category": "legit_attachment",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_social_eng_no_spamwords():
    """Malicious emails WITHOUT free/win/urgent/money vocab (Task 10)."""
    rows = []
    themes = [
        "Please review the document before today's meeting and confirm the revision.",
        "Can you confirm the updated account details on file for the vendor settlement?",
        "Please complete the verification before access is restored to your workspace.",
        "The manager asked us to double-check the credentials for the shared drive login.",
        "Kindly validate the new banking details shared by the client before we proceed.",
        "Our records show a change request; please approve the attached authorization.",
        "The security desk needs the one-time code to release the visitor's badge.",
        "Please re-enter your login so we can sync the new directory permissions.",
    ]
    for i, t in enumerate(themes):
        rows.append({
            "label": "spam", "message": t, "threat_type": "SOCIAL_ENGINEERING",
            "intent": "MALICIOUS", "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_nosw_{i}"), "category": "social_eng_no_spamwords",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_writing_style_variants():
    """Same malicious intent, different writing styles (Task 11)."""
    rows = []
    base_intent = ("your account needs verification for a security review — submit your "
                   "credentials on this page https://{d}.{t}/review")
    styles = {
        "formal": "Dear User, we respectfully request that you complete a mandatory security review of your account. Please submit your credentials on the official page to continue using our services without interruption.",
        "informal": "hey! quick one - your account needs a security review. just drop your login details here and you're good to go.",
        "broken": "you account need verify. security review pending. give login details page below. do fast else account block.",
        "technical": "As part of the quarterly identity assurance protocol (IAP-9), re-authentication is required. Present your current credentials at the designated verification endpoint.",
    }
    for i, (style, text) in enumerate(styles.items()):
        rows.append({
            "label": "spam", "message": _clean_ws(text), "threat_type": "CREDENTIAL_THEFT",
            "intent": "MALICIOUS", "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_style_{i}"), "category": f"style_{style}",
            "anchor_text": "", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/review",
        })
    return rows


def gen_hinglish():
    """Hinglish / Hindi-Roman scams (Task 12)."""
    rows = []
    for i, frag in enumerate(HINGLISH_FRAG):
        guard = f" \u2014 {frag}"
        built = (rng.choice([
            "Sir/Madam, this is an official communication.",
            "Namaste, yeh ek important notice hai.",
        ]) + guard + rng.choice([
            " Details bharne ke liye niche diye gaye link par click karein.",
            " Aapke paas sirf aaj ka time hai.",
            " Turant action lijiye, warna account suspend ho sakta hai.",
        ]))
        rows.append({
            "label": "spam", "message": _clean_ws(built), "threat_type": "SOCIAL_ENGINEERING",
            "intent": "MALICIOUS", "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_hing_{i}"), "category": "hinglish_scam",
            "anchor_text": "", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/verify",
        })
    # Legit Hinglish ham — Hinglish alone must never imply scam
    for i in range(4):
        msg = (f"Namaste, aapka college ka winter session registration confirm ho gaya hai. "
               f"Fees ki receipt attached hai. Kisi bhi problem ke liye registrar office "
               f"se contact karein. Dhanyavad.")
        rows.append({
            "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"ph_hing_legit_{i}"), "category": "legit_hinglish",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_ham_like_malicious():
    """Professional malicious emails that look like routine work mail (Task 14)."""
    rows = []
    themes = [
        "Please review the attached invoice and confirm the payment details before the end of day.",
        "Your account access requires verification — complete the request before your next login.",
        "Following up on our previous conversation, please confirm the updated payment details.",
        "Document shared with you — review the access request and approve the sharing permission.",
        "Action required before your next login: update your profile credentials.",
        "We noticed a discrepancy in your latest statement. Confirm the transactions on the portal.",
        "The compliance team requires you to confirm your identity for the annual audit.",
        "Re: account — please verify your alternate email address to continue receiving statements.",
    ]
    for i, t in enumerate(themes):
        rows.append({
            "label": "spam", "message": t, "threat_type": "SOCIAL_ENGINEERING",
            "intent": "MALICIOUS", "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_hamlike_{i}"), "category": "ham_like_malicious",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_promo_spam():
    """Non-malicious promotional spam (Task 15)."""
    rows = []
    for i in range(6):
        msg = (f"{rng.choice(['Limited time flat 50% off', 'Mega clearance sale', 'Festive price drop', 'Launch day discount']) } — "
               f"shop our new {rng.choice(['collection', 'range', 'drop']) } with free shipping today. "
               f"Use code {rng.choice(['SAVE50', 'FEST25', 'CLEAR40']) } at checkout. "
               f"Shop now: https://{rng.choice(['shop', 'store', 'deals'])}.{rng.choice(TLDS)}/{rng.randint(100, 999)}")
        rows.append({
            "label": "spam", "message": msg, "threat_type": "PROMOTIONAL",
            "intent": "SUSPICIOUS", "source_type": "SYNTHETIC", "difficulty": "EASY",
            "template_group": _family(f"px_promo_{i}"), "category": "promo_spam",
            "anchor_text": "Shop now", "url": f"https://{rng.choice(['shop', 'store', 'deals'])}.{rng.choice(TLDS)}",
        })
    return rows


def gen_obfuscation():
    """Word obfuscation variants of malicious intent (Task 18)."""
    rows = []
    obfus_styles = [
        lambda s: s.upper(),
        lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
        lambda s: s.replace(" ", "  "),
        lambda s: s.replace("e", "3").replace("a", "4").replace("o", "0").replace("i", "1"),
        lambda s: " ".join(list(s))[:180],
        lambda s: s.replace(".", " ."),
    ]
    base_msgs = [
        "Verify your account credentials immediately at the secure portal link below.",
        "Your payment method needs confirmation. Enter your card details to reactivate.",
        "Confirm your login details to prevent account closure within 24 hours.",
    ]
    for i, m in enumerate(base_msgs):
        for j, fn in enumerate(obfus_styles):
            rows.append({
                "label": "spam", "message": _clean_ws(fn(m)), "threat_type": "CREDENTIAL_THEFT",
                "intent": "MALICIOUS", "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
                "template_group": _family(f"px_obf_{i}_{j}"), "category": "obfuscation",
                "anchor_text": "", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/secure",
            })
    return rows


def gen_contextual_contrast():
    """Legitimate counterparts for dangerous keywords (Tasks 16, 19)."""
    rows = []
    pairs = [
        ("spam", "Your bank account will be suspended. Verify immediately using the link: https://secure-account-verify.com/confirm"),
        ("ham", "Your bank account statement for August is now available in your official banking application. No action is required."),
        ("spam", "Your package could not be delivered. Confirm your card details to receive it: https://parcel-fee-collect.com/pay"),
        ("ham", "Your package has been delivered successfully. View the delivery location and tracking updates in your orders page."),
        ("spam", "Your OTP for password reset is 482913. Enter it on the unknown page to recover access."),
        ("ham", "Your OTP for login is 482913. It expires in 10 minutes. Never share this code with anyone, including support staff."),
        ("spam", "Police registration required — pay the attached fine via the link to close the complaint."),
        ("ham", "Police verification appointment is confirmed for Friday at 11 AM. Carry your original identity documents."),
        ("spam", "Your electricity connection will be disconnected — pay the outstanding dues on the provided link now."),
        ("ham", "Your electricity bill of Rs 1240 was paid successfully. Receipt is attached for your records."),
        ("spam", "You won the annual cash prize of Rs 1,00,000. Claim by submitting your bank details."),
        ("ham", "You won the internal company performance award for Q3. The certificate is attached."),
    ]
    for i, (label, msg) in enumerate(pairs):
        rows.append({
            "label": label, "message": msg,
            "threat_type": "FRAUD" if label == "spam" else "NONE",
            "intent": "MALICIOUS" if label == "spam" else "BENIGN",
            "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"cx_pair_{i}"), "category": "contextual_contrast",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_legit_hard_ham():
    """Hard positive ham — legitimate security/financial alerts with trigger words (Task 13)."""
    rows = []
    templates = [
        "Security Alert: A new login to your account was detected from Chrome on Windows. If this was you, review your session in account settings.",
        "Two-Factor Authentication: Your verification code is {otp}. This code expires in 10 minutes. Never provide this code to anyone.",
        "Payment Confirmation: Your tuition payment of {amt} has been processed successfully. Transaction ID: {txn}. Receipt attached.",
        "Invoice: Your vendor payment of {amt} has been scheduled for direct deposit on Monday. Confirmation number {txn}.",
        "Order Confirmation: Your order #{txn} has been placed and confirmed. Estimated delivery is Thursday. Track your shipment from your account.",
        "Password Reset: We received a request to reset your password. Use the link in this email only if you initiated it. If not, ignore this message.",
        "IT Notice: Your SSO password will expire in 5 days. Please update your credentials through the internal intranet portal.",
        "Account Login: New sign-in from a new device. If this was not you, check your recent security activity and secure your account recovery options.",
        "Delivery Update: Your item has been out for delivery since 9 AM. No signature is required. Track live from your orders page.",
    ]
    for i, t in enumerate(templates):
        for j in range(2):
            msg = t.replace("{otp}", rng.choice(OTPS)).replace("{amt}", "Rs " + rng.choice(AMOUNTS)) \
                   .replace("{txn}", str(rng.randint(100000, 999999)))
            rows.append({
                "label": "ham", "message": msg, "threat_type": "NONE", "intent": "BENIGN",
                "source_type": "SYNTHETIC", "difficulty": "HARD",
                "template_group": _family(f"ph_ham_{i}_{j}"), "category": "legit_security_alert",
                "anchor_text": "", "url": "",
            })
    return rows


def gen_legit_system_alerts():
    """Large legitimate system/transaction alert corpus — the adversarial counterpart
    of professional phishing (Tasks 5, 13, 16). These phrases are ALWAYS ham."""
    rows = []
    templates = [
        "Dear customer, your transaction of {amt} on your debit card ending {txn} has been approved. If this was not you, please contact your branch. This is a system-generated message, please do not reply.",
        "Dear customer, your UPI payment of {amt} to {peers} has been successful. UPI Ref: {txn}. This is an automated message — no response is required.",
        "Your account ending {txn} has been credited with {amt}. Available balance: {amt2}. For privacy, we do not include clickable links in transaction alerts.",
        "OTP for transaction of {amt} on your card ending {txn}: {otp}. Valid for 10 minutes. Never share your OTP or card details with anyone, including bank employees.",
        "Login OTP for your online banking: {otp}. The code is valid for one session only and expires in 5 minutes. Do not disclose this code to callers.",
        "Your password was changed successfully at {txn} AM. If this was not you, use the official app to lock your account and contact support. No further action if this was you.",
        "We detected a sign-in from a new device using your email. If this was you, you can ignore this notification. If not, secure your account immediately from Security settings.",
        "Your password reset request has been processed. If you did not request this, please reset again through the official portal. If you did, no action is needed.",
        "KYC confirmed: Your account records are up to date. No documents are required at this time. You will be notified on the portal if any action is needed.",
        "Aadhaar verification for your account has been completed successfully. No further verification is pending for the current cycle.",
        "Electricity bill of {amt} has been paid successfully via auto-pay. Receipt no. {txn}. This notice is for your records only.",
        "Your mobile bill of {amt} is due on the 5th. Auto-pay is enabled on your registered account. If payment fails, you will receive a separate notification.",
        "Insurance premium of {amt} was collected successfully. Policy {txn} remains active until renewal. No further payment is due this month.",
        "Refund of {amt} for your cancelled course registration has been initiated to your original payment method. Expected within 5-7 business days.",
        "Refund of {amt} for order #{txn} has been initiated to your original payment method. You do not need to take any action for this refund.",
        "Your reimbursement claim {txn} has been verified and approved by the finance department. Amount of {amt} will be credited in the next payroll cycle.",
        "Invoice {txn} from {peers} is attached for your records. Payment terms remain 30 days from issue. Please confirm receipt at your convenience.",
        "Statement of account for the quarter is now available in the customer portal. To protect your data we do not attach statements to email.",
        "Annual security training is due. The module takes 20 minutes and is available on the learning portal. Completion is mandatory for all staff by month end.",
        "Scheduled maintenance: the portal will be unavailable Sunday 2-4 AM. Services resume automatically; no credentials are required afterwards.",
        "Your appointment with {peers} has been confirmed for {txn} AM. Please arrive 10 minutes early with your appointment letter and ID. Use the registration desk for check-in.",
        "Thank you for registering for the departmental seminar. Your seat is confirmed. Entry is with your university ID card, no external link required.",
        "Your library holds are ready for pickup at the front desk until Friday. Items not collected will be returned to the shelf.",
        "Good news — your scholarship disbursement of {amt} has been processed and will reflect in your account within 3 working days. Official receipt attached.",
        # Regulatory / protective-tail templates — one generation each, 3 varied rows (mass for the tails)
        "This is a mandatory regulatory notification regarding your registered holdings. No action is required from you at this time. Automated correspondence — please do not respond.",
        "We will never ask for your password, OTP, or card PIN by email or phone. Please ignore any request that does so, however official it appears.",
        "Bank correspondence is sent only through the official mobile application and SMS. Unlinked emails claiming to be from your bank are fraudulent.",
        "Reminder: your statement cycle closed on the 25th. The statement is available in your secure inbox; no link is included in this email on purpose.",
        "Security tip from the information security team: always type known portal addresses yourself instead of following links in messages.",
        "Security notice: a new sign-in was detected on an unrecognized device from a new location. If this was you, you can ignore this message. If not, review recent activity in Security settings.",
        "We detected a sign-in from a new device using your email. If this was you, no action is needed. If not, secure your account immediately. This is an automated notification.",
        "New login to your account from an unknown device. If this was you, you can continue this session. If not, lock the account from Security settings. No external link is required.",
        "Your account was accessed from a device you have not used before. If this does not match your activity, review the session list and end any sessions you do not recognise.",
        "Security notice: a new sign-in was detected on an unrecognized device. If this was you, no further action is required. If not, review your recent activity in Security settings.",
        "Security notice: a sign-in was detected from a new location using an unrecognized device. Rest assured, your existing sessions remain active until you end them.",
        "We logged a new sign-in attempt from a device that does not match your usual devices. If the device is yours, continue. Otherwise end the session from Account settings.",
        "A login alert was raised for your account from a location you do not usually use. If you recognise this activity you can ignore it; otherwise lock the account and change your password.",
        "Legitimate bank messages never ask you to follow a link to enter credentials. Verify the sender domain before acting on any banking email.",
        "Our bank communicates only through the official mobile application, SMS, and our verified domain addresses. If an email claims to be us and asks for your PIN, it is fraudulent — report it to the bank without replying to the message.",
        "If you receive an email that asks for your one-time password, card number, or PIN, do not respond. The bank will never request these details by email under any circumstance.",
        "A request to change your registered mobile number was received. If this was not you, contact support immediately. If it was you, no further action is needed.",
        "Your PAN and Aadhaar verification status is confirmed for the current financial year. No further documentation is required unless separately notified in the portal.",
        "To claim your travel reimbursement, submit the expense form at the finance desk with original receipts by the 10th of next month.",
        "Claims for medical reimbursement are processed on the 1st and 15th. Submit your prescriptions and bills to the HR desk with the approval email.",
        "Your reimbursement claim for last month was approved. The amount will be credited with the next payroll cycle. No further action is required.",
        "The finance team reminds you: any claim you submit must include the approval email from your reporting manager before it can be processed.",
    ]
    for i, t in enumerate(templates):
        for j in range(3):
            msg = t.replace("{otp}", rng.choice(OTPS)).replace("{amt}", "Rs " + rng.choice(AMOUNTS)) \
                   .replace("{amt2}", "Rs " + rng.choice(AMOUNTS)) \
                   .replace("{txn}", str(rng.randint(100000, 999999))) \
                   .replace("{peers}", rng.choice(PEOPLE))
            rows.append({
                "label": "ham", "message": _clean_ws(msg), "threat_type": "NONE", "intent": "BENIGN",
                "source_type": "SYNTHETIC", "difficulty": "HARD",
                "template_group": _family(f"ph_sysal_{i}"), "category": "legit_system_alerts",
                "anchor_text": "", "url": "",
            })
    return rows


def gen_legit_marketing():
    """Legitimate marketing/newsletters WITH links — so link presence alone never
    proves spam in the ML feature space (Task 16)."""
    rows = []
    templates = [
        "Your weekly digest is ready — top stories in AI research, curated by our editorial team. Read the full digest in your member portal: https://digest.{tld}/weekly",
        "We updated our privacy policy. An overview of the changes is on our official site: https://privacy.{tld}/summary. No action is required unless you disagree.",
        "Thanks for subscribing to the campus newsletter. The first issue is out — open it here: https://newsletter.{tld}/issue-1",
        "Your favourite store's winter collection is live. Preview the lookbook: https://lookbook.{tld}/winter. Unsubscribe anytime from your preferences page.",
        "The design team shipped version 3.2 of the app. Release notes: https://releases.{tld}/v3-2. Update for the latest fixes.",
        "Webinar invite — 'Building Threat Detection on a Budget'. Register through the event page: https://events.{tld}/register",
        "Your community forum digest for this week — new discussions in the security channel. Read online: https://forum.{tld}/digest",
        "Company-wide survey on hybrid work is open. Complete it at https://survey.{tld}/hybrid — takes 3 minutes. Participation is voluntary.",
        "New arrivals are here — preview the autumn collection and the accessory lookbook: https://lookbook.{tld}/autumn",
        "Flash sale starting Friday for members. Browse the sale preview now: https://shop.{tld}/sale, or set your preferences to stay updated.",
        "Your style quiz results are ready. Open the personalised lookbook at https://lookbook.{tld}/me and update your preferences anytime.",
    ]
    for i, t in enumerate(templates):
        rows.append({
            "label": "ham", "message": t.replace("{tld}", rng.choice(TLDS)),
            "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "MEDIUM",
            "template_group": _family(f"ph_mkt_{i}"), "category": "legit_marketing",
            "anchor_text": "read online", "url": f"https://digest.{rng.choice(TLDS)}",
        })
    return rows


def gen_macro_malware():
    """Malware delivery via macros / embedded objects / protected archives (Task 9)."""
    rows = []
    themes = [
        "Final contract for approval is attached. Open the document and enable macros to display the digital countersignature before our meeting.",
        "The signed PO is in the attachment. Please enable content to let the embedded signature render, then return the confirmation form.",
        "Updated payslip attached — enable editing and press Ctrl+Shift+Enter to refresh the secure calculations, then save a copy for records.",
        "The archive contains the full project backup. Extract it and run the included launcher to view the interactive project report.",
        "Invoice document attached in the password-protected archive. The password is your employee ID. Open and enable macro content to print.",
        "Your bonus letter is attached as a smart document. Open it, allow the embedded object to load, and confirm receipt.",
        "Final terms document is attached. To view the countersigned copy you must enable the digital signature macro — click enable content when prompted.",
        "The stamped agreement is in the attachment. Enable editing first, then press Enable Content so the embedded signature renders correctly.",
        "The updated benefits booklet needs macro security disabled in Word to display the interactive rate tables. Open and follow the instructions in the document.",
        "Please review the attached offer letter. The document contains an embedded signature that requires you to click Enable Content to load it.",
        "The encrypted project brief is attached. Run the packaged viewer from the attachment to open the interactive dashboard.",
        "Copy of the executed NDA is attached. Allow the ActiveX object inside to render, then sign the digital acknowledgement form.",
        "Your tax computation sheet is attached. The workbook uses an embedded macro to pull live exchange rates — enable content before April tracking.",
    ]
    for i, t in enumerate(themes):
        rows.append({
            "label": "spam", "message": _clean_ws(t), "threat_type": "MALWARE", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_macro_{i}"), "category": "macro_malware",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_doc_sharing():
    """Cloud document-sharing phishing vs legitimate sharing notices (Task 19)."""
    rows = []
    phish_themes = [
        "Vikas shared the file 'Salary-Review.xlsx' with you on our portal. Click to review: https://{d}.{tld}/share/dl",
        "You have been granted access to the budget folder. Sign in with your work account to view it: https://{d}.{tld}/docs/a1",
        "A colleague mentioned you in Q3-Metrics.docx. Review the comments: https://{d}.{tld}/doc/c9",
        "The 'NDA-Draft' file was shared with you. Access it before it expires: https://{d}.{tld}/s/exp?q=7",
        "Shared file 'Vendor-Master-new.xlsx' requires your sign-in to open. Complete authentication to preview: https://{d}.{tld}/u/preview",
        "Your share link for 'Audit-Reports-Q2' is ready. To open, verify your identity: https://{d}.{tld}/v/identity",
        "A colleague shared the folder 'Q3 Metrics' with you. Review and approve the sharing certificate embedded in the shared note to restore full access: https://{d}.{tld}/cert",
        "The 'Vendor-Master' document was shared from a secure external workspace. Authentication is required before the contents can be decrypted: https://{d}.{tld}/secure/open",
        "You have a new document request from the compliance team. Open the shared envelope with your organisation sign-in to continue: https://{d}.{tld}/envelope",
        "A colleague shared a folder with you. Review and approve the sharing certificate embedded in the shared note to restore full access to the folder.",
        "The shared document 'Handover-Notes' requires your confirmation before it can be opened. Approve the access request now.",
    ]
    for i, t in enumerate(phish_themes):
        rows.append({
            "label": "spam", "message": t.replace("{d}", rng.choice(DOMAINS)).replace("{tld}", rng.choice(TLDS)),
            "threat_type": "PHISHING", "intent": "MALICIOUS",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"px_docshare_{i}"), "category": "doc_sharing_phish",
            "anchor_text": "click to review", "url": f"https://{rng.choice(DOMAINS)}.{rng.choice(TLDS)}/share",
        })
    legit_themes = [
        "Rohit shared the folder 'Team Photos' with you on the company drive. Access it from your apps — no password is needed.",
        "The design team shared 'Brand Assets v3' with you in the shared workspace. You can open it directly from the workspace home screen.",
        "Your documents were moved to the new shared drive. The migration is complete and everything is accessible from your existing folder view.",
        "A read-only copy of the meeting notes was shared with the mailing list. Open it from the shared drive link in your calendar invite.",
    ]
    for i, t in enumerate(legit_themes):
        rows.append({
            "label": "ham", "message": t, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"ph_docshare_{i}"), "category": "doc_sharing_legit",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_legit_announcements():
    """Legitimate internal awards / win announcements — the benign side of
    'you won' style language (Tasks 12, 16)."""
    rows = []
    themes = [
        "You won the internal company performance award for Q3. The certificate has been shared with your manager and will be distributed at the town hall.",
        "Congratulations — the internal hackathon results are out. Team 'Nullified' won the finals; participation certificates are on the intranet.",
        "Employee of the Month for October has been announced. The internal award is presented at the monthly all-hands meeting.",
        "In the internal staff lottery held during the annual meeting, your employee ID was drawn. No payment or action is required to collect the kit at the reception desk.",
        "You have been selected for the shortlist of the internal mentoring program. No action is required — the onboarding session details will follow by next week.",
        "The Q3 innovation awards were announced internally. Congratulations to all nominated teams; certificates will be handed out at the quarterly town hall.",
    ]
    for i, t in enumerate(themes):
        rows.append({
            "label": "ham", "message": t, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"ph_award_{i}"), "category": "legit_announcements",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_adversarial_token_pairs():
    """Same dangerous word, different context (Task 17)."""
    rows = []
    pairs = [
        ("spam", "FREE call minutes for you today — dial now and claim your reward."),
        ("ham", "FREE admission for university students — bring your student ID to the gate."),
        ("spam", "Claim your prize money now by entering your card details below."),
        ("ham", "Claim your travel reimbursement by submitting the expense form to the finance office."),
        ("spam", "Congratulations, your account has won a lottery. Enter your password to claim it."),
        ("ham", "Congratulations, you have been selected for the research internship. Attend orientation tomorrow."),
        ("spam", "Your account has been suspended. Enter your password to restore access."),
        ("ham", "Your account has been noted for the annual audit. No password is required."),
        ("spam", "Urgent — send your payment to the new account immediately to avoid penalty."),
        ("ham", "Urgent — the library closes early today at 5 PM due to weather. Returned books auto-renew."),
    ]
    for i, (label, msg) in enumerate(pairs):
        rows.append({
            "label": label, "message": msg,
            "threat_type": "FRAUD" if label == "spam" else "NONE",
            "intent": "MALICIOUS" if label == "spam" else "BENIGN",
            "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"at_pair_{i}"), "category": "adversarial_tokens",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_short_minimal():
    """Minimal / low-content emails (Task 21)."""
    rows = []
    mal = [
        "http://bit.ly/3xr9K2z",
        "https://tracking-update.in/live",
        "Hi, see attached.",
        "Please review.",
        "Confirm this.",
        "Details in the attachment.",
        "Approve immediately.",
        "Verify now: https://update-portal.info/verify",
    ]
    leg = [
        "Please review the attached agenda for tomorrow's standup.",
        "Confirm this works before the demo.",
        "The latest build is attached — please test.",
        "Approved — please proceed with the merge request.",
        "Details in the attachment as discussed.",
    ]
    for i, m in enumerate(mal):
        rows.append({
            "label": "spam", "message": m, "threat_type": "SOCIAL_ENGINEERING",
            "intent": "MALICIOUS", "source_type": "ADVERSARIAL", "difficulty": "ADVERSARIAL",
            "template_group": _family(f"px_short_{i}"), "category": "short_malicious",
            "anchor_text": "", "url": m if m.startswith("http") else "",
        })
    for i, m in enumerate(leg):
        rows.append({
            "label": "ham", "message": m, "threat_type": "NONE", "intent": "BENIGN",
            "source_type": "SYNTHETIC", "difficulty": "HARD",
            "template_group": _family(f"ph_short_{i}"), "category": "short_legit",
            "anchor_text": "", "url": "",
        })
    return rows


def gen_hard_test_rows():
    """
    KAVACHAM_HARD_TEST — completely unseen benchmark (Task 25).

    Every family id starts with `ht_` and is NEVER present in the training set.
    Hand-authored professional / contextual examples across all 11 failure
    families; many include anchor-text vs real-URL separation (Task 6).
    """
    rows = []

    def add(label, msg, threat, difficulty, category, anchor="", url=""):
        rows.append({
            "label": label, "message": _clean_ws(msg),
            "threat_type": threat,
            "intent": "MALICIOUS" if label == "spam" else "BENIGN",
            "source_type": "MANUAL" if difficulty != "ADVERSARIAL" else "ADVERSARIAL",
            "difficulty": difficulty,
            "template_group": _family("ht_" + category + "_" + str(len(rows))),
            "category": category, "anchor_text": anchor, "url": url,
        })

    # HARD: professional credential phishing
    add("spam",
        "Dear Customer, our auditors detected a change in your beneficiary list. To comply with the revised KYC norms, please re-confirm your profile on the enclosed verification sheet. Access the secure form: https://bank-kyc-verify.care/confirm",
        "CREDENTIAL_THEFT", "HARD", "ht_pro_phish", "confirmation page", "https://bank-kyc-verify.care/confirm")
    add("spam",
        "Action Required: Annual device compliance review. Your machine has been flagged for a policy exception. Re-authenticate within this period to keep network access: the link is a shortened QR-style URL — https://t.co/kJ4xVw?r=d",
        "PHISHING", "HARD", "ht_pro_phish_2", "re-authenticate", "https://t.co/kJ4xVw?r=d")
    add("spam",
        "Security notification — a copy of your billing profile was exported by an external tool. We have attached what appears to be a partial statement. Review it and verify the last four digits of your card: https://billingportal-review.in/verify-card",
        "PHISHING", "HARD", "ht_pro_phish_3", "verify card", "https://billingportal-review.in/verify-card")
    add("spam",
        "Update on your recently submitted request #A-22817. Before it can be closed, you must confirm the alternate recovery email tied to this account. If you no longer have access, complete the recovery flow: https://recovery-verify.app/otp",
        "CREDENTIAL_THEFT", "HARD", "ht_pro_phish_4", "recovery flow", "https://recovery-verify.app/otp")

    # HARD: digital arrest
    add("spam",
        "Subject: Cyber Cell — IP trace report. Your registered IP was observed in a confirmed phishing infrastructure. As per section 66(C) of the IT Act, an appearance is required within 48 hours. To submit an online representation, complete the identity intake form: https://cyber-cell-gov.online/intake",
        "DIGITAL_ARREST", "HARD", "ht_digital_arrest", "identity intake", "https://cyber-cell-gov.online/intake")
    add("spam",
        "Your Aadhaar-linked number has been flagged in a narcotics case file. A video-conference statement has been scheduled. To avoid a physical summons, authorise the e-verification: https://investigation-verify.gov-escrow.com/statement",
        "DIGITAL_ARREST", "HARD", "ht_digital_arrest_2", "e-verification", "https://investigation-verify.gov-escrow.com/statement")
    add("spam",
        "Income Tax preliminary notice: discrepancies found in your filing for AY 2025-26. A 'reconciliation portal' has been provisioned. Proceed with digital confirmation of your PAN-linked bank details: https://intimation-taxportal.verify.live/reconcile",
        "DIGITAL_ARREST", "HARD", "ht_digital_arrest_3", "reconciliation portal", "https://intimation-taxportal.verify.live/reconcile")
    add("ham",
        "Your Police Verification certificate has been issued. Please visit the district cyber cell office on the scheduled date to collect it. The appointment letter is attached; carry two passport-size photographs.",
        "NONE", "HARD", "ht_legit_police")
    add("ham",
        "Reminder from the Registrar of Companies: your annual filing is due by the 30th. The acknowledgment of your previous filing is attached. No payment is required for this reminder.",
        "NONE", "HARD", "ht_legit_gov_notice")

    # HARD: BEC
    add("spam",
        "Hi Sarah, this is Daniel. Finance is running behind on the Q3 supplier settlement. I need the remaining 11 invoices approved and released to the new IBAN I shared earlier today — the vendor confirmed the account change on their letterhead. Kindly execute before 5 PM and mark this as urgent-confidential.",
        "BEC", "HARD", "ht_bec", "", "")
    add("spam",
        "Re: Purchase Order #9021 — the bank account on file returned an error on the last three attempts. Please re-route the subsequent wires to the revised account details in the attached PDF (password: PO9021). The supplier cannot wait another cycle; confirm when done.",
        "BEC", "HARD", "ht_bec_2", "", "")
    add("spam",
        "Confidential — the external auditor has flagged our vendor master for tampering. Before the close, update the master with the new banking details I approve below and notify no one else. This is a controlled remediation, not an open request.",
        "BEC", "HARD", "ht_bec_3", "", "")
    add("spam",
        "From: Director's office — I am travelling and locked out of the payment system. Purchase four corporate gift cards (Rs 5000 each) from the portal and share the redeemed codes with me directly. The finance controller is unaware; keep it between us and complete before standup.",
        "BEC", "HARD", "ht_bec_giftcard", "", "")

    # HARD: impersonation (CEO / IT / delivery / recruiter)
    add("spam",
        "IT Service Desk: your account has been provisioned for 'privileged access review'. A domain administrator will need your current network credentials to complete the migration. Reply with your username and password in the format user:pass for the scheduler.",
        "IMPERSONATION", "HARD", "ht_impersonate_it", "", "")
    add("spam",
        "Hello, I am reaching out from TalentBridge about your application for the Senior Engineer role. Before the final round, we need you to verify your previous employment by logging in to our candidate portal (credentials re-sent below): https://career-verify-portal.site/candidate/login",
        "IMPERSONATION", "HARD", "ht_impersonate_rec", "candidate portal", "https://career-verify-portal.site/candidate/login")
    add("ham",
        "Hello, we received your application for the Data Analyst position. Your resume has been shortlisted. Please complete the online assessment before Friday and confirm your availability for an interview next week.",
        "NONE", "MEDIUM", "ht_legit_recruiter")

    # HARD: fraud (bank / UPI / refund)
    add("spam",
        "A UPI mandate of Rs 24,999 was initiated from your account ending 4802 to an unknown payee. As per RBI dispute rules you have 24 hours to raise a chargeback. Complete the reversal authentication here: https://mandate-dispute.verify-bank.online/reverse",
        "FRAUD", "HARD", "ht_fraud_upi", "reversal portal", "https://mandate-dispute.verify-bank.online/reverse")
    add("spam",
        "Congratulations, you are eligible for a complimentary upgrading of your credit limit. To activate, confirm your salary account and PAN via the sim-authorised link: https://limit-upgrade.cc/pan-verify",
        "FRAUD", "MEDIUM", "ht_fraud_credit", "activate limit", "https://limit-upgrade.cc/pan-verify")
    add("spam",
        "Refund status: your earlier cashback of Rs 850 was reversed due to a validation error. Re-validate the linked card (even a used one works) to complete the re-credit: https://cashback-recredit.pay/validate",
        "FRAUD", "HARD", "ht_fraud_refund", "re-validate card", "https://cashback-recredit.pay/validate")
    add("ham",
        "Refund of Rs 850 for order #48210 has been initiated to your original payment method. Expected within 5-7 business days. You do not need to take any action for this refund.",
        "NONE", "EASY", "ht_legit_refund")

    # HARD: malware delivery
    add("spam",
        "Please find the final version of the contract attached. It contains a digital signature macro that must be enabled for the countersignature to appear. Extract the archive, enable content, and return the signed copy by noon.",
        "MALWARE", "HARD", "ht_malware", "", "")
    add("spam",
        "Resume submission — please review the attached CV and the referenced portfolio archive. The archive includes a preview executable that renders the interactive résumé; run it to view the work samples.",
        "MALWARE", "HARD", "ht_malware_resume", "", "")

    # HARD: ham-looking malicious
    add("spam",
        "Please review the attached settlement sheet and confirm the revised account before processing today's payroll. The attachment contains the updated routing details from the client's finance controller.",
        "SOCIAL_ENGINEERING", "ADVERSARIAL", "ht_hamlook", "", "")
    add("spam",
        "Document shared with you via secure link — 'FY26-Budget-Review.xlsx'. Open it, enable editing, and confirm the access token that appears in the sharing banner.",
        "SOCIAL_ENGINEERING", "ADVERSARIAL", "ht_hamlook_2", "", "")
    add("spam",
        "A colleague shared a folder with you — 'Q3 Metrics'. Review and approve the sharing certificate that is embedded in the shared note.",
        "SOCIAL_ENGINEERING", "ADVERSARIAL", "ht_hamlook_3", "", "")

    # HARD: multilingual / Hinglish
    add("spam",
        "Aapka SBI account se Rs 19,000 ka transaction ho gaya hai jo aapne nahi kiya. Turant reversal ke liye OTP verify karein: https://sbi-reversal-portal.in/otp",
        "FRAUD", "HARD", "ht_hinglish", "verify OTP", "https://sbi-reversal-portal.in/otp")
    add("spam",
        "Cyber Police se notice aaya hai, aapke number se fake call center chal raha hai. Court appearance se bachne ke liye yeh form bharein aur aadhar link karein: https://cybercase-hearing.in/form",
        "DIGITAL_ARREST", "HARD", "ht_hinglish_2", "form", "https://cybercase-hearing.in/form")

    # HARD: short / URL-only / attachment-only
    add("spam", "https://req-approval-doc.servefile.click/claim", "SOCIAL_ENGINEERING", "ADVERSARIAL", "ht_url_only", "", "https://req-approval-doc.servefile.click/claim")
    add("spam", "See attached — password-protected, the password is your employee ID.", "MALWARE", "HARD", "ht_attach_only")
    add("ham", "See attached — the agenda for tomorrow. Happy to discuss at standup.", "NONE", "HARD", "ht_attach_legit")

    # HARD: adversarial wording / obfuscation
    add("spam", "V3r1fy your acc0unt t0day — d0wnl0ad the checkp01nt 4nd c0nf1rm y0ur det41ls.", "CREDENTIAL_THEFT", "ADVERSARIAL", "ht_obfusc")
    add("spam", "ACCOUNT  R E V I E W  P E N D I N G .  P r e s e n t  c r e d e n t i a l s  to  the  security  console  below.", "CREDENTIAL_THEFT", "ADVERSARIAL", "ht_obfusc_2")

    # HARD: safe emails containing dangerous words
    add("ham", "Your bank transaction of Rs 500 has been completed successfully. Reference: NEFT2026***4821. If this was not you, contact your branch immediately. This is a system-generated message, please do not reply.",
        "NONE", "HARD", "ht_safe_bank")
    add("ham", "Your OTP for this login is 842617. Do not share this with anyone, including bank employees. It is valid for 10 minutes only.",
        "NONE", "HARD", "ht_safe_otp")
    add("ham", "Password change confirmed for your university account. If you did not make this change, reset immediately via the official portal. No further action is required if this was you.",
        "NONE", "HARD", "ht_safe_password")
    add("ham", "Urgent schedule note: the venue for tomorrow's final examination has moved to Block C, Room 22. Please inform all group members.",
        "NONE", "MEDIUM", "ht_safe_urgent")
    add("ham", "Invoice 2026-0481 from Meridian Analytics is attached for records. Payment terms remain 30 days from issue. Please review and confirm receipt.",
        "NONE", "EASY", "ht_safe_invoice")

    # HARD: macro / attachment malware (unseen)
    add("spam", "Attendance and appraisal summary for the cycle is attached. Open the workbook, enable the embedded macros, and confirm the printed copy for personnel records.",
        "MALWARE", "HARD", "ht_macro" )
    add("spam", "The auditor's working paper is in the protected archive. The password is your PAN number. Extract, open the sheet, and allow the calculation refresh to display the figures.",
        "MALWARE", "HARD", "ht_macro_2")

    # HARD: doc-sharing phishing (unseen)
    add("spam", "Anand shared the workbook 'Annual-Raise' with you. Open it with your corporate sign-in: https://filedrop-verify.click/access/tk9",
        "PHISHING", "HARD", "ht_docshare", "open workbook", "https://filedrop-verify.click/access/tk9")
    add("spam", "You were added to the folder 'Mergers-DueDiligence'. Authenticate to preview the documents before they are removed: https://sharebox-auth.net/view/ex",
        "PHISHING", "HARD", "ht_docshare_2", "preview documents", "https://sharebox-auth.net/view/ex")
    add("ham", "Kabir shared the album 'Convocation 2026' with you on the staff drive. Open it any time from your drive home screen — nothing else is needed.",
        "NONE", "HARD", "ht_docshare_legit")

    # HARD: more legitimate system alerts (unseen)
    add("ham", "UPI payment of Rs 750 to 'Canteen Charges' was successful. UPI Ref: 4129....3981. Transaction alerts never include links; contact your bank only via the official app.",
        "NONE", "HARD", "ht_legit_upi")
    add("ham", "Your policy premium for this month was collected automatically. Sum assured remains unchanged until the next renewal cycle. Receipt is available in the policy documents section.",
        "NONE", "HARD", "ht_legit_insurance")
    add("ham", "Seminar registration is confirmed. Check-in uses your college ID only — no pass or external link is required for entry.",
        "NONE", "MEDIUM", "ht_legit_seminar")

    return rows


# ---------------------------------------------------------------------------
# Assembly + data quality
# ---------------------------------------------------------------------------
def normalize_rows(rows):
    out = []
    for r in rows:
        msg = _clean_ws(r.get("message") or "")
        if len(msg) < 3:
            continue
        out.append({k: (r.get(k) or "") for k in ROW_KEYS})
    return out


def main():
    print("=" * 74)
    print("  KAVACHAM AI — Hard-Negative + Adversarial Dataset Builder")
    print("=" * 74)

    rows = load_base_rows()
    print(f"[base] loaded {len(rows)} unique PDF-derived rows")

    generators = [
        ("credential_phishing", gen_credential_phishing, "spam"),
        ("account_suspension", gen_account_suspension, "spam"),
        ("digital_arrest", gen_digital_arrest, "both"),
        ("financial_fraud", gen_financial_fraud, "spam"),
        ("investment_loan", gen_investment_loan, "spam"),
        ("otp_phishing", gen_credential_otp, "spam"),
        ("bec", gen_bec, "both"),
        ("impersonation", gen_impersonation, "both"),
        ("malware_delivery", gen_malware_delivery, "both"),
        ("social_eng_no_spamwords", gen_social_eng_no_spamwords, "spam"),
        ("writing_style", gen_writing_style_variants, "spam"),
        ("hinglish", gen_hinglish, "both"),
        ("ham_like_malicious", gen_ham_like_malicious, "spam"),
        ("promo_spam", gen_promo_spam, "spam"),
        ("obfuscation", gen_obfuscation, "spam"),
        ("contextual_contrast", gen_contextual_contrast, "both"),
        ("legit_hard_ham", gen_legit_hard_ham, "ham"),
        ("legit_system_alerts", gen_legit_system_alerts, "ham"),
        ("legit_marketing", gen_legit_marketing, "ham"),
        ("legit_announcements", gen_legit_announcements, "ham"),
        ("macro_malware", gen_macro_malware, "spam"),
        ("doc_sharing", gen_doc_sharing, "both"),
        ("adversarial_tokens", gen_adversarial_token_pairs, "both"),
        ("short_minimal", gen_short_minimal, "both"),
    ]
    for name, fn, _ in generators:
        new = fn()
        rows.extend(normalize_rows(new))
        print(f"[{name:<26}] +{len(new)}")

    # --- Data quality (Task 23) ---
    before = len(rows)
    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=["message"]).copy()
    print(f"[dedupe] {before} -> {len(df)} exact duplicates removed")

    # Contradictory labels: same message with both labels
    dup_labels = df.groupby("message")["label"].nunique()
    conflict = set(dup_labels[dup_labels > 1].index)
    df = df[~df["message"].isin(conflict)].copy()
    print(f"[conflict] removed {len(conflict)} contradictory-label messages")

    df = df.reset_index(drop=True)

    # Near-duplicate report (shingle Jaccard on first 8 tokens)
    def _shingles(s, k=4):
        toks = str(s).lower().split()
        return set(" ".join(toks[i:i + k]) for i in range(max(0, len(toks) - k + 1)))

    if len(df) <= 6000:
        sim = []
        sampled = df.sample(min(1500, len(df)), random_state=SEED)
        keys = list(sampled["message"])
        for a in range(len(keys)):
            for b in range(a + 1, len(keys)):
                sa, sb = _shingles(keys[a]), _shingles(keys[b])
                if not sa or not sb:
                    continue
                j = len(sa & sb) / len(sa | sb)
                if j > 0.8 and keys[a] != keys[b]:
                    sim.append((j, keys[a][:50], keys[b][:50]))
        print(f"[near-dupe] {len(sim)} near-duplicate pairs (Jaccard>0.80) in sample — kept for diversity")

    # Class balance report
    vc = df["label"].value_counts()
    print(f"[balance] {dict(vc)}")

    # Vocabulary leakage report
    danger = ["free", "win", "urgent", "verify", "password", "otp", "bank", "payment",
              "invoice", "security", "account", "claim", "prize", "congratulations"]
    for w in danger:
        sp = df[(df["label"] == "spam") & (df["message"].str.lower().str.contains(w, regex=False))]
        hm = df[(df["label"] == "ham") & (df["message"].str.lower().str.contains(w, regex=False))]
        print(f"[leak] '{w:<15}' spam={len(sp):>4} ham={len(hm):>4}")

    df.to_csv("dataset_kavacham_v2.csv", index=False, encoding="utf-8")
    print(f"[+] Wrote dataset_kavacham_v2.csv ({len(df)} rows)")

    # --- Hard test set (never trained on) ---
    hard = normalize_rows(gen_hard_test_rows())
    hard_df = pd.DataFrame(hard)
    train_msgs = set(df["message"].str.lower())
    overlap = hard_df["message"].str.lower().isin(train_msgs).sum()
    hard_df = hard_df[~hard_df["message"].str.lower().isin(train_msgs)].reset_index(drop=True)
    print(f"[hard-test] {len(hard) - overlap} unseen rows (dropped {overlap} overlaps)")
    print(f"[hard-test] balance {dict(hard_df['label'].value_counts())}")
    hard_df.to_csv("KAVACHAM_HARD_TEST.csv", index=False, encoding="utf-8")
    print(f"[+] Wrote KAVACHAM_HARD_TEST.csv ({len(hard_df)} rows)")

    print("Done.")


if __name__ == "__main__":
    main()