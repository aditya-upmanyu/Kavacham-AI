# KAVACHAM AI — Failure Report (Hard-Negative & Adversarial)

_Initial report: failures of the CURRENT served model on the unseen hard benchmark._

## Summary

- Hard-test examples: 37 (spam 27, ham 10)
- Spam missed (false negatives): **26** — the primary security failure
- Ham classified as spam (false positives): **1** — trust regression

## False negatives by category

| Category | Missed |
|---|---|
| ht_attach_only | 1 |
| ht_bec | 1 |
| ht_bec_2 | 1 |
| ht_bec_3 | 1 |
| ht_bec_giftcard | 1 |
| ht_digital_arrest | 1 |
| ht_digital_arrest_2 | 1 |
| ht_digital_arrest_3 | 1 |
| ht_fraud_refund | 1 |
| ht_fraud_upi | 1 |
| ht_hamlook | 1 |
| ht_hamlook_2 | 1 |
| ht_hamlook_3 | 1 |
| ht_hinglish | 1 |
| ht_hinglish_2 | 1 |
| ht_impersonate_it | 1 |
| ht_impersonate_rec | 1 |
| ht_malware | 1 |
| ht_malware_resume | 1 |
| ht_obfusc | 1 |
| ht_obfusc_2 | 1 |
| ht_pro_phish | 1 |
| ht_pro_phish_2 | 1 |
| ht_pro_phish_3 | 1 |
| ht_pro_phish_4 | 1 |
| ht_url_only | 1 |

## Full negative misses

- **[ht_pro_phish]** prob=29.3% — Dear Customer, our auditors detected a change in your beneficiary list. To comply with the revised KYC norms, 
- **[ht_pro_phish_2]** prob=1.0% — Action Required: Annual device compliance review. Your machine has been flagged for a policy exception. Re-aut
- **[ht_pro_phish_3]** prob=0.0% — Security notification — a copy of your billing profile was exported by an external tool. We have attached what
- **[ht_pro_phish_4]** prob=0.0% — Update on your recently submitted request #A-22817. Before it can be closed, you must confirm the alternate re
- **[ht_digital_arrest]** prob=0.0% — Subject: Cyber Cell — IP trace report. Your registered IP was observed in a confirmed phishing infrastructure.
- **[ht_digital_arrest_2]** prob=0.0% — Your Aadhaar-linked number has been flagged in a narcotics case file. A video-conference statement has been sc
- **[ht_digital_arrest_3]** prob=0.1% — Income Tax preliminary notice: discrepancies found in your filing for AY 2025-26. A 'reconciliation portal' ha
- **[ht_bec]** prob=0.0% — Hi Sarah, this is Daniel. Finance is running behind on the Q3 supplier settlement. I need the remaining 11 inv
- **[ht_bec_2]** prob=0.0% — Re: Purchase Order #9021 — the bank account on file returned an error on the last three attempts. Please re-ro
- **[ht_bec_3]** prob=45.1% — Confidential — the external auditor has flagged our vendor master for tampering. Before the close, update the 
- **[ht_bec_giftcard]** prob=0.0% — From: Director's office — I am travelling and locked out of the payment system. Purchase four corporate gift c
- **[ht_impersonate_it]** prob=0.0% — IT Service Desk: your account has been provisioned for 'privileged access review'. A domain administrator will
- **[ht_impersonate_rec]** prob=27.7% — Hello, I am reaching out from TalentBridge about your application for the Senior Engineer role. Before the fin
- **[ht_fraud_upi]** prob=0.2% — A UPI mandate of Rs 24,999 was initiated from your account ending 4802 to an unknown payee. As per RBI dispute
- **[ht_fraud_refund]** prob=0.0% — Refund status: your earlier cashback of Rs 850 was reversed due to a validation error. Re-validate the linked 
- **[ht_malware]** prob=0.0% — Please find the final version of the contract attached. It contains a digital signature macro that must be ena
- **[ht_malware_resume]** prob=0.0% — Resume submission — please review the attached CV and the referenced portfolio archive. The archive includes a
- **[ht_hamlook]** prob=0.0% — Please review the attached settlement sheet and confirm the revised account before processing today's payroll.
- **[ht_hamlook_2]** prob=0.0% — Document shared with you via secure link — 'FY26-Budget-Review.xlsx'. Open it, enable editing, and confirm the
- **[ht_hamlook_3]** prob=0.0% — A colleague shared a folder with you — 'Q3 Metrics'. Review and approve the sharing certificate that is embedd
- **[ht_hinglish]** prob=8.1% — Aapka SBI account se Rs 19,000 ka transaction ho gaya hai jo aapne nahi kiya. Turant reversal ke liye OTP veri
- **[ht_hinglish_2]** prob=32.1% — Cyber Police se notice aaya hai, aapke number se fake call center chal raha hai. Court appearance se bachne ke
- **[ht_url_only]** prob=15.2% — https://req-approval-doc.servefile.click/claim
- **[ht_attach_only]** prob=0.2% — See attached — password-protected, the password is your employee ID.
- **[ht_obfusc]** prob=41.7% — V3r1fy your acc0unt t0day — d0wnl0ad the checkp01nt 4nd c0nf1rm y0ur det41ls.
- **[ht_obfusc_2]** prob=4.8% — ACCOUNT R E V I E W P E N D I N G . P r e s e n t c r e d e n t i a l s to the security console below.

## False positives (ham -> spam)

- **[ht_safe_password]** prob=99.8% — Password change confirmed for your university account. If you did not make this change, reset immediately via 

## Remediation target

Retrain on a corpus that includes the same *failure families* (credential phishing, account suspension, digital arrest, financial fraud, BEC, impersonation, malware delivery, social engineering without spam words, ham-like malicious mail, Hinglish, obfuscation, short/minimal mail) together with their legitimate counterparts, then re-run this audit and the promotion gate in `train_kavacham_v2.py`.
