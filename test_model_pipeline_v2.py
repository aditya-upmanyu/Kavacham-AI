"""
test_model_pipeline_v2.py
Tests feature union of Word TF-IDF (1,3-grams) + Char TF-IDF (3,5-grams)
with negation-aware preprocessing, MultinomialNB, probability calibration,
and threshold validation.
"""
import re
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

NEGATION_TERMS = {
    "no", "not", "never", "none", "neither", "nor", "cannot", "cant", "wont",
    "dont", "doesnt", "didnt", "isnt", "arent", "wasnt", "werent", "without"
}

STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", 
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", 
    "but", "by", "could", "did", "do", "does", "doing", "down", "during", "each", "few", "for", 
    "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself", 
    "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", 
    "me", "more", "most", "my", "myself", "of", "off", "on", "once", "only", "or", "other", 
    "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "she", "should", "so", 
    "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves", "then", 
    "there", "these", "they", "this", "those", "through", "to", "too", "under", "until", "up", 
    "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", 
    "why", "with", "you", "your", "yours", "yourself", "yourselves"
}

def clean_text_v2(text: str) -> str:
    if not text or not isinstance(text, str):
        return ""
    t = text.lower()
    t = re.sub(r"https?://\S+|www\.\S+", " url_token ", t)
    t = re.sub(r"\S+@\S+", " email_token ", t)
    t = re.sub(r"[\$£€]\s*\d+(?:[,\.]\d+)?", " currency_amount ", t)
    t = re.sub(r"\b\d{4,}\b", " num_sequence ", t)
    t = re.sub(r"\b\d+\b", " num_token ", t)
    t = re.sub(r"(.)\1{2,}", r"\1\1", t)
    t = t.replace("n't", " not").replace("'re", " are").replace("'s", " is").replace("'d", " would")
    t = t.replace("'ll", " will").replace("'ve", " have").replace("'m", " am")
    
    raw_tokens = re.findall(r"[a-zA-Z_]+|[.,!?;:\n]", t)
    processed = []
    negate_active = False
    negate_window = 0
    
    for tok in raw_tokens:
        if tok in ".,!?;:\n":
            negate_active = False
            negate_window = 0
            continue
        clean_tok = tok.strip()
        if not clean_tok:
            continue
        if clean_tok in NEGATION_TERMS:
            negate_active = True
            negate_window = 4
            processed.append("not")
            continue
        if negate_active and negate_window > 0:
            processed.append(f"not_{clean_tok}")
            negate_window -= 1
            if negate_window == 0:
                negate_active = False
        else:
            if clean_tok not in STOPWORDS or clean_tok in {"urgent", "alert", "security", "verify", "claim", "free", "payment", "winner"}:
                processed.append(clean_tok)
    return " ".join(processed)

df = pd.read_csv("dataset_balanced.csv")
df["cleaned"] = df["message"].apply(clean_text_v2)
df["label_num"] = df["label"].map({"ham": 0, "spam": 1})

X = df["cleaned"]
y = df["label_num"]

# 70% Train, 15% Val, 15% Test
X_train_val, X_test, y_train_val, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val)

print(f"Train samples: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

# Feature Union: Word n-grams + Char n-grams
vectorizer = FeatureUnion([
    ("word_tfidf", TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=5000,
        sublinear_tf=True
    )),
    ("char_tfidf", TfidfVectorizer(
        ngram_range=(3, 5),
        analyzer="char",
        max_features=3000,
        sublinear_tf=True
    ))
])

X_train_vec = vectorizer.fit_transform(X_train)
X_val_vec = vectorizer.transform(X_val)
X_test_vec = vectorizer.transform(X_test)

model = MultinomialNB(alpha=0.5)
model.fit(X_train_vec, y_train)

# Optimize threshold on Validation Set
val_probs = model.predict_proba(X_val_vec)[:, 1]

best_thresh = 0.50
best_f1 = 0.0
print("\n--- Validation Threshold Search ---")
for t in [0.50, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]:
    val_pred = (val_probs >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, val_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    f1 = f1_score(y_val, val_pred)
    prec = precision_score(y_val, val_pred, zero_division=0)
    rec = recall_score(y_val, val_pred, zero_division=0)
    print(f"Threshold {t:.2f} -> Prec: {prec*100:.2f}%, Rec: {rec*100:.2f}%, F1: {f1*100:.2f}%, FP: {fp} (FPR: {fpr*100:.2f}%)")
    if t >= 0.70 and f1 > best_f1:
        best_f1 = f1
        best_thresh = t

print(f"\nSelected Threshold: {best_thresh:.2f}")

# Test on Holdout Test Set
test_probs = model.predict_proba(X_test_vec)[:, 1]
test_pred = (test_probs >= best_thresh).astype(int)

tn, fp, fn, tp = confusion_matrix(y_test, test_pred).ravel()
fpr = fp / (fp + tn)
fnr = fn / (fn + tp)
acc = accuracy_score(y_test, test_pred)
prec = precision_score(y_test, test_pred)
rec = recall_score(y_test, test_pred)
f1 = f1_score(y_test, test_pred)

print("\n--- Final Test Set Evaluation ---")
print(f"Accuracy:  {acc*100:.2f}%")
print(f"Precision: {prec*100:.2f}%")
print(f"Recall:    {rec*100:.2f}%")
print(f"F1-score:  {f1*100:.2f}%")
print(f"FPR (Ham classified as Spam): {fpr*100:.2f}% (FP: {fp}/{fp+tn})")
print(f"FNR (Spam missed): {fnr*100:.2f}% (FN: {fn}/{fn+tp})")

# Test on the 6 adversarial test cases
print("\n--- 6 Adversarial Legitimate Test Cases ---")
adversarial_tests = [
    ("Security verification email", "Security Alert: A new login was detected from Chrome on Windows. If this was you, please verify your identity by confirming your session. We will never ask you to provide your password or OTP over email. No payment is required."),
    ("Payment confirmation", "Payment Confirmation: Your payment of $49.99 for Order #84920 has been received and confirmed. Attached is your official invoice receipt. If you have questions regarding this charge, contact customer service. No further claim or action is required."),
    ("Project selection email", "Congratulations! You have been selected to join the Robotics Research Project team for the upcoming semester. Please attend the orientation meeting tomorrow at 10 AM. Urgent submissions are not required."),
    ("Password expiration notice", "IT Security Alert: Your corporate password will expire in 5 days. Please update your credentials using the official internal portal. Remember: IT will never send direct links asking for your secret passphrase."),
    ("Student workshop newsletter", "Department Workshop Newsletter: Register for the Annual AI and Data Science Seminar held this Friday in Room 302. Snacks and certificates provided. Free entry for all students."),
    ("Registration confirmation", "Event Registration Confirmation: Your ticket registration for the Tech Summit has been confirmed. Please claim your name badge at the reception desk upon arrival. This is an urgent reminder to bring your student ID.")
]

for name, raw in adversarial_tests:
    cleaned = clean_text_v2(raw)
    feat = vectorizer.transform([cleaned])
    prob_spam = model.predict_proba(feat)[0, 1]
    pred = "Spam" if prob_spam >= best_thresh else "Not Spam"
    print(f"{name:<30} -> {pred:<9} (Spam Prob: {prob_spam*100:5.2f}%)")

# Test on 3 actual spam messages to verify spam detection is strong
print("\n--- Actual Phishing / Scam Messages ---")
actual_spam = [
    ("Cash lottery scam", "WINNER! You have won a guaranteed cash prize of $5000! Click here now to claim your exclusive reward before your link expires!"),
    ("Account suspension phishing", "URGENT: Your bank account will be suspended within 24 hours. Verify your login credentials immediately to restore access."),
    ("Free gift card lure", "Congratulations! You were selected for a free $1000 Amazon Gift Card. Act fast, offer ends today!")
]
for name, raw in actual_spam:
    cleaned = clean_text_v2(raw)
    feat = vectorizer.transform([cleaned])
    prob_spam = model.predict_proba(feat)[0, 1]
    pred = "Spam" if prob_spam >= best_thresh else "Not Spam"
    print(f"{name:<30} -> {pred:<9} (Spam Prob: {prob_spam*100:5.2f}%)")
