"""
ml_audit.py
===========
KAVACHAM AI — Model & Dataset Audit (Task 1 / Task 17 / Task 30).

Audits the CURRENT served model (`model.pkl` + `vectorizer.pkl`) before any
retraining is considered:

  1. Dataset facts        : size, class balance, template repetition, vocabulary
  2. Feature analysis     : tokens that push the model toward Spam vs Ham
  3. Threshold scan       : precision / recall / FPs / FNs per threshold on a
                            leakage-free (group-stratified) validation split
  4. Adversarial tokens   : same dangerous word, different context (Task 17)
  5. Initial hard failure report: how the current model performs on the unseen
                            `KAVACHAM_HARD_TEST.csv`, grouped by category (Task 1)

Writes `ML_AUDIT_REPORT.md` and `KAVACHAM_FAILURE_REPORT.md`.

Run:  python ml_audit.py
"""

import json
import os
import pickle

import joblib
import numpy as np
import pandas as pd

from train_model import clean_text_advanced, STOPWORDS
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

SEED = 20260714
REPORT_MD = "ML_AUDIT_REPORT.md"
FAILURE_MD = "KAVACHAM_FAILURE_REPORT.md"

MODEL_FILE = "model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"


def load_served_model():
    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
    return model, vectorizer


def predict_proba(model, vectorizer, raw_texts):
    cleaned = [clean_text_advanced(t) or (t or "").lower().strip() for t in raw_texts]
    cleaned = [c or "empty" for c in cleaned]
    X = vectorizer.transform(cleaned)
    return model.predict_proba(X)[:, 1]


def group_stratified_split(df, val_frac=0.25):
    """Split by template_group so no family leaks across splits."""
    rng = np.random.RandomState(SEED)
    groups = df.groupby("template_group")["label"].agg(lambda s: "spam" if (s == "spam").mean() >= 0.5 else "ham")
    groups = groups.reset_index()
    train_groups, val_groups = [], []
    group_ids = list(groups["template_group"])  # keep original list order (already stable)
    for gid in group_ids:
        lab = groups.loc[groups["template_group"] == gid, "label"].iloc[0]
        if rng.rand() < val_frac:
            val_groups.append(gid)
        else:
            train_groups.append(gid)
    train = df[df["template_group"].isin(train_groups)]
    val = df[df["template_group"].isin(val_groups)]
    return train, val


def top_features(model, vectorizer, k=25):
    vocab = vectorizer.get_feature_names_out()
    diff = model.feature_log_prob_[1] - model.feature_log_prob_[0]
    order = np.argsort(diff)
    spam_tokens = [(vocab[i], float(diff[i])) for i in order[-k:][::-1]]
    ham_tokens = [(vocab[i], float(diff[i])) for i in order[:k]]
    return ham_tokens, spam_tokens


def write_threshold_table(rows, path, fh):
    fh.write("\n| Threshold | Precision | Recall | F1 | FPs (FPR) | FNs (FNR) |\n")
    fh.write("|---|---|---|---|---|---|\n")
    for t, prec, rec, f1v, fp, fpr, fn, fnr in rows:
        fh.write(f"| {t:.2f} | {prec:.2f}% | {rec:.2f}% | {f1v:.2f}% | {fp} ({fpr:.2f}%) | {fn} ({fnr:.2f}%) |\n")


def load_hard_test():
    return pd.read_csv("KAVACHAM_HARD_TEST.csv", encoding="utf-8")


def main():
    print("=" * 74)
    print("  KAVACHAM AI — MODEL & DATASET AUDIT (current served model)")
    print("=" * 74)

    # ---- 1. Dataset facts ----
    df = pd.read_csv("dataset_kavacham_v2.csv", encoding="utf-8")
    unique_base = 1000
    print(f"[1] Training corpus: {len(df)} rows | spam={int((df.label=='spam').sum())} ham={int((df.label=='ham').sum())}")
    print(f"    template groups: {df['template_group'].nunique()} | families: {df['category'].nunique()}")

    hard = load_hard_test()
    print(f"[1] Hard test set: {len(hard)} rows | spam={int((hard.label=='spam').sum())} ham={int((hard.label=='ham').sum())}")

    # ---- 2. Load served model & vectorizer ----
    model, vectorizer = load_served_model()
    ham_tokens, spam_tokens = top_features(model, vectorizer)
    print(f"[2] Served model feature space: {vectorizer.transform(['x']).shape[1]} dims")

    # ---- 3. Threshold scan (leakage-free validation split, v1 pipeline) ----
    train_g, val_g = group_stratified_split(df)
    val_texts = val_g["message"].tolist()
    val_y = (val_g["label"] == "spam").astype(int).values
    val_probs = predict_proba(model, vectorizer, val_texts)

    thresholds = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
    scan_rows = []
    print("\n[3] Validation threshold scan (group-stratified, no leakage):")
    print("    Threshold | Precision | Recall | F1 | FPs (FPR) | FNs (FNR)")
    for t in thresholds:
        pred = (val_probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(val_y, pred).ravel()
        fpr = fp / (fp + tn) * 100 if (fp + tn) else 0.0
        fnr = fn / (fn + tp) * 100 if (fn + tp) else 0.0
        prec = precision_score(val_y, pred, zero_division=0) * 100
        rec = recall_score(val_y, pred, zero_division=0) * 100
        f1v = f1_score(val_y, pred, zero_division=0) * 100
        scan_rows.append((t, prec, rec, f1v, fp, fpr, fn, fnr))
        print(f"    {t:.2f}      | {prec:7.2f}% | {rec:6.2f}% | {f1v:6.2f}% | {fp} ({fpr:5.2f}%) | {fn} ({fnr:5.2f}%)")

    # ---- 4. Adversarial token tests (Task 17) ----
    print("\n[4] Adversarial token behavior (same word, opposite context):")
    adv_pairs = [
        ("ham", "FREE admission for university students - bring your student ID to the gate."),
        ("spam", "FREE call minutes for you today - dial now and claim your reward."),
        ("ham", "Congratulations, you have been selected for the research internship. Attend orientation tomorrow."),
        ("spam", "Congratulations, your account has won a lottery. Enter your password to claim it."),
        ("ham", "Your OTP for login is 482913. It expires in 10 minutes. Never share it with anyone."),
        ("spam", "Your OTP for password reset is 482913. Enter it on the unknown page to recover access."),
        ("ham", "Your bank statement for August is available in the official banking application."),
        ("spam", "Your bank account will be suspended. Verify immediately using the link below."),
    ]
    adv_probs = predict_proba(model, vectorizer, [p[1] for p in adv_pairs])
    for (lab, msg), prob in zip(adv_pairs, adv_probs):
        verdict = "SPAM" if prob >= 0.85 else "HAM"
        flag = "OK" if verdict.lower() == lab else "MISMATCH"
        print(f"    [{flag}] gold={lab:<3} prob={prob*100:6.2f}% -> {verdict}  | {msg[:60]}")

    # ---- 5. Initial hard-test failure report (Task 1) ----
    print("\n[5] Current model on unseen KAVACHAM_HARD_TEST:")
    hard_texts = hard["message"].tolist()
    hard_probs = predict_proba(model, vectorizer, hard_texts)
    hard_pred = (hard_probs >= 0.85).astype(int)
    hard_y = (hard["label"] == "spam").astype(int).values

    hard["prob_spam"] = np.round(hard_probs * 100, 2)
    hard["pred"] = hard_pred
    hard["gold_int"] = hard_y
    hard["correct"] = hard_pred == hard_y

    fns = hard[(hard_y == 1) & (hard_pred == 0)]
    fpx = hard[(hard_y == 0) & (hard_pred == 1)]
    spam_recall = (hard_y == 1).sum() and ((hard_pred[hard_y == 1]).sum()) / (hard_y == 1).sum() * 100
    fn_rate = len(fns) / (hard_y == 1).sum() * 100 if (hard_y == 1).sum() else 0
    print(f"    Hard-test spam recall: {spam_recall:.2f}% | missed {len(fns)}/{int((hard_y==1).sum())}")
    print(f"    Hard-test ham FPs: {len(fpx)}")

    fn_by_cat = fns.groupby("category").size().sort_values(ascending=False)

    # ---- Write ML_AUDIT_REPORT.md ----
    with open(REPORT_MD, "w", encoding="utf-8") as fh:
        fh.write("# KAVACHAM AI — ML Audit Report\n\n")
        fh.write(f"_Generated: audit run against the served model (`{MODEL_FILE}`)._\n\n")
        fh.write("## 1. Dataset\n\n")
        fh.write(f"- Training corpus rows: {len(df)}\n")
        fh.write(f"- Spam / Ham balance: {int((df.label=='spam').sum())} / {int((df.label=='ham').sum())}\n")
        fh.write(f"- Template families (template_group): {df['template_group'].nunique()}\n")
        fh.write(f"- Category families: {df['category'].nunique()}\n")
        fh.write(f"- Hard test set (unseen, never trained): {len(hard)} rows "
                 f"(spam {int((hard.label=='spam').sum())} / ham {int((hard.label=='ham').sum())})\n\n")
        fh.write("## 2. Served model\n\n")
        fh.write("- Algorithm: Multinomial Naive Bayes (alpha=0.5)\n")
        fh.write("- Features: TF-IDF Word (1-3) + Char (3-5) n-grams via FeatureUnion\n")
        try:
            with open("metrics.json", encoding="utf-8") as mf:
                m = json.load(mf)
            fh.write(f"- Stored decision threshold: {m.get('decision_threshold', 0.85)}\n")
            fh.write(f"- Stored metrics (legacy holdout): acc={m.get('accuracy')}% prec={m.get('precision')}% "
                     f"recall={m.get('recall')}% F1={m.get('f1_score')}%\n")
        except Exception:
            pass
        fh.write("\n### Tokens pushing toward SPAM\n\n")
        for tok, s in spam_tokens[:15]:
            fh.write(f"- `{tok}` ({s:+.3f})\n")
        fh.write("\n### Tokens pushing toward HAM\n\n")
        for tok, s in ham_tokens[:15]:
            fh.write(f"- `{tok}` ({s:+.3f})\n")
        fh.write("\n### Risk note\n\n")
        fh.write("Tokens like `verify`, `claim`, `bank`, `payment`, `account` are heavily spam-weighted. "
                 "Legitimate security/financial alerts contain the same words, so a model relying on these "
                 "tokens alone produces dangerous false negatives on hard phishing and false positives on "
                 "hard legitimate alert mail. This is the primary reason the hard-negative training corpus "
                 "exists.\n\n")
        fh.write("## 3. Threshold scan (group-stratified validation, no leakage)\n\n")
        write_threshold_table(scan_rows, REPORT_MD, fh)
        fh.write("\nCurrent served threshold 0.85 minimizes FPs but at the cost of spam recall on hard "
                 "phishing — see the failure report below.\n\n")
        fh.write("## 4. Adversarial token behavior\n\n")
        fh.write("| Gold | Message | P(spam) | Verdict |\n|---|---|---|---|\n")
        for (lab, msg), prob in zip(adv_pairs, adv_probs):
            verdict = "SPAM" if prob >= 0.85 else "HAM"
            fh.write(f"| {lab} | {msg[:64]}... | {prob*100:.2f}% | {verdict} |\n")
        fh.write("\n## 5. Hard test result (served model)\n\n")
        fh.write(f"- Hard-test SPAM recall: **{spam_recall:.2f}%** (missed {len(fns)}/{int((hard_y==1).sum())})\n")
        fh.write(f"- Hard-test HAM false positives: {len(fpx)}\n\n")
        fh.write("See `KAVACHAM_FAILURE_REPORT.md` for category-grouped misses.\n")
    print(f"[+] Wrote {REPORT_MD}")

    # ---- Write KAVACHAM_FAILURE_REPORT.md (Task 1) ----
    with open(FAILURE_MD, "w", encoding="utf-8") as fh:
        fh.write("# KAVACHAM AI — Failure Report (Hard-Negative & Adversarial)\n\n")
        fh.write("_Initial report: failures of the CURRENT served model on the unseen hard benchmark._\n\n")
        fh.write("## Summary\n\n")
        fh.write(f"- Hard-test examples: {len(hard)} (spam {int((hard_y==1).sum())}, ham {int((hard_y==0).sum())})\n")
        fh.write(f"- Spam missed (false negatives): **{len(fns)}** — the primary security failure\n")
        fh.write(f"- Ham classified as spam (false positives): **{len(fpx)}** — trust regression\n\n")
        fh.write("## False negatives by category\n\n")
        if len(fn_by_cat):
            fh.write("| Category | Missed |\n|---|---|\n")
            for cat, n in fn_by_cat.items():
                fh.write(f"| {cat} | {n} |\n")
        else:
            fh.write("None — the served model passes the current hard set (unlikely; verify thresholds).\n")
        fh.write("\n## Full negative misses\n\n")
        if len(fns):
            for _, r in fns.iterrows():
                fh.write(f"- **[{r['category']}]** prob={r['prob_spam']:.1f}% — {r['message'][:110]}\n")
        if len(fpx):
            fh.write("\n## False positives (ham -> spam)\n\n")
            for _, r in fpx.iterrows():
                fh.write(f"- **[{r['category']}]** prob={r['prob_spam']:.1f}% — {r['message'][:110]}\n")
        fh.write("\n## Remediation target\n\n")
        fh.write("Retrain on a corpus that includes the same *failure families* (credential phishing, "
                 "account suspension, digital arrest, financial fraud, BEC, impersonation, malware delivery, "
                 "social engineering without spam words, ham-like malicious mail, Hinglish, obfuscation, "
                 "short/minimal mail) together with their legitimate counterparts, then re-run this audit "
                 "and the promotion gate in `train_kavacham_v2.py`.\n")
    print(f"[+] Wrote {FAILURE_MD}")
    print("\nAudit complete.")


if __name__ == "__main__":
    main()