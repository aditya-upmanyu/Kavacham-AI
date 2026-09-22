# KAVACHAM AI — ML Audit Report

_Generated: audit run against the served model (`model.pkl`)._

## 1. Dataset

- Training corpus rows: 1198
- Spam / Ham balance: 662 / 536
- Template families (template_group): 408
- Category families: 33
- Hard test set (unseen, never trained): 37 rows (spam 27 / ham 10)

## 2. Served model

- Algorithm: Multinomial Naive Bayes (alpha=0.5)
- Features: TF-IDF Word (1-3) + Char (3-5) n-grams via FeatureUnion
- Stored decision threshold: 0.85
- Stored metrics (legacy holdout): acc=99.52% prec=100.0% recall=99.03% F1=99.51%

### Tokens pushing toward SPAM

- `word_tfidf__offer` (+3.971)
- `word_tfidf__soon` (+3.631)
- `word_tfidf__not_miss` (+3.552)
- `word_tfidf__not not_miss not_this` (+3.552)
- `word_tfidf__not not_miss` (+3.552)
- `word_tfidf__not_miss not_this` (+3.552)
- `word_tfidf__act` (+3.470)
- `word_tfidf__bonus` (+3.408)
- `word_tfidf__ends` (+3.398)
- `word_tfidf__offer ends` (+3.398)
- `word_tfidf__ends soon` (+3.388)
- `word_tfidf__offer ends soon` (+3.388)
- `word_tfidf__not_this not_opportunity` (+3.323)
- `word_tfidf__not_miss not_this not_opportunity` (+3.323)
- `word_tfidf__not_opportunity` (+3.323)

### Tokens pushing toward HAM

- `word_tfidf__reply` (-3.589)
- `word_tfidf__reply convenient` (-3.564)
- `word_tfidf__convenient` (-3.564)
- `word_tfidf__let` (-3.424)
- `word_tfidf__please reply convenient` (-3.349)
- `word_tfidf__please reply` (-3.349)
- `word_tfidf__order` (-3.267)
- `word_tfidf__notes` (-3.262)
- `word_tfidf__class` (-3.241)
- `word_tfidf__appointment` (-3.228)
- `word_tfidf__meeting` (-3.173)
- `word_tfidf__know` (-3.168)
- `word_tfidf__changes` (-3.150)
- `word_tfidf__anything changes` (-3.140)
- `word_tfidf__anything` (-3.140)

### Risk note

Tokens like `verify`, `claim`, `bank`, `payment`, `account` are heavily spam-weighted. Legitimate security/financial alerts contain the same words, so a model relying on these tokens alone produces dangerous false negatives on hard phishing and false positives on hard legitimate alert mail. This is the primary reason the hard-negative training corpus exists.

## 3. Threshold scan (group-stratified validation, no leakage)


| Threshold | Precision | Recall | F1 | FPs (FPR) | FNs (FNR) |
|---|---|---|---|---|---|
| 0.50 | 99.40% | 89.19% | 94.02% | 1 (0.95%) | 20 (10.81%) |
| 0.55 | 99.40% | 89.19% | 94.02% | 1 (0.95%) | 20 (10.81%) |
| 0.60 | 99.40% | 89.19% | 94.02% | 1 (0.95%) | 20 (10.81%) |
| 0.65 | 99.40% | 89.19% | 94.02% | 1 (0.95%) | 20 (10.81%) |
| 0.70 | 99.40% | 89.19% | 94.02% | 1 (0.95%) | 20 (10.81%) |
| 0.75 | 100.00% | 88.65% | 93.98% | 0 (0.00%) | 21 (11.35%) |
| 0.80 | 100.00% | 88.65% | 93.98% | 0 (0.00%) | 21 (11.35%) |
| 0.85 | 100.00% | 88.11% | 93.68% | 0 (0.00%) | 22 (11.89%) |
| 0.90 | 100.00% | 85.95% | 92.44% | 0 (0.00%) | 26 (14.05%) |
| 0.95 | 100.00% | 84.86% | 91.81% | 0 (0.00%) | 28 (15.14%) |

Current served threshold 0.85 minimizes FPs but at the cost of spam recall on hard phishing — see the failure report below.

## 4. Adversarial token behavior

| Gold | Message | P(spam) | Verdict |
|---|---|---|---|
| ham | FREE admission for university students - bring your student ID t... | 0.01% | HAM |
| spam | FREE call minutes for you today - dial now and claim your reward... | 100.00% | SPAM |
| ham | Congratulations, you have been selected for the research interns... | 0.22% | HAM |
| spam | Congratulations, your account has won a lottery. Enter your pass... | 99.92% | SPAM |
| ham | Your OTP for login is 482913. It expires in 10 minutes. Never sh... | 24.48% | HAM |
| spam | Your OTP for password reset is 482913. Enter it on the unknown p... | 0.22% | HAM |
| ham | Your bank statement for August is available in the official bank... | 3.41% | HAM |
| spam | Your bank account will be suspended. Verify immediately using th... | 100.00% | SPAM |

## 5. Hard test result (served model)

- Hard-test SPAM recall: **3.70%** (missed 26/27)
- Hard-test HAM false positives: 1

See `KAVACHAM_FAILURE_REPORT.md` for category-grouped misses.
