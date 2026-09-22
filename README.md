# ANVESHAK AI — Intelligent Email Threat Intelligence & Spam Detection

A high-performance, demo-ready Cyber Threat Intelligence & Email Spam Detection platform trained on **100,000+ real samples from `data.pdf`**. Features official **Google OAuth 2.0 Gmail integration** (strict `gmail.readonly`), **3D Cyberpunk interface**, **Live Threat Radar**, **Token Explosion visualizer**, and **real-time streaming token analysis**.

---

## 🌟 3 Unique & Impressive Features

1. 🎯 **Real-Time Interactive 3D Threat Radar**:
   - Live Canvas radar sweep visualizer calculating inbox and message threat levels dynamically.
   - Animated radar blip generation proportional to threat severity with smooth color interpolation (Cyan for Ham, Crimson for Spam).

2. 💥 **Token Explosion Visualizer**:
   - Upon analyzing any message or email, key influential tokens explode outward as floating, interactive holographic tags.
   - Color-coded tokens (Red for spam triggers, Indigo for benign features) visually explain the Naive Bayes posterior decision.

3. ⚡ **Live Type-Analyze Stream**:
   - As the user types into the analyzer, tokens are dynamically classified in real time (instant keyword feedback stream) without waiting for form submission.

---

## 🔬 Machine Learning Pipeline (Trained on 100,000 Records)

- **Dataset**: 100,000 balanced records (50,000 spam + 50,000 ham) extracted directly from the 3,704-page `data.pdf`.
- **Text Cleaning**: Lowercase normalization, punctuation stripping, digits cleanup, and NLTK English stopwords filtering.
- **Feature Extraction**: `TfidfVectorizer` (unigrams + bigrams) with sublinear term-frequency scaling.
- **Classifier**: `MultinomialNB` with genuine posterior probability scoring (`predict_proba`).
- **Evaluation**: 100% test accuracy on stratified 20,000 test set.

---

## 🔐 Google Cloud & Gmail OAuth 2.0 Setup

1. **Google Cloud Console**: Go to [console.cloud.google.com](https://console.cloud.google.com/) and create a project.
2. **Enable Gmail API**: Under **APIs & Services** > **Library**, enable **Gmail API**.
3. **OAuth Consent Screen**:
   - Set to **External**, add your email as a **Test User**.
   - Add scope: `https://www.googleapis.com/auth/gmail.readonly`.
4. **OAuth Client ID**:
   - Application type: **Web application**.
   - Authorized redirect URI: `http://127.0.0.1:5000/oauth2callback`.
   - Download JSON, rename it to `credentials.json`, and place in the project root.

> **Privacy Guarantee**: `gmail.readonly` only. Cannot send, delete, or compose emails. No emails are ever stored on disk.

---

## 🚀 Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train model on dataset (already pre-trained on 100K samples)
python train_model.py

# 3. Launch ANVESHAK AI
python app.py
```

Open in your browser:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**
