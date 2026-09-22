"""
analyzer/spam_analyzer.py
=========================
Spam classification via the existing Kavacham AI ML model.

The model lives in `app.py` (`predict_spam`). To avoid importing the Flask
app (and its globals) from the analyzer layer, the route injects the
`predict_spam` callable into the pipeline. This keeps the existing trained
model EXACTLY as the primary spam classifier and avoids duplicating logic.

No invented confidence is produced — only what the actual model returns.
"""


def analyze(email, predict_spam_fn):
    """
    Run the ML spam classifier on the normalized email.

    predict_spam_fn: callable(subject+body text) -> dict with prediction,
                     confidence, probability_spam, probability_ham,
                     decision_threshold, influential_signals, matched_keywords
    """
    raw = (email.subject or "")
    body = email.body_text or ""
    if raw:
        raw = "Subject: " + raw

    analyzed_text = ". ".join(p for p in [raw, body] if p)
    if not analyzed_text.strip():
        return {
            "status": "clean", "severity": "none", "score": 0, "detected": False,
            "indicators": [], "summary": "No content available for ML classification.",
            "classification": "Not Spam", "confidence": 0.0,
            "probability_spam": 0.0, "probability_ham": 0.0,
            "influential_signals": [], "matched_keywords": [],
        }

    try:
        result = predict_spam_fn(analyzed_text)
    except Exception as e:
        return {
            "status": "unavailable", "severity": "none", "score": 0, "detected": False,
            "indicators": [{"type": "ml_unavailable",
                            "evidence": f"ML classifier unavailable: {str(e)}",
                            "severity": "low", "category": "model"}],
            "summary": "ML spam classification could not be performed.",
            "classification": "Unavailable", "confidence": 0.0,
            "probability_spam": 0.0, "probability_ham": 0.0,
            "influential_signals": [], "matched_keywords": [],
        }

    is_spam = result.get("prediction") == "Spam"
    prob_spam = float(result.get("probability_spam", 0.0) or 0.0)
    confidence = float(result.get("confidence", 0.0) or 0.0)

    indicators = []
    if is_spam:
        indicators.append({
            "type": "spam_classification",
            "evidence": f"ML model classified the message as Spam with {confidence}% model confidence (threshold {result.get('decision_threshold', '?')}%).",
            "severity": "medium" if prob_spam < 90 else "high",
            "category": "spam",
        })
    matched = result.get("matched_keywords") or []
    if matched:
        indicators.append({
            "type": "influential_tokens",
            "evidence": "Model-weighted tokens: " + ", ".join(matched[:6]),
            "severity": "low", "category": "spam",
        })

    # Spam probability maps to a 0-100 score on the spam axis only.
    spam_score = int(prob_spam)
    severity = None
    if is_spam:
        severity = "high" if prob_spam >= 90 else "medium"
    else:
        severity = "none"

    return {
        "status": "malicious" if is_spam else "clean",
        "severity": severity,
        "score": spam_score,
        "detected": is_spam,
        "indicators": indicators,
        "summary": ("ML model classified this message as SPAM."
                    if is_spam else "ML model classified this message as NOT SPAM."),
        "classification": result.get("prediction"),
        "confidence": round(confidence, 2),
        "probability_spam": round(prob_spam, 2),
        "probability_ham": round(float(result.get("probability_ham", 0.0) or 0.0), 2),
        "decision_threshold": result.get("decision_threshold"),
        "influential_signals": result.get("influential_signals", []),
        "matched_keywords": matched,
    }