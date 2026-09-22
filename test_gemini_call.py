import urllib.request
import json
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ.get('GEMINI_API_KEY', '')

url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}'

prompt = """
You are an email security analysis assistant.
Analyze the provided email based on contextual behavior, intent, requests, sender characteristics, links, urgency, financial requests, credential requests, impersonation indicators, and overall semantics.

Do NOT classify an email as spam merely because it contains words such as:
urgent, alert, security, payment, confirmation, winner, claim, verify, limited, account.
These words can appear in legitimate emails.

Email content:
Subject: Security Alert: New sign-in detected
Body: Security Alert: A new login was detected from Chrome on Windows. If this was you, please verify your identity by confirming your session in your security dashboard. We will never ask you to provide your password or OTP over email. No payment is required.

Return structured JSON with keys:
- classification: "Spam" or "Not Spam"
- confidence: number between 0 and 100
- risk_level: "Low", "Medium", or "High"
- reasons: list of concise strings explaining the decision
- suspicious_signals: list of suspicious patterns detected (empty list if none)
- legitimate_signals: list of legitimate patterns detected
"""

payload = {
    "contents": [{"parts": [{"text": prompt}]}],
    "generationConfig": {"responseMimeType": "application/json"}
}

req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode('utf-8'))
        print("Gemini Structured Response:")
        print(res['candidates'][0]['content']['parts'][0]['text'])
except Exception as e:
    print("Error:", e)
