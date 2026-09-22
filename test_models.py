import urllib.request
import json
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ.get('GEMINI_API_KEY', '')

models_to_try = [
    'models/gemini-3-flash-preview',
    'models/gemini-3.1-pro-preview',
    'models/gemini-3.5-flash',
    'models/gemini-3.5-flash-lite',
    'models/gemini-3.1-flash-lite-preview',
    'models/gemini-3-flash-preview',
    'models/antigravity-preview-latest'
]

payload = {
    'contents': [{'parts': [{'text': 'Return JSON only: {"status": "success", "classification": "Spam", "confidence": 92}'}]}],
    'generationConfig': {'responseMimeType': 'application/json'}
}

for model in models_to_try:
    url = f'https://generativelanguage.googleapis.com/v1beta/{model}:generateContent?key={api_key}'
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            text = data['candidates'][0]['content']['parts'][0]['text']
            print(f'SUCCESS: {model} => {text.strip()[:80]}')
    except Exception as e:
        print(f'FAIL: {model} => {e}')
