import urllib.request
import json
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ.get('GEMINI_API_KEY', '')

models_to_try = [
    'models/gemini-flash-latest',
    'models/gemini-3.8-flash',
    'models/gemini-2.5-flash',
    'models/gemini-3-flash-preview',
    'models/gemini-flash-lite-latest',
]

payload = {
    'contents': [{'parts': [{'text': 'Reply with just valid JSON: {"ok": true}'}]}],
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
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            text = data['candidates'][0]['content']['parts'][0]['text']
            print(f'SUCCESS: {model} => {text[:80]}')
            break
    except Exception as e:
        print(f'FAIL: {model} => {e}')
