"""build_dataset.py - Extract 77K+ records from data.pdf and create dataset.csv"""
from pypdf import PdfReader
import re, csv

reader = PdfReader('data.pdf')
print('Extracting text from 3704 pages...')

full_text = ''
for i, page in enumerate(reader.pages):
    t = page.extract_text()
    if t:
        full_text += t + '\n'
    if i % 500 == 0:
        print(f'  Page {i}...')

print('Parsing records...')

records = []
lines = full_text.split('\n')
buffer_msg = []

for line in lines:
    stripped = line.strip()
    if stripped.endswith(',spam') or stripped.endswith(',normal'):
        if stripped.endswith(',spam'):
            label = 'spam'
            msg_part = stripped[:-5]
        else:
            label = 'normal'
            msg_part = stripped[:-7]

        if msg_part.endswith('.'):
            msg_part = msg_part[:-1]

        buffer_msg.append(msg_part.strip())
        full_msg = ' '.join(buffer_msg).strip()
        full_msg = re.sub(r'Ref\s+\d+', '', full_msg)
        full_msg = re.sub(r'^input,output\s*', '', full_msg)
        full_msg = full_msg.strip().strip('"').strip()

        if len(full_msg) > 10:
            records.append((label, full_msg))
        buffer_msg = []
    elif stripped and stripped != 'input,output':
        buffer_msg.append(stripped)

print(f'Parsed {len(records)} clean records')
spam_count = sum(1 for r in records if r[0] == 'spam')
normal_count = sum(1 for r in records if r[0] == 'normal')
print(f'Spam: {spam_count}, Normal (ham): {normal_count}')

with open('dataset.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['label', 'message'])
    for label, msg in records:
        mapped_label = 'spam' if label == 'spam' else 'ham'
        writer.writerow([mapped_label, msg])

print('Saved dataset.csv successfully!')
