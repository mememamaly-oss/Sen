"""الخطوة 5 — إعادة توليد SHA256SUMS لمحور 4 (سكربت المشرف + إضافة معلنة).

الإضافة الوحيدة عن قائمة المشرف السبعة: axis4_RED_atoms.json — كانت
مراسيّة في SHA256SUMS القديمة وإسقاطها يُفقد تغطية دليل قائم.
"""
import hashlib
import os

files = [
    'results/axis4/axis4_RED.json',
    'results/axis4/axis4_RED_atoms.json',
    'results/axis4/axis4_GREEN.json',
    'results/axis4/axis4_ATOMS.json',
    'results/axis4/axis4_RUN2.json',
    'results/axis4/axis4_RUN3.json',
    'results/gate_axis4_7448f95e.log',
    'results/bench_axis4_7448f95e.log',
]

lines = []
for f in files:
    if os.path.exists(f):
        h = hashlib.sha256(open(f, 'rb').read()).hexdigest()
        lines.append(f'{h}  {f}')
    else:
        print(f'MISSING: {f}')

sums_path = 'results/axis4/SHA256SUMS'
with open(sums_path, 'w') as out:
    out.write('\n'.join(lines) + '\n')

print('SHA256SUMS regenerated:')
for l in lines:
    print(l)
