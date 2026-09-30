#!/usr/bin/env python3
"""T-section: report content validation."""
import json, re

R = '/home/z/my-project/readiness'
out = {}

html = open(f'{R}/evidence/B06_report_clean.html').read()
glass = open(f'{R}/evidence/B06_glass_clean.html').read()
exec_ = json.load(open(f'{R}/evidence/B06_executive_clean.json'))
sarif = json.load(open(f'{R}/evidence/S_ci.sarif'))

def has(pattern, body):
    return bool(re.search(pattern, body, re.I))

out['T02_technical_html'] = {
    'title_present': has(r'<title>|<h1', html),
    'size_kb': round(len(html) / 1024, 1),
    'findings_table': has(r'finding|severity', html),
    'T03_evidence_section': has(r'evidence|proof|attack_hypothesis', html),
    'T04_reproduction': has(r'reproduc|recipe', html),
    'T05_coverage': has(r'coverage', html),
    'T06_untested': has(r'untested', html),
    'T07_identity': has(r'identity|role|account', html),
    'T08_workflow': has(r'workflow|flow', html),
}
out['T01_executive'] = {
    'keys': list(exec_.keys()),
    'T09_business_impact': has(r'impact|business', json.dumps(exec_)),
    'risk_posture': 'risk' in json.dumps(exec_).lower(),
}
out['T15_arabic_rtl'] = {
    'glass_dir_rtl': 'dir="rtl"' in glass or "dir='rtl'" in glass,
    'arabic_text': bool(re.search(r'[\u0600-\u06FF]{4,}', glass)),
    'glass_size_kb': round(len(glass) / 1024, 1),
}
out['T16_glass_functional'] = {
    'charts_or_metrics': has(r'findings|coverage|risk', glass),
    'no_external_assets': not has(r'src="http|href="http', glass),
}
out['T10_sarif'] = {'version': sarif.get('version'), 'results': len(sarif.get('runs', [{}])[0].get('results', []))}
out['T13_no_secrets'] = 's3nt1nelDbPw' not in html and 's3nt1nelDbPw' not in glass

json.dump(out, open(f'{R}/evidence/T_report_validation.json', 'w'), indent=1, ensure_ascii=False)
print(json.dumps(out, indent=1, ensure_ascii=False))
