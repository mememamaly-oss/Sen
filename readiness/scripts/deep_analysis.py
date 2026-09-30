#!/usr/bin/env python3
"""Deep analysis of B04 (fixture clean scan) + C03 (ginandjuice live) for sections D-I.
Writes structured analysis to evidence/deep_analysis.json"""
import json

OUT = {}
b = json.load(open('/home/z/my-project/readiness/evidence/B04_scan_clean.json'))
g = json.load(open('/home/z/my-project/readiness/evidence/live/C03_ginjuice_v400.json'))

for tag, d in [("fixture", b), ("ginjuice", g)]:
    st = d.get('stats', {})
    OUT[f'{tag}_auth'] = st.get('auth')
    OUT[f'{tag}_authz'] = st.get('authz')
    OUT[f'{tag}_workflow'] = st.get('workflow')
    OUT[f'{tag}_twin'] = st.get('digital_twin')
    OUT[f'{tag}_reasoning'] = st.get('reasoning')
    OUT[f'{tag}_planner'] = st.get('planner')
    OUT[f'{tag}_secrets'] = st.get('secrets')
    OUT[f'{tag}_oast'] = st.get('oast')
    cov = st.get('coverage', {})
    OUT[f'{tag}_coverage_summary'] = {k: cov.get(k) for k in
        ('discovered','tested','passive','active','authz_probed','untested','skip_reasons','coverage_pct')}
    am = st.get('appmap', {})
    OUT[f'{tag}_appmap_keys'] = list(am.keys()) if isinstance(am, dict) else str(am)[:100]
    if isinstance(am, dict):
        OUT[f'{tag}_workflows_detail'] = am.get('workflows')
        OUT[f'{tag}_access_matrix'] = am.get('access_matrix')
        OUT[f'{tag}_authentication'] = am.get('authentication')
        OUT[f'{tag}_data_objects'] = am.get('data_objects')

# proofs structure (I section)
proofs = b.get('stats', {}).get('proofs', [])
OUT['fixture_n_proofs'] = len(proofs)
if proofs:
    p0 = proofs[0]
    OUT['fixture_proof_fields'] = sorted(p0.keys())
    # state before/after population across proofs
    pop_state = [(p.get('type'), bool(p.get('state_before')), bool(p.get('state_after')),
                  len(p.get('responses', []))) for p in proofs]
    OUT['fixture_state_population'] = pop_state
    # confidence values
    OUT['fixture_confidences'] = sorted({p.get('confidence') for p in proofs})
    # recipes
    OUT['fixture_recipe_sample'] = proofs[0].get('reproduction') or proofs[0].get('recipe')

# twin projections from the CLI (run later): authorization_matrix etc. — captured separately

with open('/home/z/my-project/readiness/evidence/deep_analysis.json', 'w') as f:
    json.dump(OUT, f, indent=1, ensure_ascii=False)

# console digest (short)
for k in ['fixture_auth', 'fixture_authz', 'fixture_workflow', 'fixture_twin', 'fixture_reasoning',
          'fixture_planner', 'ginjuice_twin', 'ginjuice_reasoning']:
    v = OUT.get(k)
    print(k, '=', json.dumps(v, ensure_ascii=False)[:400])
print('fixture_n_proofs =', OUT['fixture_n_proofs'])
print('fixture_proof_fields =', OUT.get('fixture_proof_fields'))
print('fixture_confidences =', OUT.get('fixture_confidences'))
print('state populated (type, before, after, n_responses):')
for row in (OUT.get('fixture_state_population') or [])[:12]:
    print('  ', row)
