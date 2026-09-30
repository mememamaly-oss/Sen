#!/usr/bin/env python3
import json
raw = open('/home/z/my-project/readiness/evidence/B07_reproduce_reinstall.json').read()
obj, consumed = json.JSONDecoder().raw_decode(raw)
tail = raw[consumed:].strip()
out = {
    'json_keys': list(obj.keys()),
    'executed': obj.get('executed'),
    'reproduced': obj.get('reproduced'),
    'verification': obj.get('verification'),
    'confidence': obj.get('confidence'),
    'proof_grade': obj.get('proof_grade'),
    'recipe_keys': list(obj.get('recipe', {}).keys()) if isinstance(obj.get('recipe'), dict) else str(obj.get('recipe'))[:200],
    'tail_after_json': tail[:800],
}
with open('/home/z/my-project/readiness/evidence/B07_structure.json', 'w') as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
print(json.dumps(out, indent=1, ensure_ascii=False))
