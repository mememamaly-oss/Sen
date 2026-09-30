#!/usr/bin/env bash
# K-section vault battery v3: init vault first, then arm the scan
R=/home/z/my-project/readiness; Z=$R/ziprun2; EV=$R/evidence
VK=$EV/vault_demo; rm -rf $VK; mkdir -p $VK
> $EV/K_vault_battery.txt
PY="python3 $Z/sentinel/cli.py"

$PY vault keygen --out $VK/orgA.key --label "orgA owner" >> $EV/K_vault_battery.txt 2>&1; echo "keygenA=$?" >> $EV/K_vault_battery.txt
$PY vault keygen --out $VK/orgB.key --label "orgB owner" >> $EV/K_vault_battery.txt 2>&1; echo "keygenB=$?" >> $EV/K_vault_battery.txt
stat -c "perm %a: %n" $VK/orgA.key $VK/orgB.key >> $EV/K_vault_battery.txt 2>&1
$PY vault init --vault $VK/scan.vault --key-file $VK/orgA.key --org acme-corp >> $EV/K_vault_battery.txt 2>&1; echo "init=$?" >> $EV/K_vault_battery.txt

cd $Z
PORT=8778 python3 fixtures/vulnapp.py > $EV/K_fixture.log 2>&1 &
sleep 3
timeout 200 python3 sentinel/cli.py scan http://127.0.0.1:8778 --allow-private --no-browser --no-oast \
  --vault $VK/scan.vault --vault-key-file $VK/orgA.key \
  --db $VK/k.db --out $VK/k_scan.json > /dev/null 2>&1; echo "scan_with_vault=$?" >> $EV/K_vault_battery.txt

$PY vault status --vault $VK/scan.vault --key-file $VK/orgA.key >> $EV/K_vault_battery.txt 2>&1; echo "statusA=$?" >> $EV/K_vault_battery.txt
$PY vault list --vault $VK/scan.vault --key-file $VK/orgA.key >> $EV/K_vault_battery.txt 2>&1; echo "listA=$?" >> $EV/K_vault_battery.txt
$PY vault status --vault $VK/scan.vault --key-file $VK/orgB.key >> $EV/K_vault_battery.txt 2>&1; echo "wrongkey_status=$? (nonzero expected)" >> $EV/K_vault_battery.txt
$PY vault report --vault $VK/scan.vault --key-file $VK/orgB.key >> $EV/K_vault_battery.txt 2>&1; echo "wrongkey_report=$? (nonzero expected)" >> $EV/K_vault_battery.txt
$PY vault audit --vault $VK/scan.vault --key-file $VK/orgA.key >> $EV/K_vault_battery.txt 2>&1; echo "audit=$?" >> $EV/K_vault_battery.txt
$PY vault report --vault $VK/scan.vault --key-file $VK/orgA.key > $VK/reveal.json 2>&1; echo "authorized_report=$?" >> $EV/K_vault_battery.txt

python3 - <<'PYEOF' >> $EV/K_vault_battery.txt 2>&1
import re, os, json
src = open('/home/z/my-project/readiness/ziprun2/fixtures/vulnapp.py').read()
pat = r'([A-Za-z0-9._%+-]{6,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|SEN-[A-Z0-9-]{4,}|sk-[A-Za-z0-9]{8,}|AKIA[A-Z0-9]{8,}|BEGIN[A-Z ]*PRIVATE KEY)'
cands = [c for c in dict.fromkeys(re.findall(pat, src)) if c not in ('127.0.0.1',)]
hits = {}
for path in ['scan.vault', 'k.db', 'k_scan.json', 'reveal.json']:
    full = f'/home/z/my-project/readiness/evidence/vault_demo/{path}'
    if not os.path.exists(full):
        hits[path] = 'MISSING'; continue
    blob = open(full, 'rb').read()
    found = [c for c in cands if c.encode() in blob]
    hits[path] = found or 'CLEAN'
print('candidates checked:', len(cands), cands[:10])
print('plaintext hits:', json.dumps(hits, indent=1))
PYEOF

$PY vault purge --vault $VK/scan.vault --key-file $VK/orgA.key --all >> $EV/K_vault_battery.txt 2>&1; echo "purge=$?" >> $EV/K_vault_battery.txt
$PY vault status --vault $VK/scan.vault --key-file $VK/orgA.key >> $EV/K_vault_battery.txt 2>&1; echo "status_after_purge=$?" >> $EV/K_vault_battery.txt
cat $EV/K_vault_battery.txt
