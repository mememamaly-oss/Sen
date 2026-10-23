#!/usr/bin/env bash
# GREEN GATE 2026-10-23 — Gate 2/5: secret scan on the COMPLETE outgoing diff (added lines)
# Base: origin/main (722d9fd) -> Candidate: main (7f0d795)
set -uo pipefail
cd /home/z/my-project

OUT="qa-results/greengate_secret_scan.txt"
git diff origin/main..main > /tmp_diff_full.patch 2>/dev/null || git diff origin/main..main > .greengate_diff_full.patch

# Added lines only (start with '+'), excluding '+++ file headers'
grep -E '^\+' .greengate_diff_full.patch | grep -vE '^\+\+\+' > .greengate_added_lines.txt
ADDED=$(wc -l < .greengate_added_lines.txt)

echo "=== GREEN GATE SECRET SCAN — outgoing diff 722d9fd..7f0d795 ===" | tee "$OUT"
echo "added lines scanned: $ADDED" | tee -a "$OUT"
echo "" | tee -a "$OUT"

declare -A FINDINGS
scan() {
  local name="$1" pattern="$2"
  local hits
  hits=$(grep -nE "$pattern" .greengate_added_lines.txt | head -20)
  local count
  count=$(grep -cE "$pattern" .greengate_added_lines.txt || true)
  echo "--- pattern: $name — matches: $count" | tee -a "$OUT"
  if [ "$count" -gt 0 ]; then
    # Show match context but redact long token-like values
    echo "$hits" | sed -E 's/(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{8,}/\1<REDACTED>/g; s/AKIA[A-Za-z0-9]{12,}/AKIA<REDACTED>/g; s/(secret|password|token|api_key)(["'"'"']?\s*[:=]\s*["'"'"']?)[A-Za-z0-9+\/=_-]{12,}/\1\2<REDACTED-CANDIDATE>/gi' | tee -a "$OUT"
  fi
}

scan "github-tokens"        '(github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|ghr_[A-Za-z0-9]{30,})'
scan "aws-access-key"       'AKIA[A-Za-z0-9]{14,}'
scan "private-keys"         '-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----'
scan "nextauth-secret-lit"  'NEXTAUTH_SECRET\s*=\s*["'"'"'][A-Za-z0-9+\/=_-]{16,}'
scan "db-url-with-creds"    '(postgres|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:\/\/\s]+:[^@\s]+@'
scan "high-entropy-assign"  '(secret|passwd|password|api_?key|auth_?token|access_?token)["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9+\/=_]{24,}["'"'"']'
scan "slack/discord/twilio" '(xox[baprs]-[A-Za-z0-9-]{10,}|discord\.gg\/[A-Za-z0-9]{8,}|SK[0-9a-fA-F]{32}|AC[a-z0-9]{32})'
scan "generic-bearer"       'Bearer\s+[A-Za-z0-9+\/=_-]{28,}'
scan "cookies/session"      '(sessionid|connect\.sid|PHPSESSID)["'"'"']?\s*[:=]\s*["'"'"'][A-Za-z0-9+\/=_-]{20,}'

echo "" | tee -a "$OUT"
echo "=== KNOWN PLANTED TEST DATA (fixture canaries — expected, NOT secrets) ===" | tee -a "$OUT"
grep -nE 'ghp_SENTINEL|SENTINELFI' .greengate_added_lines.txt | sed 's/\(ghp_SENTINELFI[A-Za-z0-9]*\)/\1 <== PLANTED FIXTURE CANARY (fixtures\/vulnapp.py secret-detection test)/' | head -5 | tee -a "$OUT"

rm -f .greengate_diff_full.patch .greengate_added_lines.txt
echo "" | tee -a "$OUT"
echo "SCAN COMPLETE — see verdict in gate report" | tee -a "$OUT"
