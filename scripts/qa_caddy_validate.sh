#!/usr/bin/env bash
# QA: validate the repo Caddyfile parses, then run the behavioral test.
set -uo pipefail
cd /home/z/my-project
echo "== caddy validate (regression proof for the '//' comment defect) =="
caddy validate --config Caddyfile --adapter caddyfile 2>&1 | tail -3
echo "VALIDATE_RC=$?"
