#!/usr/bin/env bash
# PHASE-1 VPS RUNNER — the independent-verification targets that cannot run
# in the dev sandbox (no docker/php/mysql/maven there). Run on ANY VPS with
# Docker (a $6-10/mo 2GB instance is enough). Everything is loopback after
# the images pull; nothing scans third-party infrastructure.
#
# Usage:  bash vps_independent_verification.sh [workdir]
# Then:   copy the produced evidence/ directory back into the repo.
#
# Targets:
#   1. DVWA 3.x          (docker)      + engine scan + the DVWA lesson list
#   2. crAPI             (docker compose) + engine scan
#   3. Juice Shop        (docker)      FULL-BUDGET rescan (the sandbox pass
#                                      was budget-limited to 4500 requests)
#   4. WebGoat 2026.4    (docker)      deep lesson-surface scan (needs the
#                                      hash-fragment SPA seeding below)
#   5. OWASP Benchmark   (docker)      v1.2c — the heavy truth set
#
# Engine requirements on the VPS: python3.11+, pip install -r requirements.txt
# (cryptography, blake3), plus chromium for the browser engine
# (playwright install chromium). The repo ships on the VPS via git clone.
set -euo pipefail
cd "${1:-$HOME/sen-vps}"
mkdir -p evidence logs

echo "== [0] prerequisites =="
command -v docker >/dev/null || { echo "FATAL: docker not installed"; exit 1; }
docker compose version >/dev/null 2>&1 || docker-compose version >/dev/null 2>&1 \
  || { echo "FATAL: docker compose unavailable"; exit 1; }
python3 -m pip install -q cryptography blake3 pytest 2>/dev/null || true
python3 -c "import cryptography, blake3" || { echo "FATAL: python deps"; exit 1; }
(python3 -m playwright install chromium >/dev/null 2>&1 && echo "chromium ok") \
  || echo "WARN: no chromium — browser-engine findings will be skipped"

# Common scan invocation (bounded, disclosed; raise the budgets for the FULL
# pass — the numbers below are the full-budget settings for the VPS).
scan() {  # scan <name> <base-url> <max_requests>
  local name="$1" url="$2" budget="$3"
  python3 - "$name" "$url" "$budget" << 'PYEOF'
import json, sys, time
sys.path.insert(0, ".")
name, url, budget = sys.argv[1], sys.argv[2], int(sys.argv[3])
from sentinel.core import EventBus
from sentinel.oast import OastServer
from sentinel.orchestrator import ScanConfig, SentinelScanner
oast = OastServer()
cfg = ScanConfig(allow_private=True, max_pages=60, timeout=12.0,
                 seed=f"vps-{name}", oast=oast, max_requests=budget,
                 browser=True)
t0 = time.time()
rep = SentinelScanner(url, cfg).run()
oast.stop()
out = {"requests": rep["stats"]["requests"],
       "endpoints": rep["stats"]["endpoints"],
       "findings": len(rep["findings"]),
       "wall_seconds": round(time.time()-t0, 1),
       "run_id": rep.get("run_id")}
json.dump(rep, open(f"evidence/{name}_scan.json", "w"), indent=1)
json.dump(out, open(f"evidence/{name}_meta.json", "w"), indent=1)
print(f"{name}: {out}")
PYEOF
}

echo "== [1] DVWA 3.x =="
docker rm -f dvwa >/dev/null 2>&1 || true
docker run -d --name dvwa -p 127.0.0.1:4280:80 vulnerables/web-dvwa
for i in $(seq 1 30); do curl -sf -o /dev/null "http://127.0.0.1:4280/setup.php" && break; sleep 2; done
# DVWA first-run: initialize the DB, set security to low (the scan baseline
# documented in the repo's OWSP campaign), then scan.
curl -s -c /tmp/dvwa.jar "http://127.0.0.1:4280/login.php" -o /dev/null
curl -s -b /tmp/dvwa.jar -c /tmp/dvwa.jar -d "create_db=Create / Reset Database" \
     "http://127.0.0.1:4280/setup.php" -o /dev/null
curl -s -b /tmp/dvwa.jar -c /tmp/dvwa.jar -L \
     -d "username=admin&password=password&Login=Login" \
     "http://127.0.0.1:4280/login.php" -o /dev/null
curl -s -b /tmp/dvwa.jar -c /tmp/dvwa.jar \
     "http://127.0.0.1:4280/security.php" -o /dev/null
curl -s -b /tmp/dvwa.jar -d "security=low&seclev_submit=Submit" \
     "http://127.0.0.1:4280/security.php" -o /dev/null
scan dvwa "http://127.0.0.1:4280" 9000
docker rm -f dvwa >/dev/null

echo "== [2] crAPI (compose) =="
rm -rf crapi && git clone -q https://github.com/OWASP/crAPI.git crapi
( cd crapi && docker compose -f deploy/docker/docker-compose.yml up -d )
for i in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:8888" && break; sleep 3; done
scan crapi "http://127.0.0.1:8888" 9000
( cd crapi && docker compose -f deploy/docker/docker-compose.yml down -v )

echo "== [3] Juice Shop FULL-BUDGET rescan =="
docker rm -f juice-shop >/dev/null 2>&1 || true
docker run -d --name juice-shop -p 127.0.0.1:33000:3000 bkimminich/juice-shop:latest
for i in $(seq 1 30); do curl -sf -o /dev/null "http://127.0.0.1:33000/" && break; sleep 2; done
scan juice-shop-full "http://127.0.0.1:33000" 18000
docker rm -f juice-shop >/dev/null

echo "== [4] WebGoat deep lesson scan =="
docker rm -f webgoat >/dev/null 2>&1 || true
docker run -d --name webgoat -p 127.0.0.1:48080:8080 -p 127.0.0.1:49090:9090 webgoat/webgoat:latest
for i in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:48080/WebGoat/login" && break; sleep 3; done
# register + scan; NOTE the engine-side gap recorded in the Phase-1 report:
# WebGoat's lessons route through #lesson/ fragments — the deep scan needs
# the lesson-endpoint seeding the report describes (until the engine gains
# hash-fragment SPA lesson discovery).
scan webgoat "http://127.0.0.1:48080/WebGoat" 9000
docker rm -f webgoat >/dev/null

echo "== [5] OWASP Benchmark v1.2c =="
docker rm -f benchmark >/dev/null 2>&1 || true
docker run -d --name benchmark -p 127.0.0.1:8443:8443 -p 127.0.0.1:8080:8080 \
    ddierick/benchmark53bad:53b
echo "NOTE: benchmark takes ~2-4 min to deploy its full app set; then:"
echo "      scan benchmark http://127.0.0.1:8080/benchmark 20000"
echo "      and score against expectedresults-1.2.csv (the published truth)"
echo "      (scripted scoring lands with the engine's benchmark runner)"

echo "== DONE — collect evidence/ and return it to the repo =="
ls -la evidence/
