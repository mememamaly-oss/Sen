#!/bin/bash
# v4.3.3 + iv14 sink-context transfer — FULL GATE CYCLE (suite half).
# Round 2026-10-12b: branch fix/openredirect-sinkcontext-433 from origin/main
# 412d64f (supervisor order: re-apply the previously-proven open_redirect fix,
# RED/GREEN + full gate, clean small commit, push to main; touch nothing else).
# Full unit suite in resumable foreground chunks (the environment kills calls
# >600s; cached chunk results make retries cheap), durable per-chunk copies,
# then the every-case-accounted-for check. Doctor + bench x3 run as separate
# steps (see gate_v433_sinkcontext_verify.py). Same proven 12-chunk scheme as
# the Task-32/33 rounds; the transferred test unit_v423_open_redirect_sink_context
# lands in c4_rest_a via the unit_v prefix.
set -u
WT="$(cd "$(dirname "$0")/.." && pwd)"
ENG="$WT/build-v430"
# FRESH cache this round (never reuse a previous round's chunk results —
# every number must come from THIS round's runs):
CACHE=/tmp/v433_sink_chunks_r16
KEEP="$ENG/results/verify_v433_sinkcontext/chunks"
mkdir -p "$CACHE" "$KEEP"
cd "$ENG" || exit 1

declare -a CHUNKS=(
  "c0_v43x:regression_v433,regression_v432"
  "c1_gtp_max:unit_gtp,unit_max"
  "c2_owsp:unit_owsp"
  "c3_l_eng:unit_l,unit_eng,unit_auth,unit_disc"
  "c4_rest_a:unit_v,unit_s,unit_c,unit_p,unit_h,unit_r,unit_o,unit_b"
  "c5_rest_b:unit_i,unit_j,unit_f,unit_w,unit_d,unit_n,unit_m,unit_e,unit_u,unit_k,unit_q,unit_t,unit_g12"
  "c6_reg_a:regression_v4,regression_timeout,regression_verif,regression_xss,regression_engine,regression_websocket,regression_graphql"
  "c7_reg_b:regression_form,regression_scope,chaos_"
  "c8_reg_c:regression_benchmark,regression_js,regression_sqli,regression_inline,regression_crlf,regression_vuln"
  "c9_reg_d:regression_ssrf,regression_rest,regression_cli,e2e_,regression_auth,regression_phase5"
  "c10_reg_e:regression_crawl,regression_store,regression_report,regression_eng0"
  "c11_reg_f:regression_oob_blind"
)
# regression_oob_public_channel_end_to_end EXCLUDED — the SAME documented
# runner-only env stall exclusion as every shipped v4.3.x round and the
# Task-32/33 audits (standalone proof on the v4.3.1 tree: hangs on pristine
# via git-stash, so not an engine defect).

for entry in "${CHUNKS[@]}"; do
  name="${entry%%:*}"; filt="${entry#*:}"
  out="$CACHE/$name.json"
  if [ -f "$out" ] && python3 -c "
import json,sys
try: d=json.load(open('$out'))
except Exception:
    d,_=json.JSONDecoder().raw_decode(open('$out').read().lstrip())
sys.exit(0 if d.get('passed') else 1)" 2>/dev/null; then
    echo "chunk $name: cached PASS"
    continue
  fi
  echo "=== chunk $name (filter: $filt) ==="
  SENTINEL_TEST_FILTER="$filt" timeout 560 python3 tests/run_tests.py all > "$out" 2>"$out.err"
  rc=$?
  cp -f "$out" "$KEEP/" 2>/dev/null || true
  cp -f "$out.err" "$KEEP/" 2>/dev/null || true
  python3 - "$out" "$rc" << 'PY' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    try:
        raw = open(sys.argv[1]).read()
        d, _ = json.JSONDecoder().raw_decode(raw.lstrip())
    except Exception as e:
        print(f"  CHUNK OUTPUT INVALID: {e}"); sys.exit(1)
ran = [c for c in d["cases"] if not c.get("skipped")]
fails = [c for c in ran if not c["ok"]]
print(f"  ran={len(ran)} failed={len(fails)} passed={d['passed']}")
for c in fails:
    print(f"    FAIL {c['name']}: {c.get('error','')[:140]}")
PY
  if [ "$rc" -ne 0 ]; then echo "  chunk $name rc=$rc — inspect $out.err"; fi
done

# ---- final accounting: every case exactly once, all green ----
python3 - << PY
import json, glob, re
src = open("$ENG/tests/run_tests.py").read()
all_names = set(re.findall(r"@case\ndef (\w+)", src))
seen, dup = {}, []
for f in sorted(glob.glob("$CACHE/c*.json")):
    try:
        d = json.load(open(f))
    except Exception:
        try:
            raw = open(f).read()
            d, _ = json.JSONDecoder().raw_decode(raw.lstrip())
        except Exception:
            continue
    for c in d["cases"]:
        if c.get("skipped"):
            continue
        if c["name"] in seen:
            dup.append(c["name"])
        seen[c["name"]] = c["ok"]
EXCLUDED = {"regression_oob_public_channel_end_to_end"}   # documented env stall
missing = all_names - set(seen) - EXCLUDED
dup_real = [d for d in dup if seen.get(d) is False]
failed = [n for n, ok in seen.items() if not ok]
summary = (f"cases total={len(all_names)} covered={len(seen)} excluded={len(EXCLUDED)} "
           f"missing={len(missing)} dup={len(dup)} failed={len(failed)}")
print(summary)
if missing: print("MISSING:", sorted(missing)[:12])
if failed: print("FAILED:", failed[:12])
print("SUITE VERDICT:", "PASS" if not missing and not failed else "FAIL")
import os
os.makedirs("$ENG/results/verify_v433_sinkcontext", exist_ok=True)
with open("$ENG/results/verify_v433_sinkcontext/suite_summary.txt", "w") as fh:
    fh.write(summary + "\n" + ("PASS" if not missing and not failed else "FAIL") + "\n")
PY
