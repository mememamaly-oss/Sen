#!/bin/bash
# SENTINEL v4.1 final gates — chunked regression+chaos runner (resume-safe).
# Usage: bash v41_regr_chunks.sh <chunk-number|chaos>
set -u
cd /home/z/my-project/build-v410 || exit 1
N="${1:?chunk id required}"
LOG=/tmp/v41_regr_verdicts.log

declare -A CHUNKS
CHUNKS[1]="timeout_repair_rule,verification_rejects_false_candidate,xss_verifier_waf_bypass,xss_verifier_rejects_encoded_only,engine_preserves_redirect_oracle_e2e"
CHUNKS[2]="form_param_location_follows_method,scope_blocks_metadata_service,benchmark_autostarts_fixture,js_url_extraction_rejects_code_fragments,sqli_or_redirect_oracle,inline_js_url_extraction"
CHUNKS[3]="sqli_quote500_and_orpair_oracles,sqli_orpair_bodydiff_verification_path_d,xss_slashfree_canary,crlf_header_injection_and_xxe_live,vuln_js_dependency_passive,crawl_preserves_link_query"
CHUNKS[4]="store_persistence_and_intelligence,report_builder_outputs,oob_blind_xxe_end_to_end,oob_public_channel_end_to_end"
CHUNKS[5]="eng08_self_callback_guard,ssrf_cmdi_cors_end_to_end,rest_api_server,cli_script_mode_all_subcommands"
CHUNKS[6]="auth_scan_finds_gated_surface_and_anonymous_does_not,auth03_watchdog_reauth_midscan,phase54_ops_stealth_composition"
CHUNKS[7]="phase55_five_classes_end_to_end,phase56_intelligence_end_to_end"
CHUNKS[8]="phase57_vault_end_to_end,phase58_logic_end_to_end"
CHUNKS[9]="v41_flows_battery,v41_graphql_battery,v41_websocket_battery"
CHUNKS[10]="v41_self_security,v41_full_platform"
CHUNKS[chaos]="timeouts_fail_safe,connection_reset_fail_safe,garbage_and_huge_fail_safe,strategy_store_counts_only_verified,reproducible_run_ids"

KEY="${CHUNKS[$N]+x}"
[ -z "$KEY" ] && { echo "unknown chunk: $N"; exit 1; }

if rg -q "^chunk $N OK " "$LOG" 2>/dev/null; then
  echo "chunk $N already done: $(rg "^chunk $N " "$LOG")"; exit 0
fi

if [ "$N" = "chaos" ]; then
  F=$(echo "${CHUNKS[$N]}" | sed 's/[^,]*/chaos_&/g')
  SUITE=chaos
else
  F=$(echo "${CHUNKS[$N]}" | sed 's/[^,]*/regression_&/g')
  SUITE=regression
fi
CNT=$(echo "${CHUNKS[$N]}" | tr ',' '\n' | wc -l)
echo "=== $SUITE chunk $N ($CNT tests) ==="
START=$(date +%s)
SENTINEL_TEST_FILTER="$F" python3 tests/run_tests.py "$SUITE" > "/tmp/v41_regr_$N.json" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))

python3 - "$N" "$CNT" "$ELAPSED" <<'PYEOF'
import json, sys
n, cnt, el = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(f"/tmp/v41_regr_{n}.json", errors="replace").read()
d = json.loads(raw[raw.find("{"):])
cases = d.get("cases", [])
ran = [c for c in cases if not c.get("skipped")]
failed = [c for c in ran if not c.get("ok")]
line = (f"chunk {n} {'OK' if ran and not failed else 'FAIL'} "
        f"ran={len(ran)}/{cnt} failed={len(failed)} elapsed={el}s")
open("/tmp/v41_regr_verdicts.log", "a").write(line + "\n")
print(line)
for c in failed:
    print("  FAILED:", c["name"], c.get("error", "")[:200])
PYEOF
