#!/bin/bash
# SENTINEL v4.1.1 gap-validation gates — chunked regression runner (resume-safe).
# Same discipline as v41_regr_chunks.sh, against build-v411 with the V411 cases.
set -u
cd /home/z/my-project/build-v411 || exit 1
LOG=/tmp/v411_regr_verdicts.log
touch "$LOG"

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
CHUNKS[11]="v411_authz_token_accounts"
CHUNKS[chaos]="timeouts_fail_safe,connection_reset_fail_safe,garbage_and_huge_fail_safe,strategy_store_counts_only_verified,reproducible_run_ids"

N="${1:?chunk id required}"
KEY="${CHUNKS[$N]+x}"
[ -z "$KEY" ] && { echo "unknown chunk: $N"; exit 1; }

if grep -q "^chunk $N OK " "$LOG" 2>/dev/null; then
  echo "chunk $N already done: $(grep "^chunk $N " "$LOG")"; exit 0
fi

if [ "$N" = "chaos" ]; then
  F=$(echo "${CHUNKS[$N]}" | sed 's/[^,]*/chaos_&/g')
else
  F=$(echo "${CHUNKS[$N]}" | sed 's/[^,]*/regression_&/g')
fi
OUT=/tmp/v411_chunk_$N.json
if SENTINEL_TEST_FILTER="$F" timeout 560 python3 tests/run_tests.py > "$OUT" 2>&1; then
  RAN=$(python3 - "$OUT" <<'PYEOF'
import json, re, sys
raw = open(sys.argv[1]).read()
m = re.search(r'\{[\s\S]*\}', raw)
d = json.loads(m.group(0))
ran = [c for c in d["cases"] if not c.get("skipped")]
print(f"{len(ran)}:{d['failed']}")
PYEOF
)
  RANNUM="${RAN%%:*}"; FAILNUM="${RAN##*:}"
  if [ "$FAILNUM" = "0" ] && [ "$RANNUM" -gt 0 ]; then
    echo "chunk $N OK ran=$RANNUM failed=0" | tee -a "$LOG"
    exit 0
  fi
fi
echo "chunk $N FAIL" | tee -a "$LOG"
exit 1
