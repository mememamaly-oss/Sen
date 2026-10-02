#!/bin/bash
# SENTINEL v4.1 final gates — chunked unit-suite runner (resume-safe, strict).
# Usage: bash v41_unit_chunks.sh <chunk-number>
# Strict accounting: a chunk only counts as done when >=1 test RAN and 0 failed.
set -u
cd /home/z/my-project/build-v410 || exit 1
N="${1:?chunk number required}"
LOG=/tmp/v41_unit_verdicts.log

declare -a CHUNKS
CHUNKS[1]="scope_blocks_private,param_classification,planner_deterministic,finding_fingerprint_stable,wilson_sample_size_aware,strategy_ordering_deterministic,repair_classifier_rules,dedup_pipeline,eng20_benchmark_owned_fixture"
CHUNKS[2]="oast_server_records_interactions,public_oast_provider_protocol,make_oast_channel_policy,cors_detector_and_fresh_origin_verify,disc10_divform_parsing,disc11_dom_sink_scanner,eng04_json_body_render,eng05_cookie_jar_session_continuity"
CHUNKS[3]="eng06_body_serialization_without_mutation,eng07_cookie_refresh_across_redirect_hops,auth01_form_intelligent_login,waf_fingerprinter_named_signatures,tech_fingerprinter_platform_map,eng09_rate_limit_backoff,auth05_token_bearer_modes"
CHUNKS[4]="op02_sarif_export,disc13_openapi_seed,paramintel_value_shape_inference,coverage_tracker_accounting,secrets_scanner_classification_and_gates,evidence_impact_profiles"
CHUNKS[5]="phase55_detectors_and_gates,authz_engine_matrix_idor_vertical,phase57_vault_crypto_lifecycle"
CHUNKS[6]="phase58_workflow_engine,eng15_csrf_state_classifier,eng16_workflow_anchor_query_params,eng17_discovery_select_params"
CHUNKS[7]="twin_graph_fusion,twin_entity_and_action_typing,twin_authorization_matrix_projection,planner_safety_gates,reasoning_hypothesis_lifecycle"
CHUNKS[8]="evidence_os_proof_files,workflow_cross_identity_preconditions,report_executive_and_glass"
CHUNKS[9]="v41_boundary_engine,v41_coverage_dimensions,v41_workflow_graph_model,v41_twin_provenance,v41_reasoning_records,v41_memory,v41_replay,v41_planner_realtime_and_ci,v41_apintel_and_action_matrix,v41_no_hallucination_gate"

if rg -q "^chunk $N OK " "$LOG" 2>/dev/null; then
  echo "chunk $N already done: $(rg "^chunk $N " "$LOG")"; exit 0
fi

# build the filter with the unit_ prefix the runner matches on
F=$(echo "${CHUNKS[$N]}" | sed 's/[^,]*/unit_&/g')
CNT=$(echo "${CHUNKS[$N]}" | tr ',' '\n' | wc -l)
echo "=== chunk $N ($CNT tests) ==="
START=$(date +%s)
SENTINEL_TEST_FILTER="$F" python3 tests/run_tests.py unit > "/tmp/v41_chunk_$N.json" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))

python3 - "$N" "$CNT" "$ELAPSED" <<'PYEOF'
import json, sys
n, cnt, el = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(f"/tmp/v41_chunk_{n}.json", errors="replace").read()
d = json.loads(raw[raw.find("{"):])
cases = d.get("cases", [])
ran = [c for c in cases if not c.get("skipped")]
failed = [c for c in ran if not c.get("ok")]
line = (f"chunk {n} {'OK' if ran and not failed else 'FAIL'} "
        f"ran={len(ran)}/{cnt} failed={len(failed)} elapsed={el}s")
open("/tmp/v41_unit_verdicts.log", "a").write(line + "\n")
print(line)
for c in failed:
    print("  FAILED:", c["name"])
PYEOF
