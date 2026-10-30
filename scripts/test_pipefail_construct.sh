#!/bin/bash
# Verify the package.json dev/start pipefail construct propagates exit codes.
# Success pipeline -> 0 ; failing pipeline -> its code ; tee still captures output.
set -u
TMP=$(mktemp)

# 1) success case
bash -c "set -o pipefail; echo hello 2>&1 | tee $TMP" >/dev/null
rc_ok=$?

# 2) failure case
bash -c "set -o pipefail; (echo dying; exit 3) 2>&1 | tee $TMP" >/dev/null
rc_bad=$?

# 3) tee captured the output of the failing command
captured=$(cat "$TMP" | tail -1)
rm -f "$TMP"

echo "success-case exit: $rc_ok (expect 0)"
echo "failure-case exit: $rc_bad (expect 3)"
echo "tee captured:      '$captured' (expect 'dying')"

if [ "$rc_ok" -eq 0 ] && [ "$rc_bad" -eq 3 ] && [ "$captured" = "dying" ]; then
  echo "PIPEFAIL FIX VERIFIED"
  exit 0
fi
echo "PIPEFAIL FIX FAILED"
exit 1
