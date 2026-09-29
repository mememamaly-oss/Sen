#!/bin/bash
# Build the complete SENTINEL archive (beginning to end) into download/
set -e

BASE=/home/z/my-project
DL=$BASE/download
STAGE=$DL/.stage-full-archive
ARCHIVE=$DL/SENTINEL-FULL-ARCHIVE-v2.6.0.zip

rm -rf "$STAGE" "$ARCHIVE"
mkdir -p "$STAGE/SENTINEL-FULL-ARCHIVE"/{01-versions,02-results,04-docs}

# 1) All version packages 2.0.0 -> 2.6.0 (source + complete bundles)
cp "$DL"/sentinel-*.zip "$STAGE/SENTINEL-FULL-ARCHIVE/01-versions/"

# 2) All real-test results, reports, DBs, fonts, test-scripts
cp -r "$DL/sentinel-results" "$STAGE/SENTINEL-FULL-ARCHIVE/02-results"

# 3) Current authoritative source tree v2.6.0 (beginning-to-end working code)
mkdir -p "$STAGE/SENTINEL-FULL-ARCHIVE/03-source-v2.6.0"
cd "$BASE/verify-live"
find . -type d -name __pycache__ -prune -o -type f ! -name '*.db-shm' ! -name '*.db-wal' -print0 \
  | xargs -0 cp --parents -t "$STAGE/SENTINEL-FULL-ARCHIVE/03-source-v2.6.0"

# 4) Documentation: master worklog + changelog
cp "$BASE/worklog.md" "$STAGE/SENTINEL-FULL-ARCHIVE/04-docs/WORKLOG.md"
cp "$BASE/verify-live/CHANGELOG.md" "$STAGE/SENTINEL-FULL-ARCHIVE/04-docs/"

# 5) Zip it
cd "$STAGE"
zip -r -q "$ARCHIVE" SENTINEL-FULL-ARCHIVE
rm -rf "$STAGE"

echo "=== ARCHIVE BUILT ==="
ls -la "$ARCHIVE"
echo "=== INTEGRITY TEST ==="
unzip -t "$ARCHIVE" > /dev/null && echo "ZIP OK"
echo "=== CONTENT COUNTS ==="
unzip -l "$ARCHIVE" | tail -1
echo "by section:"
unzip -l "$ARCHIVE" | awk -F'  +' 'NR>3 && $NF ~ /^SENTINEL/ {split($NF,a,"/"); if(a[2]!="") s[a[2]]++} END {for (k in s) printf "  %-22s %d files\n", k, s[k]}' | sort
