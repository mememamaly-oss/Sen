#!/bin/bash
# Persistent Tomcat 9.0.85 fetch — NO-CLOBBER CONTRACT (see tomcat_guard.sh):
# a verified-complete tarball is never written over; only incomplete files
# are resumed; the official Apache SHA-512 is checked before the file is
# declared usable. Usage: tomcat_fetch.sh [output-file]
set -u
GUARD=/home/z/my-project/scripts/owsp/tomcat_guard.sh
# shellcheck source=tomcat_guard.sh
source "$GUARD" || { echo "cannot source $GUARD"; exit 1; }
OUT="${1:-/home/z/tools/tomcat.tgz}"
mkdir -p "$(dirname "$OUT")"
fetch_tarball "$OUT"
