#!/bin/bash
# tomcat_guard.sh — the no-clobber artifact guard for the Tomcat 9.0.85 stack.
# Sourced library, not executed directly.
#
# WHY THIS EXISTS (the flaw this fixes, live-caught 2026-10-14): the assembly
# scripts did `curl -sSL -o tomcat.tgz <url>` — an unconditional overwrite that
# REPLACED a previously-complete tarball with a fresh partial download whenever
# a session died mid-fetch; and `tar xzf` straight into the live tomcat9/ left
# a PARTIAL tree whose mere `bin/catalina.sh` presence then satisfied the
# `[ -x catalina.sh ]` re-entry guard, so re-runs skipped the step believing
# the stack intact. Contract after this fix:
#   1. A file whose completeness is VERIFIED (size + official SHA-512 for the
#      tarball; structural identity + marker for the extracted core) is NEVER
#      written over — fetch resumes only INCOMPLETE files, extraction happens
#      in a temp dir and swaps in only after verification.
#   2. Downloads verify size AND the official Apache SHA-512 before use; a
#      checksum mismatch discards the partial and restarts (bounded).
#   3. The extracted core is verified structurally (key files, exact jar
#      count for the pinned 9.0.85, the 5 stock webapps, the jar's own
#      ServerInfo version) and a marker file records the verification.

# ---- the pinned artifact: Apache Tomcat 9.0.85 (official dist) ----
TC_URL="https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.85/bin/apache-tomcat-9.0.85.tar.gz"
TC_SIZE=11809177
# official sha512, fetched from archive.apache.org .../apache-tomcat-9.0.85.tar.gz.sha512
TC_SHA512="06e239d15ff7b72017c1d0752ddb1be4651374f7c1391631ec5619f4981cb2911267bc6b044d6c71a2a74738f70d433b96418951439848121f1d874862ddd3de"
TC_MARKER_NAME=".stack_core_verified"

# tarball_verified <file> — size == official AND sha512 == official
tarball_verified() {
  local f="$1"
  [ -f "$f" ] || return 1
  [ "$(stat -c%s "$f" 2>/dev/null)" = "$TC_SIZE" ] || return 1
  [ "$(sha512sum "$f" 2>/dev/null | cut -d' ' -f1)" = "$TC_SHA512" ] || return 1
  return 0
}

# tomcat_core_verified <dir> — structural completeness of a stock 9.0.85 core
# (the deployed benchmark webapp may ALSO be present; it does not interfere).
tomcat_core_verified() {
  local d="$1"
  [ -x "$d/bin/catalina.sh" ] && [ -f "$d/bin/startup.sh" ] || return 1
  [ -f "$d/conf/server.xml" ] && [ -f "$d/conf/web.xml" ] && [ -f "$d/conf/catalina.properties" ] || return 1
  [ -f "$d/lib/catalina.jar" ] || return 1
  # the pinned 9.0.85 ships exactly 32 jars in lib/
  [ "$(find "$d/lib" -maxdepth 1 -name '*.jar' 2>/dev/null | wc -l)" = "32" ] || return 1
  # all 5 stock webapps must survive a complete extraction (they sit at the
  # tail of the tar stream — a truncated tarball loses them first)
  local w
  for w in ROOT docs examples host-manager manager; do
    [ -d "$d/webapps/$w" ] || return 1
  done
  # stock core = 637 files; anything below 600 is a partial extraction
  [ "$(find "$d" -type f 2>/dev/null | wc -l)" -ge 600 ] || return 1
  # version identity from the jar itself, not from a filename
  unzip -p "$d/lib/catalina.jar" org/apache/catalina/util/ServerInfo.properties 2>/dev/null \
    | grep -q "server.number=9.0.85" || return 1
  return 0
}

# write_core_marker <dir> <provenance-note>
write_core_marker() {
  local d="$1" note="$2"
  printf 'verified: %s\nmethod: %s\nsource_sha512: %s\nstock_file_count_min: 600\nversion: Apache Tomcat 9.0.85 (ServerInfo)\n%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$note" "$TC_SHA512" "$(find "$d" -type f | wc -l) files on disk at verification" \
    > "$d/$TC_MARKER_NAME"
}

# fetch_tarball <out-file> — guarded fetch. NEVER writes over a verified file;
# resumes only incomplete ones; verifies size+sha512; bounded restarts on
# checksum mismatch.
fetch_tarball() {
  local out="$1"
  if tarball_verified "$out"; then
    echo "[fetch] $out already complete + SHA-512 verified — NOT touching it"
    return 0
  fi
  local restarts=0
  while :; do
    local s
    while :; do
      s=0
      [ -f "$out" ] && s=$(stat -c%s "$out" 2>/dev/null || echo 0)
      [ "$s" -ge "$TC_SIZE" ] && break
      echo "[fetch] resuming from $s/$TC_SIZE bytes ($(date -u +%H:%M:%S))"
      # -C - : resume; only ever appends to an INCOMPLETE file (verified files
      # never reach this line — checked at entry and after every completion)
      curl -sSL --speed-time 40 --speed-limit 256 -C - -o "$out" "$TC_URL" || true
      sleep 3
    done
    if tarball_verified "$out"; then
      echo "[fetch] complete + SHA-512 verified ($(stat -c%s "$out") bytes)"
      return 0
    fi
    restarts=$((restarts+1))
    if [ "$restarts" -ge 3 ]; then
      echo "[fetch] FAILED: size reached but SHA-512 mismatch after 3 tries — honest abort"
      rm -f "$out"
      return 1
    fi
    echo "[fetch] checksum mismatch — discarding the corrupt partial, full restart $restarts/2"
    rm -f "$out"
  done
}

# extract_core <tgz> <dest-dir> — verified extraction with an atomic swap.
# Callers MUST first check `tomcat_core_verified <dest-dir>`; this function
# also refuses to run against a verified dest (belt and braces).
extract_core() {
  local tgz="$1" dest="$2"
  tarball_verified "$tgz" || { echo "[extract] REFUSED: tarball not SHA-512 verified: $tgz"; return 1; }
  if tomcat_core_verified "$dest"; then
    echo "[extract] $dest already structurally verified — NOT touching it"
    return 0
  fi
  local tmp="${dest}.new.$$"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  if ! tar xzf "$tgz" -C "$tmp" --strip-components=1; then
    rm -rf "$tmp"
    echo "[extract] tar FAILED on a verified tarball — aborting (no clobber happened)"
    return 1
  fi
  if ! tomcat_core_verified "$tmp"; then
    rm -rf "$tmp"
    echo "[extract] extracted tree FAILED structural verification — aborting (no clobber happened)"
    return 1
  fi
  # swap in: the old tree (incomplete by definition — verified trees returned
  # above) is moved aside, the verified new tree takes its place
  rm -rf "${dest}.old"
  if [ -e "$dest" ]; then mv "$dest" "${dest}.old"; fi
  mv "$tmp" "$dest"
  rm -rf "${dest}.old"
  write_core_marker "$dest" "extracted from SHA-512-verified tarball"
  echo "[extract] verified extraction swapped into $dest (marker written)"
  return 0
}
