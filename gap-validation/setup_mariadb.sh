#!/bin/bash
# Userspace MariaDB (no root) for DVWS — extract Debian debs into a local prefix.
set -e
P=/home/z/my-project/gap-validation/tools/mariadb
M=/home/z/my-project/gap-validation/tools/debs
mkdir -p $P $M
cd $M
BASE=https://deb.debian.org/debian/pool/main
for f in \
  "m/mariadb/mariadb-server-core_11.8.8-0+deb13u1_amd64.deb" \
  "m/mariadb/mariadb-server_11.8.8-0+deb13u1_amd64.deb" \
  "m/mariadb/mariadb-client-core_11.8.8-0+deb13u1_amd64.deb" \
  "m/mariadb/mariadb-common_11.8.8-0+deb13u1_all.deb" \
  ; do
  n=$(basename $f)
  [ -f "$n" ] || timeout 120 curl -sL "$BASE/$f" -o "$n"
  echo "downloaded: $n $(stat -c%s $n)"
done
# libaio1 (soname libaio.so.1) — try libaio1t64 (trixie) then libaio1
timeout 60 curl -sL "$BASE/liba/libaio/libaio1t64_0.3.113-8+b1_amd64.deb" -o libaio.deb || true
[ -s libaio.deb ] || timeout 60 curl -sL "$BASE/liba/libaio/libaio1_0.3.112-9_amd64.deb" -o libaio.deb
echo "libaio: $(stat -c%s libaio.deb)"
# libnuma1 if present
timeout 60 curl -sL "$BASE/n/numactl/libnuma1_2.0.19-1_amd64.deb" -o libnuma.deb || true
echo "libnuma: $(stat -c%s libnuma.deb 2>/dev/null || echo missing)"
# extract
for d in mariadb-server-core_*.deb mariadb-server_11.8.8*.deb mariadb-client-core_*.deb mariadb-common_*.deb libaio.deb libnuma.deb; do
  [ -f "$d" ] && dpkg-deb -x "$d" $P
done
echo "=== layout ==="
ls $P/usr/bin/ 2>/dev/null | head -12
ls $P/usr/sbin/ 2>/dev/null | head -12
echo "=== ldd mariadbd ==="
LD_LIBRARY_PATH=$P/usr/lib/x86_64-linux-gnu ldd $P/usr/sbin/mariadbd 2>&1 | grep -Ei "not found|libaio|libnuma|libssl|libc " | head -10
