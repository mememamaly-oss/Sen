"""PART 1 re-execution (2026-10-31): REAL fetch of the official BLAKE3
test_vectors.json from the reference repository, then verify:
  (1) live sentinel.blake3() vs EVERY official vector (hash mode, 32B);
  (2) the 35 literals embedded in tests/test_axis3_pcs.py vs official;
  (3) scripts/crypto_remediation/blake3_preswap_capture.json vs official
      (pre-swap byte-consistency evidence);
  (4) the extra 0..5-byte probes in the capture, live;
  (5) bonus: the blake3 PACKAGE itself vs official keyed_hash vectors
      (proves the binding is the reference implementation).
Prints facts only; exits non-zero on any mismatch."""
import hashlib
import json
import re
import sys
import urllib.request

URL = ("https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/"
       "master/test_vectors/test_vectors.json")

sys.path.insert(0, "/home/z/my-project")
from sentinel.blake3 import blake3  # noqa: E402

import blake3 as blake3_pkg  # the official package directly  # noqa: E402


def gen(n):
    """Official input rule: input[i] = i % 251."""
    return bytes(i % 251 for i in range(n))


def main():
    print("== [1] real fetch ==")
    print("url:", URL)
    req = urllib.request.Request(URL, headers={"User-Agent": "p1-reverify"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
    print("bytes:", len(raw))
    official = json.loads(raw)
    cases = official["cases"]
    print("cases:", len(cases))
    print("input_len list:", [c["input_len"] for c in cases])
    key_field = official["key"]
    key = key_field.encode() if isinstance(key_field, str) else bytes(key_field)
    print("key field repr:", repr(key_field)[:60],
          "| encoded bytes:", len(key))

    fails = 0

    print("== [2] live sentinel.blake3() vs ALL official vectors ==")
    for c in cases:
        n = c["input_len"]
        expected = c["hash"][:64]  # first 32 bytes of extended output
        got = blake3(gen(n)).hex()
        if got != expected:
            print(f"MISMATCH len={n}: expected {expected} got {got}")
            fails += 1
    print(f"hash-mode checked: {len(cases)} vectors, mismatches: {fails}")

    print("== [3] bonus: package keyed_hash vs official ==")
    kfails = 0
    if len(key) == 32:
        for c in cases:
            n = c["input_len"]
            expected = c["keyed_hash"][:64]
            got = blake3_pkg.blake3(gen(n), key=key).digest().hex()
            if got != expected:
                print(f"KEYED MISMATCH len={n}")
                kfails += 1
        print(f"keyed checked: {len(cases)} vectors, mismatches: {kfails}")
    else:
        print("keyed check SKIPPED: official key field is not a 32-byte "
              f"string (len={len(key)}); hash mode is the audited contract")
    fails += kfails

    print("== [4] literals in tests/test_axis3_pcs.py vs official ==")
    src = open("/home/z/my-project/tests/test_axis3_pcs.py",
               encoding="utf-8").read()
    embedded = dict((int(a), b) for a, b in
                    re.findall(r"\((\d+), \"([0-9a-f]{64})\"\)", src))
    print("embedded vector count:", len(embedded))
    official_map = {c["input_len"]: c["hash"][:64] for c in cases}
    if embedded != official_map:
        diffs = {k: (embedded.get(k), official_map.get(k))
                 for k in set(embedded) | set(official_map)
                 if embedded.get(k) != official_map.get(k)}
        print("EMBEDDED != OFFICIAL:", diffs)
        fails += 1
    else:
        print("embedded literals == official file: EXACT (all",
              len(official_map), "vectors)")

    print("== [5] pre-swap capture vs official (byte-consistency evidence) ==")
    cap = json.load(open("/home/z/my-project/scripts/crypto_remediation/"
                         "blake3_preswap_capture.json", encoding="utf-8"))
    cap_off = {int(k): v for k, v in cap["official_vectors"].items()}
    print("capture official_vectors count:", len(cap_off))
    if cap_off != official_map:
        bad = {k for k in set(cap_off) | set(official_map)
               if cap_off.get(k) != official_map.get(k)}
        print("CAPTURE != OFFICIAL at lengths:", sorted(bad))
        fails += 1
    else:
        print("pre-swap capture == official file: EXACT (old implementation",
              "byte-identical to reference — proven)")

    print("== [6] extra probes (FIXED input list per capture generator), live ==")
    EXTRAS = [b"", b"abc", b"sentinel-pcs-empty-v1", bytes(1024),
              bytes(range(256)) * 5, b"\x00" * 100000]
    for i, e in enumerate(EXTRAS):
        rec = cap["extra_probes"][str(i)]
        b3 = blake3(e).hex()
        s2 = hashlib.sha256(e).hexdigest()
        ok = (b3 == rec["blake3_hex"]) and (s2 == rec["sha256_input"])
        label = e[:24].decode("latin-1").replace("\x00", ".")
        print(f"  probe {i} (input~{label!r}, {len(e)}B): "
              f"blake3 {'OK' if b3 == rec['blake3_hex'] else 'MISMATCH'}"
              f", sha256 {'OK' if s2 == rec['sha256_input'] else 'MISMATCH'}")
        if not ok:
            fails += 1

    print("== [7] type contract live ==")
    try:
        blake3("not-bytes")
        print("TypeError contract: BROKEN (no raise)")
        fails += 1
    except TypeError:
        print("TypeError contract: OK")
    ok_alias = (blake3(bytearray(b"abc")) == blake3(b"abc") ==
                blake3(memoryview(b"abc")) == blake3(b"abc"))
    print("bytes/bytearray/memoryview aliasing:", "OK" if ok_alias else "BROKEN")
    if not ok_alias:
        fails += 1

    print("TOTAL MISMATCHES:", fails)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
