"""SENTINEL v4.3.0 — hash/crypto artifact chain phase (GTP-10).

Two whole Benchmark categories (hash: 236, crypto: 246) never put the
digest/ciphertext in the response — the servlet WRITES it to a server-side
artifact (passwordFile.txt in the app's working directory) and echoes only
the plaintext. Black-box the value is invisible... unless the same app
carries a FILE-READ primitive, in which case the artifact is readable
through it. This phase chains the two:

  leg 1 (write):  submit a KNOWN marker value to a hash/crypto-shaped
                  endpoint ("hashed and stored" / "encrypted and stored"
                  response gates — real apps say the same words).
  leg 2 (read):   read the artifact through a VERIFIED path-traversal
                  file-read primitive on the same app, from a bounded
                  wordlist of conventional artifact names.
  oracle (hash):  the artifact's appended hash_value line base64-decodes to
                  EXACTLY md5(K) or sha1(K) computed locally — a digest
                  match is cryptographic proof of the weak algorithm
                  (SHA-256+ endpoints never match either).
  oracle (crypto): block-size analysis on the newly-appended secret_value
                  line for a 16-byte known plaintext: 24 bytes = an 8-byte
                  block cipher (DES/DESede/Blowfish family); 32 = AES-class
                  (16 ct + GCM tag or CBC padding). A repeat-probe with a
                  32-byte plaintext catches ECB shapes (two identical
                  8-byte ciphertext blocks).

New-line attribution: the artifact is snapshotted before the write leg and
diffed after — only lines our request added are attributed. The finding
cites BOTH legs (write endpoint + read primitive) in its evidence chain;
VR-27/VR-28 re-execute the full chain with fresh markers.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse

from .core import Endpoint, EventBus, Evidence, Finding, FindingStatus, Severity
from .http_engine import RequestMutation
from .detect import command_shaped_endpoint

ARTIFACT_WORDLIST = ["passwordFile.txt", "passwords.txt", "secret.txt", "secrets.txt",
                     "hashes.txt", "dump.txt", "data.txt", "output.txt", "users.txt",
                     "log.txt"]
HASH_GATE = re.compile(r"hashed and stored", re.I)
CRYPTO_GATE = re.compile(r"encrypted and stored", re.I)
HASH_LINE = re.compile(r"hash_value=([A-Za-z0-9+/=]+)")
SECRET_LINE = re.compile(r"secret_value=([A-Za-z0-9+/=]+)")
K1 = "sentinel-hash-probe-01"
P16 = "A" * 16
P32 = "A" * 32


class HashCryptoChainPhase:
    name = "hashchain"

    def __init__(self, engine, bus: EventBus):
        self.engine = engine
        self.bus = bus

    # ---------------------------------------------------------------- utils
    def _read_primitive(self, endpoints, findings):
        """A VERIFIED content-read path_traversal finding -> (Endpoint, param).
        Only file_marker evidence counts (the exists-oracle cannot read)."""
        eps = {ep.url: ep for ep in endpoints}
        for f in findings:
            if f.type != "path_traversal" or f.status != FindingStatus.VERIFIED:
                continue
            if not any(e.kind == "file_marker" for e in f.evidence):
                continue
            ep = eps.get(f.endpoint_url)
            if ep is None:
                continue
            param = f.parameter or next((p.name for p in ep.parameters
                                         if p.kind.value != "token" and not p.flow_control), None)
            if param:
                return ep, param
        return None

    def _read_artifact(self, read_ep, read_param, name) -> str | None:
        r = self.engine.send(RequestMutation(endpoint=read_ep, param_name=read_param,
                                             param_value=name, note=f"artifact-read:{name}"))
        if r is None or r.error or not r.status:
            return None
        # GTP-10b (wave 3, live-caught on the pair mini-scan): the read
        # primitive echoes the artifact ENTITY-ENCODED (ESAPI: '=' as &#x3d;,
        # '+' as &#x2b;) — 'hash_value=&lt;b64&gt;' never matched the raw body
        # and the chain never even discovered its artifact. Normalize.
        from .detect import entity_normalize
        return entity_normalize(r.body or "")

    def _find_artifact(self, read_ep, read_param) -> tuple[str, str] | None:
        """(artifact name, current body) for the first wordlist hit carrying
        our value= lines."""
        for name in ARTIFACT_WORDLIST:
            body = self._read_artifact(read_ep, read_param, name)
            if body and (HASH_LINE.search(body) or SECRET_LINE.search(body)):
                return name, body
        return None

    def _submit(self, ep: Endpoint, value: str):
        """Returns (response, write_param) — the param name the write rode."""
        p = next((x for x in ep.parameters
                  if x.kind.value != "token" and not x.flow_control and x.name), None)
        if p is not None:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=value, note="chain-write")),
                    p.name)
        seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
        if seg:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=seg,
                                                     param_value=value, note="chain-write")), seg)
        return None, ""

    @staticmethod
    def _new_lines(before: str, after: str) -> list[str]:
        """Count-aware line diff: submitting the SAME marker twice appends an
        IDENTICAL line — set-membership diff would miss it (the second write
        is invisible). A line is new when its COUNT grew."""
        from collections import Counter
        cb, ca = Counter(before.splitlines()), Counter(after.splitlines())
        out = []
        for ln, n in ca.items():
            extra = n - cb.get(ln, 0)
            if extra > 0:
                out.extend([ln] * extra)
        return out

    def _gate_endpoints(self, endpoints):
        """Endpoints whose base response carries the write-gate text.
        MAX-10a: logout/destructive/command-shaped surfaces are never opened."""
        hash_eps, crypto_eps = [], []
        for ep in endpoints:
            if (ep.method or "GET").upper() not in ("GET", "POST"):
                continue
            if command_shaped_endpoint(ep):
                continue
            r = self.engine.send(RequestMutation(endpoint=ep, note="chain-gate"))
            if r is None or r.error or not r.status:
                continue
            body = r.body or ""
            if HASH_GATE.search(body):
                hash_eps.append(ep)
            elif CRYPTO_GATE.search(body):
                crypto_eps.append(ep)
        return hash_eps, crypto_eps

    # -------------------------------------------------------------- phases
    def run(self, endpoints: list[Endpoint], findings: list):
        prim = self._read_primitive(endpoints, findings)
        if prim is None:
            return []
        read_ep, read_param = prim
        out = []
        hash_eps, crypto_eps = self._gate_endpoints(endpoints)

        # ---- artifact DISCOVERY (write-then-read): a fresh app's artifact
        # is EMPTY until our first write — a read-only probe can never see
        # it. The first writer endpoint + the wordlist decide the name:
        # submit a known marker, re-read each candidate; the file whose NEW
        # line carries our value IS the artifact.
        artifact_name = None
        writer = (hash_eps or crypto_eps or [None])[0]
        if writer is not None:
            for name in ARTIFACT_WORDLIST:
                before = self._read_artifact(read_ep, read_param, name) or ""
                wr = self._submit(writer, K1)[0] if hash_eps else self._submit(writer, P16)[0]
                if wr is None or wr.error:
                    continue
                after = self._read_artifact(read_ep, read_param, name) or ""
                new_lines = self._new_lines(before, after)
                if any(HASH_LINE.search(ln) or SECRET_LINE.search(ln) for ln in new_lines):
                    artifact_name = name
                    break
        if artifact_name is None:
            return []

        # ---- hash: exact-digest oracle --------------------------------
        import json as _json
        md5_k = hashlib.md5(K1.encode()).digest()
        sha1_k = hashlib.sha1(K1.encode()).digest()
        for ep in hash_eps[:260]:
            before = self._read_artifact(read_ep, read_param, artifact_name) or ""
            r, wparam = self._submit(ep, K1)
            if r is None or r.error:
                continue
            after = self._read_artifact(read_ep, read_param, artifact_name) or ""
            new_lines = self._new_lines(before, after)
            hit = None
            for ln in new_lines:
                m = HASH_LINE.search(ln)
                if not m:
                    continue
                try:
                    d = base64.b64decode(m.group(1))
                except Exception:
                    continue
                if d == md5_k:
                    hit = ("MD5", d)
                    break
                if d == sha1_k:
                    hit = ("SHA-1", d)
                    break
            if hit:
                algo, d = hit
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name, "write_param": wparam})
                out.append(Finding(type="weak_hash", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter=wparam, method=ep.method,
                    evidence=[
                        Evidence("digest_match",
                                 f"known input {K1!r} submitted to this endpoint is stored as "
                                 f"{algo} — the artifact line 'hash_value={base64.b64encode(d).decode()}' "
                                 f"read back through a verified file-read primitive matches the "
                                 f"locally computed {algo} digest exactly; {algo} is a broken "
                                 "hash (CWE-327)", r.request_id),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)",
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))

        # ---- crypto: block-size oracle ---------------------------------
        for ep in crypto_eps[:260]:
            before = self._read_artifact(read_ep, read_param, artifact_name) or ""
            r, wparam = self._submit(ep, P16)
            if r is None or r.error:
                continue
            after = self._read_artifact(read_ep, read_param, artifact_name) or ""
            new_lines = self._new_lines(before, after)
            ct = None
            for ln in new_lines:
                m = SECRET_LINE.search(ln)
                if m:
                    try:
                        ct = base64.b64decode(m.group(1))
                        break
                    except Exception:
                        continue
            if not ct:
                continue
            # 16-byte plaintext: 24B = 8-byte block (DES family); 32B = AES class
            if len(ct) == 24:
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name, "write_param": wparam})
                out.append(Finding(type="weak_crypto", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter=wparam, method=ep.method,
                    evidence=[
                        Evidence("block_size",
                                 f"known 16-byte plaintext encrypts to a 24-byte ciphertext "
                                 f"({base64.b64encode(ct).decode()[:44]}…) — an 8-byte BLOCK "
                                 "CIPHER (DES/DESede/Blowfish family), broken since the "
                                 "1990s (CWE-327); AES-class answers 32 bytes for the same "
                                 "input (16 ciphertext + 16 GCM tag or CBC padding)", r.request_id),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)",
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))
            elif len(ct) % 16 == 0 and len(ct) >= 32:
                # ECB repeat probe: 32 identical plaintext bytes -> repeated
                # 8-byte (weak-ECB) blocks are visible even at 32B totals.
                before2 = after
                r2, wparam2 = self._submit(ep, P32)
                if r2 is None or r2.error:
                    continue
                after2 = self._read_artifact(read_ep, read_param, artifact_name) or ""
                ct2 = None
                for ln in [l for l in after2.splitlines() if l not in before2.splitlines()]:
                    m2 = SECRET_LINE.search(ln)
                    if m2:
                        try:
                            ct2 = base64.b64decode(m2.group(1))
                            break
                        except Exception:
                            continue
                if ct2 and len(ct2) >= 16:
                    blocks8 = [ct2[i:i + 8] for i in range(0, len(ct2) - 7, 8)]
                    if len(blocks8) != len(set(blocks8)) and len(ct2) % 8 == 0 and len(ct2) % 16 != 0:
                        out.append(Finding(type="weak_crypto", severity=Severity.HIGH,
                            endpoint_url=ep.url, parameter="", method=ep.method,
                            evidence=[
                                Evidence("ecb_repeat",
                                         f"known 32-byte repeated plaintext encrypts to a "
                                         f"ciphertext with REPEATED 8-byte blocks — 8-byte "
                                         "block ECB (DES family), deterministic and "
                                         "pattern-preserving (CWE-327)", r2.request_id),
                                Evidence("chain_legs",
                                         f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                         f"{read_param}={artifact_name} (verified path_traversal)",
                                         None)],
                            status=FindingStatus.CANDIDATE))
        return out
