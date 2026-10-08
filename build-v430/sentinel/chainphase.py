"""SENTINEL v4.3.0 — hash/crypto artifact chain phase (GTP-10, upgraded GTP-12c).

Two whole Benchmark categories (hash: 236, crypto: 246) never put the
digest/ciphertext in the response — the servlet WRITES it to a server-side
artifact (passwordFile.txt in the app's working directory) and echoes only
the plaintext. Black-box the value is invisible... unless the same app
carries a FILE-READ primitive, in which case the artifact is readable
through it. This phase chains the two:

  leg 0 (truncate): GTP-12c — the read primitive's window is the artifact's
                  FIRST 1000 bytes and every request to a hash/crypto
                  servlet APPENDS a line, so the scan's own battery traffic
                  exhausts the window mid-scan (the round-4 bound: chain
                  validated end-to-end on a controlled pair, 0 findings on
                  the full target). A VERIFIED write-capable sink
                  (FileOutputStream family, append=false) pointed at the
                  artifact opens it and closes WITHOUT writing — the open
                  alone truncates the file to zero (live-proven: read after
                  truncate returns 'Range [0, 0 + -1] out of bounds'). The
                  app's own launcher truncates the same artifact at boot
                  (GTP-10 fixture hygiene); this is the same operation,
                  on demand, before every probe cycle.
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
  oracle (crypto): GTP-12c three-tier block analysis on the fresh
                  secret_value line:
                    T1  16-byte plaintext -> 24-byte ciphertext = an 8-byte
                        BLOCK cipher (DES/DESede family) on direct-param
                        surfaces;
                    T2  8/16/24-byte plaintexts whose ciphertexts are ALL
                        length==0 (mod 8) with EXACT +8 steps = the 8-byte
                        block signature on ANY input shape (the raw-stream
                        servlets prepend 'name=' to the body — absolute
                        lengths shift, the signature does not; AES-GCM/CCM
                        answers pt+tag, never 0 mod 8 on these lengths);
                    T3  64-byte uniform plaintext -> any REPEATED 8- or
                        16-byte ciphertext block = ECB mode (deterministic,
                        pattern-preserving — DES/ECB and AES/ECB alike).

VR-27/VR-28 re-execute the full chain with fresh markers (truncate
included); every finding cites BOTH legs (write endpoint + read primitive)
in its evidence chain.
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
K1 = "sentinel-hash-probe-01"
P8 = "B" * 8
P16 = "A" * 16
P24 = "C" * 24
P64 = "D" * 64


def _extract_value(body: str, prefix: str) -> bytes | None:
    """GTP-12c: ESAPI encodeForBase64(..., true) LINE-WRAPS the base64 at 76
    chars — the value spans multiple physical lines and a naive
    [A-Za-z0-9+/=]+ match stops at the first newline (live-caught: 57 of 88
    ciphertext bytes on BenchmarkTest00019). This extracts the wrapped value
    from 'prefix=...' to the next 'name=' line or EOF, strips ALL whitespace,
    and decodes."""
    i = body.find(prefix + "=")
    if i < 0:
        return None
    seg = body[i + len(prefix) + 1:]
    # value ends at the next artifact line (word=...) at line start or EOF
    m = re.search(r"\n\s*\w+=", seg)
    if m:
        seg = seg[:m.start()]
    seg = re.sub(r"\s+", "", seg)
    if not seg:
        return None
    try:
        return base64.b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:
        return None


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

    def _prim_loc(self, ep, param) -> str:
        """GTP-12c: the param's ACTUAL location (verifier replays build bare
        Endpoints — without the explicit location the write leg ships as a
        query string and never reaches a cookie/header sink; live-caught:
        every VR-27/VR-28 replay rejected with the payload in the URL)."""
        for p in ep.parameters:
            if p.name == param:
                return p.location.value
        return "query"

    def _write_primitive(self, endpoints, findings):
        """GTP-12c: a VERIFIED write-capable path_traversal finding (the
        writability_oracle family — FileOutputStream sinks) -> (Endpoint,
        param). Truncation leg of the chain."""
        eps = {ep.url: ep for ep in endpoints}
        for f in findings:
            if f.type != "path_traversal" or f.status != FindingStatus.VERIFIED:
                continue
            if not any(e.kind == "writability_oracle" for e in f.evidence):
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

    def _truncate_artifact(self, write_ep, write_param, artifact_name) -> bool:
        """GTP-12c: the truncation leg. A FileOutputStream sink opens the
        artifact with append=false and closes without writing — the OPEN
        alone zeroes it (live-proven). The app's own stack launcher performs
        the identical truncate at boot; this is the on-demand form."""
        if write_ep is None:
            return False
        r = self.engine.send(RequestMutation(endpoint=write_ep, param_name=write_param,
                                             param_value=artifact_name,
                                             note=f"artifact-truncate:{artifact_name}"))
        return r is not None and not r.error and bool(r.status)

    def _find_artifact(self, read_ep, read_param) -> tuple[str, str] | None:
        """(artifact name, current body) for the first wordlist hit carrying
        our value= lines."""
        for name in ARTIFACT_WORDLIST:
            body = self._read_artifact(read_ep, read_param, name)
            if body and ("hash_value=" in body or "secret_value=" in body):
                return name, body
        return None

    def _submit(self, ep: Endpoint, value: str):
        """Returns (response, write_param) — the param name the write rode.
        GTP-12f: prefer the param NAMED AFTER the URL's last segment — the
        Benchmark servlets read their OWN test-name parameter
        (getParameterValues("BenchmarkTestNNNNN")) and the drifted spec lists
        it among other decoys (password/username); the first-param choice
        hashed the decoy and the digest never matched."""
        seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
        p = next((x for x in ep.parameters if x.name == seg and x.kind.value != "token"
                  and not x.flow_control), None) \
            or next((x for x in ep.parameters
                     if x.kind.value != "token" and not x.flow_control and x.name), None)
        if p is not None:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=value, note="chain-write")),
                    p.name)
        if seg:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=seg,
                                                     param_value=value, note="chain-write")), seg)
        return None, ""

    def _write_param_of(self, ep: Endpoint) -> str:
        seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
        p = next((x for x in ep.parameters if x.name == seg and x.kind.value != "token"
                  and not x.flow_control), None) \
            or next((x for x in ep.parameters
                     if x.kind.value != "token" and not x.flow_control and x.name), None)
        return p.name if p is not None else seg

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

    # -------------------------------------------------------------- probe kit
    def _probe(self, ep, value, read_ep, read_param, artifact_name,
               write_ep=None, write_param=None, channel="declared") -> bytes | None:
        """GTP-12c: the bounded probe cycle — truncate (when a write sink
        exists), write the marker, read the artifact, return the FIRST
        fresh value (digest or ciphertext) as raw bytes. With truncation the
        window is deterministic: everything after the truncate is ours.
        GTP-12f: channel='body' rides the form body with the URL's last
        segment as the field name — the Benchmark servlets read their OWN
        test-name parameter (getParameterValues("BenchmarkTestNNNNN")) while
        the shipped openapi.yaml declares nothing (or a drifted decoy) on
        the POST surface; the declared-channel write hashed the EMPTY string
        and the digest never matched (96 hash / 80 crypto FNs live-caught)."""
        if write_ep is not None:
            # GTP-12g(h): a FAILED truncate must ABORT the probe — the read
            # would see the PREVIOUS probe's stale line (the last FP of the
            # round-5 re-measurement, BenchmarkTest01975: the P15 read saw
            # the stale 24B P16 line and 'confirmed' a block multiple on an
            # AES/GCM servlet)
            if not self._truncate_artifact(write_ep, write_param, artifact_name):
                return None
        if channel == "body":
            seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
            if not seg:
                return None
            from .core import ParamLocation
            # GTP-12f: GET-with-body is structurally dead — the transport only
            # ships a body for POST/PUT/PATCH (http_engine._dispatch line 507),
            # so the form-body channel FORCES POST.
            r = self.engine.send(RequestMutation(endpoint=ep, param_name=seg,
                                                 param_location=ParamLocation.BODY,
                                                 method="POST",
                                                 param_value=value, note="chain-write-body"))
        else:
            r, _wp = self._submit(ep, value)
        if r is None or r.error:
            return None
        body = self._read_artifact(read_ep, read_param, artifact_name)
        if not body:
            return None
        for prefix in ("hash_value", "secret_value"):
            v = _extract_value(body, prefix)
            if v is not None:
                return v
        return None

    # -------------------------------------------------------------- phases
    def run(self, endpoints: list[Endpoint], findings: list):
        prim = self._read_primitive(endpoints, findings)
        if prim is None:
            return []
        read_ep, read_param = prim
        read_loc = self._prim_loc(read_ep, read_param)
        # GTP-12c: the truncation sink (may be None — the chain still runs
        # in the old before/after mode when no write primitive verified)
        wprim = self._write_primitive(endpoints, findings)
        write_ep, write_param = (wprim if wprim else (None, None))
        write_loc = self._prim_loc(write_ep, write_param) if write_ep else "query"
        out = []
        hash_eps, crypto_eps = self._gate_endpoints(endpoints)

        # ---- artifact DISCOVERY: a fresh app's artifact is EMPTY until the
        # first write. With a write sink: truncate + write + read each
        # candidate directly (the fresh window is deterministic). Without:
        # the original before/after diff.
        artifact_name = None
        writer = (hash_eps or crypto_eps or [None])[0]
        if writer is not None:
            if write_ep is not None:
                for name in ARTIFACT_WORDLIST:
                    v = self._probe(writer, K1, read_ep, read_param, name,
                                    write_ep, write_param)
                    if v is not None:
                        artifact_name = name
                        break
            else:
                for name in ARTIFACT_WORDLIST:
                    before = self._read_artifact(read_ep, read_param, name) or ""
                    wr = self._submit(writer, K1)[0] if hash_eps else self._submit(writer, P16)[0]
                    if wr is None or wr.error:
                        continue
                    after = self._read_artifact(read_ep, read_param, name) or ""
                    new_lines = self._new_lines(before, after)
                    if any("hash_value=" in ln or "secret_value=" in ln for ln in new_lines):
                        artifact_name = name
                        break
        if artifact_name is None:
            return []

        # ---- hash: exact-digest oracle --------------------------------
        import json as _json
        md5_k = hashlib.md5(K1.encode()).digest()
        sha1_k = hashlib.sha1(K1.encode()).digest()
        K2M = "sentinel-hash-probe-02"
        for ep in hash_eps[:260]:
            d = None
            chan, wloc = "declared", self._prim_loc(ep, self._write_param_of(ep))
            if write_ep is not None:
                d = self._probe(ep, K1, read_ep, read_param, artifact_name,
                                write_ep, write_param)
                if d not in (md5_k, sha1_k):
                    # GTP-12f: the body-channel fallback (spec drift)
                    d2 = self._probe(ep, K1, read_ep, read_param, artifact_name,
                                     write_ep, write_param, channel="body")
                    if d2 in (md5_k, sha1_k):
                        d, chan, wloc = d2, "body", "body"
                    elif d2 is not None and d is None:
                        d, chan, wloc = d2, "body", "body"
            hit = None
            const_hit = None
            if d is not None and d not in (md5_k, sha1_k) and write_ep is not None:
                # GTP-12h (live-caught: 20 of the 76 remaining hash FNs): the
                # CONSTANT-DIGEST family — a switch/if on the safe path feeds
                # the digest a hardcoded value ('bob'); the input never
                # arrives. The ALGORITHM is still identifiable black-box: the
                # artifact line is byte-identical across two DISTINCT inputs
                # and its decoded length is the MD-family (16B) or SHA-1
                # (20B) output size — both cryptographically broken. SHA-256+
                # answers 32B+ and never fires.
                c2 = self._probe(ep, K2M, read_ep, read_param, artifact_name,
                                 write_ep, write_param, channel=chan)
                if c2 is not None and c2 == d and len(d) in (16, 20):
                    algo = "MD5/MD-family (16-byte digest)" if len(d) == 16 \
                        else "SHA-1 (20-byte digest)"
                    const_hit = algo
            if const_hit and not hit:
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan == "body"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": write_loc})
                out.append(Finding(type="weak_hash", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("digest_length_const",
                                 f"the artifact's hash_value line is INPUT-INDEPENDENT — "
                                 f"byte-identical across two distinct submissions "
                                 f"({K1!r} / {K2M!r}) — and decodes to {len(d)} bytes: the "
                                 f"{const_hit} output size. The hashed input is "
                                 "server-controlled (a constant on this path), but the "
                                 "ALGORITHM is identifiable by its digest length and it is "
                                 "a broken hash (CWE-327); SHA-256+ answers 32B+",
                                 None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))
                continue
            if d is not None:
                if d == md5_k:
                    hit = ("MD5", d)
                elif d == sha1_k:
                    hit = ("SHA-1", d)
            elif write_ep is None:
                # legacy mode (no write sink): before/after diff
                before = self._read_artifact(read_ep, read_param, artifact_name) or ""
                r, wparam = self._submit(ep, K1)
                if r is None or r.error:
                    continue
                after = self._read_artifact(read_ep, read_param, artifact_name) or ""
                for ln in self._new_lines(before, after):
                    m = re.search(r"hash_value=([A-Za-z0-9+/=]+)", ln)
                    if not m:
                        continue
                    try:
                        dd = base64.b64decode(m.group(1))
                    except Exception:
                        continue
                    if dd == md5_k:
                        hit = ("MD5", dd)
                        break
                    if dd == sha1_k:
                        hit = ("SHA-1", dd)
                        break
            if hit:
                algo, d = hit
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan == "body"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": write_loc})
                out.append(Finding(type="weak_hash", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("digest_match",
                                 f"known input {K1!r} submitted to this endpoint is stored as "
                                 f"{algo} — the artifact line 'hash_value={base64.b64encode(d).decode()}' "
                                 f"read back through a verified file-read primitive matches the "
                                 f"locally computed {algo} digest exactly; {algo} is a broken "
                                 "hash (CWE-327)", None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))

        # ---- crypto: three-tier block oracle (GTP-12g: P15 boundary gate) --
        P15 = "E" * 15
        def _is_block_cipher(cts: list[bytes | None]) -> bool:
            """GTP-12g (live-caught on the round-5 re-measurement: 25 verified
            weak_crypto FPs on AES/GCM servlets): a BARE length curve cannot
            separate an 8-byte block cipher from a stream+tag mode — AES/GCM
            with an 8-byte tag answers ct = pt + 8, which lands on EXACTLY the
            same all-multiples-of-8 +8-step curve as DES (16/24/32 for
            8/16/24-byte plaintexts). The decisive discriminator is the
            OFF-BOUNDARY probe: a block cipher pads EVERY length to a block
            multiple (a 15-byte plaintext still answers 0 mod 8), while
            pt+tag answers 15+8=23 (live-measured: 00058 GCM -> 23, 00005
            DES -> 16, 00019 DES-stream -> 40, 00345 CCM -> 42)."""
            return all(c is not None and len(c) % 8 == 0 for c in cts)

        for ep in crypto_eps[:260]:
            chan, wloc = "declared", self._prim_loc(ep, self._write_param_of(ep))
            if write_ep is None:
                continue      # legacy before/after mode cannot bound the window
            # T1: direct-param DES — 16B plaintext -> exactly 24B ciphertext
            ct16 = self._probe(ep, P16, read_ep, read_param, artifact_name,
                               write_ep, write_param)
            if ct16 is None or len(ct16) != 24:
                # GTP-12f: the body-channel fallback (spec drift) — retry P16
                ct16b = self._probe(ep, P16, read_ep, read_param, artifact_name,
                                    write_ep, write_param, channel="body")
                if ct16b is not None and (ct16 is None or len(ct16b) in (24, 40, 48)):
                    ct16, chan, wloc = ct16b, "body", "body"
            if ct16 is None:
                continue
            weak_reason = None
            if len(ct16) == 24:
                # GTP-12g: confirm with the OFF-BOUNDARY probe (15B -> must
                # still be a multiple of 8 on a real block cipher, AND
                # strictly SHORTER than ct16 — a block cipher grows 16->24;
                # an equal length means a STALE line (the truncate failed and
                # the read returned the previous probe's ciphertext))
                ct15 = self._probe(ep, P15, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if _is_block_cipher([ct15]) and len(ct15) < len(ct16):
                    weak_reason = ("known 16-byte plaintext encrypts to a 24-byte ciphertext "
                                   f"({base64.b64encode(ct16).decode()[:44]}…) and a 15-byte "
                                   f"plaintext still answers {len(ct15 or b'')}B (a block "
                                   "multiple) — an 8-byte BLOCK CIPHER (DES/DESede family), "
                                   "broken since the 1990s (CWE-327); AES-class answers "
                                   "pt+tag and leaves the multiple-of-8 grid off-boundary")
                else:
                    # the length curve matched but the boundary probe says
                    # stream+tag (the AES/GCM-8B-tag collision) — NOT weak
                    pass
            if weak_reason is None:
                # T2: the block-step signature on any input shape —
                # 8/16/24-byte plaintexts, ciphertexts all ==0 mod 8, +8 steps
                ct8 = self._probe(ep, P8, read_ep, read_param, artifact_name,
                                  write_ep, write_param, channel=chan)
                ct24 = self._probe(ep, P24, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if ct8 is not None and ct24 is not None and ct8 != ct16 \
                        and len(ct8) % 8 == 0 and len(ct16) % 8 == 0 and len(ct24) % 8 == 0 \
                        and len(ct16) - len(ct8) == 8 and len(ct24) - len(ct16) == 8:
                    ct15 = self._probe(ep, P15, read_ep, read_param, artifact_name,
                                       write_ep, write_param, channel=chan)
                    if _is_block_cipher([ct15]):
                        weak_reason = (f"block-step signature: 8/16/24-byte known plaintexts "
                                       f"encrypt to {len(ct8)}/{len(ct16)}/{len(ct24)}-byte "
                                       "ciphertexts — all multiples of 8 with exact +8 steps, "
                                       "and the 15-byte off-boundary probe answers "
                                       f"{len(ct15 or b'')}B (still a multiple of 8) — an "
                                       "8-byte BLOCK CIPHER, DES family (AES-GCM/CCM answer "
                                       "plaintext+tag and leave the grid off-boundary) "
                                       "(CWE-327)")
            if weak_reason is None:
                # T3: ECB repeat — 64 uniform plaintext bytes
                ct64 = self._probe(ep, P64, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if ct64 is not None and len(ct64) >= 24:
                    blocks = {8: [ct64[i:i + 8] for i in range(0, len(ct64) - 7, 8)],
                              16: [ct64[i:i + 16] for i in range(0, len(ct64) - 15, 16)]}
                    for bs, bl in blocks.items():
                        if len(bl) != len(set(bl)) and len(ct64) % bs == 0:
                            weak_reason = (f"known 64-byte repeated plaintext encrypts "
                                           f"to a ciphertext with REPEATED {bs}-byte "
                                           f"blocks ({len(bl)} blocks, "
                                           f"{len(set(bl))} unique) — ECB mode, "
                                           "deterministic and pattern-preserving "
                                           "(CWE-327)")
                            break
            if weak_reason:
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan == "body"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": write_loc})
                out.append(Finding(type="weak_crypto", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("block_oracle", weak_reason, None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))
        return out
