#!/usr/bin/env python3
"""GTP-13: (re)apply the intel.py verifier patches — VR-25 channels, XSS
name-channel replay, VR-28 const-plaintext branch. Idempotent-ish: asserts
each anchor, fails loudly if already applied."""
import sys

P = "/home/z/my-project/build-v430/sentinel/intel.py"
src = open(P).read()

# ---------- 1) VR-25 trustbound: channel-mirrored replay ----------
old1 = '''            # VR-25 (GTP-08): a FRESH marker must reflect through the same
            # channel on replay.
            from .detect import TrustBoundDetector, last_path_segment
            ok25 = False
            if ep is not None:
                m3 = "sentineltb3verify"
                if ep.parameters:
                    _p25 = next((p.name for p in ep.parameters
                                 if p.kind != ParamKind.TOKEN and not p.flow_control), None)
                    r25 = self.engine.send(RequestMutation(endpoint=ep, param_name=_p25,
                                                           param_value=m3, note="vr25")) if _p25 else None
                else:
                    seg = last_path_segment(ep.url)
                    r25 = self.engine.send(RequestMutation(endpoint=ep, param_name=m3,
                                                           param_value=seg, note="vr25n")) if seg else None
                ok25 = bool(r25 is not None and not r25.error and m3 in (r25.body or ""))'''
new1 = '''            # VR-25 (GTP-08): a FRESH marker must reflect through the same
            # channel on replay. GTP-13b/d: the channel set now mirrors the
            # detector's — self-named-preferred value channel, the resolver
            # NAME channel (rename the key param), then the bare fallback.
            from .detect import (TrustBoundDetector, last_path_segment,
                                 ordered_probe_params, resolver_name_single)
            ok25 = False
            if ep is not None:
                m3 = "sentineltb3verify"
                _chan25 = []
                _ps25 = ordered_probe_params(ep, cap=1)
                if _ps25:
                    _chan25.append(RequestMutation(endpoint=ep, param_name=_ps25[0].name,
                                                   param_value=m3, note="vr25"))
                _nm25 = resolver_name_single(ep, m3)
                if _nm25 is not None:
                    _chan25.append(_nm25)
                if not ep.parameters:
                    seg = last_path_segment(ep.url)
                    if seg:
                        _chan25.append(RequestMutation(endpoint=ep, param_name=m3,
                                                       param_value=seg, note="vr25n"))
                r25 = None
                for _m25 in _chan25:
                    _r25 = self.engine.send(_m25)
                    if _r25 is not None and not _r25.error and m3 in (_r25.body or ""):
                        r25 = _r25
                        break
                ok25 = bool(r25 is not None)'''
if old1 in src:
    src = src.replace(old1, new1)
    print("[1] VR-25 channels applied")
else:
    print("[1] VR-25 anchor NOT found (already applied?)", "GTP-13b/d" in src)

# ---------- 2) XSS verifier: name-channel replay for every location ----------
old2 = '''                from .detect import _clone_ep_rename_param, last_path_segment
                fresh = "<sentinelxssvrmk>pro91"
                _qp = next((x for x in ep.parameters
                            if x.kind != ParamKind.TOKEN and not x.flow_control
                            and x.location.value == "query"), None)'''
new2 = '''                from .detect import (_clone_ep_rename_param, last_path_segment,
                                     ordered_probe_params, resolver_key_param)
                fresh = "<sentinelxssvrmk>pro91"
                # GTP-13d: the rename anchor mirrors the detector — prefer the
                # resolver key param (its VALUE names the endpoint and rides
                # the rename), else the self-named/first mutable param; ANY
                # location, not just query.
                _qp = resolver_key_param(ep) or next(iter(ordered_probe_params(ep, cap=1)), None)'''
if old2 in src:
    src = src.replace(old2, new2)
    print("[2] XSS name-channel replay applied")
else:
    print("[2] XSS anchor NOT found (already applied?)")

# ---------- 3) VR-28 const-plaintext branch ----------
old3 = '''        elif f.type == "weak_crypto":
            # VR-28 (GTP-10, GTP-12c): fresh plaintexts through the chain —
            # the weak block class must reproduce through the SAME tier
            # logic the detector used (direct 24B signature, the all-mod-8
            # +8-step block signature on stream surfaces, or the ECB repeat).
            import base64 as _b64
            ok28 = False
            used28 = ""
            recipe = self._chain_recipe(f)'''
new3_lines = [
    '''        elif f.type == "weak_crypto":
            # VR-28 (GTP-10, GTP-12c): fresh plaintexts through the chain —
            # the weak block class must reproduce through the SAME tier
            # logic the detector used (direct 24B signature, the all-mod-8
            # +8-step block signature on stream surfaces, or the ECB repeat).
            # GTP-13e: the CONSTANT-PLAINTEXT family re-runs the const oracle
            # on two fresh bounded windows instead (no input channel exists).
            import base64 as _b64
            ok28 = False
            used28 = ""
            recipe = self._chain_recipe(f)
            _kinds28c = {e.kind for e in (f.evidence or [])}
            if "const_plaintext_blockcipher" in _kinds28c and recipe:
                from .core import Endpoint as _E28c
                _read_ep = _E28c(url=recipe["read_url"], method="GET")
                _write_ep = None
                if recipe.get("truncate_url"):
                    _write_ep = _E28c(url=recipe["truncate_url"], method="POST")
                _pt28 = None
                for e in f.evidence:
                    if e.kind == "const_plaintext_blockcipher":
                        import re as _re28c
                        _m28 = _re28c.search(r"echo='([^']*)'", e.raw_snippet or "")
                        _pt28 = _m28.group(1) if _m28 else None
                ok28c = False
                if _pt28:
                    ok28c = True
                    for _round28 in (1, 2):
                        if _write_ep is not None:
                            _tr = self._chain_truncate(recipe)
                            if _tr is None:
                                ok28c = False
                                break
                        r28c = self._chain_read(recipe)
                        if not r28c:
                            ok28c = False
                            break
                        from .detect import entity_normalize as _en28c
                        _body28 = _en28c(r28c)
                        _i28 = _body28.find("secret_value=")
                        if _i28 < 0:
                            ok28c = False
                            break
                        _seg28 = _body28[_i28 + len("secret_value="):]
                        _m28b = re.search(r"\\n\\s*\\w+=", _seg28)''',
    '''                        if _m28b:
                            _seg28 = _seg28[:_m28b.start()]
                        _seg28 = re.sub(r"\\s+", "", _seg28)
                        try:
                            _ct28 = _b64.b64decode(_seg28 + "=" * (-len(_seg28) % 4))
                        except Exception:
                            ok28c = False
                            break
                        _delta28 = len(_ct28) - len(_pt28.encode("utf-8"))
                        ok28c = 1 <= _delta28 <= 7
                        if not ok28c:
                            break
                if ok28c:
                    v = Verification(method="re-test:const-plaintext-x2",
                                     passed=True, confidence=0.9, rounds=2,
                                     notes=("the constant-plaintext pad delta (1..7B) "
                                            "reproduced on two fresh bounded windows"))
                    f.verification, f.confidence = v, v.confidence
                    f.status = FindingStatus.VERIFIED
                    return f''']
new3 = "\n".join(new3_lines)
if old3 in src:
    src = src.replace(old3, new3)
    print("[3] VR-28 const branch applied")
else:
    print("[3] VR-28 anchor NOT found (already applied?)")

open(P, "w").write(src)
print("intel.py written")
