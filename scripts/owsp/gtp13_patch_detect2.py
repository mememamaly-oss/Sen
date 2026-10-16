#!/usr/bin/env python3
"""GTP-13d wave 1b: self-named HEADER channel for the generic batteries
(xss / traversal / trustbound / cmdi / sqli) + trustbound third attempt."""
import re

P = "/home/z/my-project/build-v430/sentinel/detect.py"
src = open(P).read()

# ---------- 0) clone helper: append a synthetic self-named HEADER param ----------
anchor0 = '''def filled_baseline(ep: Endpoint, note: str) -> RequestMutation:'''
helper = '''def with_selfname_header(ep: Endpoint):
    """GTP-13d: a shallow clone carrying a SYNTHETIC self-named HEADER param
    (name = the URL's last segment) when the endpoint has any header-shaped
    surface. Batteries that iterate ordered_probe_params then naturally
    include the self-named header (getHeader("<seg>") surfaces), and _render
    dispatches the mutation as a request header of that name."""
    import copy as _copy13
    seg = last_path_segment(ep.url)
    if not seg or not (4 <= len(seg) <= 64):
        return None
    if not any(p.location == ParamLocation.HEADER for p in ep.parameters):
        return None
    if any(p.name == seg for p in ep.parameters):
        return ep      # already declared — nothing to add
    ep2 = _copy13.copy(ep)
    ep2.parameters = list(ep.parameters) + [
        Parameter(seg, ParamLocation.HEADER, "").classify()]
    return ep2


def filled_baseline(ep: Endpoint, note: str) -> RequestMutation:'''
assert src.count(anchor0) == 1
src = src.replace(anchor0, helper)
print("[0] with_selfname_header helper added")

# ---------- 1) XSS: battery on the synthetic self-named header ----------
anchor1 = '''        # GTP-02: paramless surfaces — the self-named servlet convention (the
        # path's last segment as field name) and the transposed resolver
        # shape (canary as name, segment as value). MAX-10a: never on a
        # logout/destructive/command-shaped surface.'''
add1 = '''        # GTP-13d: the SELF-NAMED HEADER battery — getHeader("<seg>")
        # surfaces (the spec declares a decoy header; the real one is named
        # after the test). One context probe + the plain battery, exactly
        # like a declared param.
        _eph = with_selfname_header(ep)
        if _eph is not None and _eph is not ep:
            _hp = ordered_probe_params(_eph, cap=8)[-1] if _eph.parameters else None
            if _hp is not None and _hp.name == last_path_segment(ep.url) \\
                    and _hp.location == ParamLocation.HEADER:
                mode_h, _ = self._context_probe(_eph, _hp)
                if mode_h != "filtered":
                    out.append(("selfhdr_full", RequestMutation(
                        endpoint=_eph, param_name=_hp.name,
                        param_value=f"<{self.CANARY}>pro41</{self.CANARY}>")))
                    out.append(("selfhdr_slash", RequestMutation(
                        endpoint=_eph, param_name=_hp.name,
                        param_value=f"<{self.CANARY}pro42")))
'''
assert src.count(anchor1) == 1
src = src.replace(anchor1, add1 + anchor1)
print("[1] XSS selfhdr battery added")

# ---------- 2) Traversal: the synthetic header joins the capped param list ----------
anchor2 = '''        _seen, _params = 0, []
        # GTP-13b: self-named param FIRST under the cap (live-caught: the
        # positional first-two choice probed password/username and never
        # reached the self-named channel the traversal sinks read).
        for p in ordered_probe_params(ep):
            if p.kind != ParamKind.TOKEN and not p.flow_control:
                _params.append(p)
                _seen += 1
                if _seen >= 2:          # GTP budget: 2 params x 11 payloads max
                    break'''
new2 = '''        _seen, _params = 0, []
        # GTP-13b: self-named param FIRST under the cap (live-caught: the
        # positional first-two choice probed password/username and never
        # reached the self-named channel the traversal sinks read).
        # GTP-13d: a synthetic self-named HEADER param joins the list when
        # the surface is header-shaped (getHeader("<seg>") traversal sinks).
        _epb = with_selfname_header(ep) or ep
        for p in ordered_probe_params(_epb):
            if p.kind != ParamKind.TOKEN and not p.flow_control:
                _params.append((p, _epb if p.location == ParamLocation.HEADER else ep))
                _seen += 1
                if _seen >= 2:          # GTP budget: 2 params x 11 payloads max
                    break'''
assert src.count(anchor2) == 1
src = src.replace(anchor2, new2)

# the candidates() return must use the (param, endpoint) pairs
old_ret = '''        return [(pl, RequestMutation(endpoint=ep, param_name=p.name, param_value=pl))
                for p in _params for pl in payloads]'''
new_ret = '''        return [(pl, RequestMutation(endpoint=(_e if _e is not None else ep),
                                     param_name=p.name, param_value=pl))
                for p, _e in _params for pl in payloads]'''
assert src.count(old_ret) == 1
src = src.replace(old_ret, new_ret)
print("[2] Traversal selfhdr param added")

# ---------- 3) TrustBound: third attempt via the self-named header ----------
anchor3 = '''        if p is None and not _np:
            seg = last_path_segment(ep.url)
            if not seg or len(seg) > 64:
                return None'''
add3 = '''        # GTP-13d: the SELF-NAMED HEADER attempt — getHeader("<seg>")
        # surfaces echo the header value into the trusted store.
        _mh1 = selfname_header_mutation(ep, self.M1)
        _mh2 = selfname_header_mutation(ep, self.M2)
        if _mh1 is not None and _mh2 is not None:
            rh1 = self.engine.send(_mh1)
            rh2 = self.engine.send(_mh2)
            attempts.append(("selfhdr", rh1, rh2, "<self-header>"))
        if p is None and not _np:
            seg = last_path_segment(ep.url)
            if not seg or len(seg) > 64:
                return None'''
assert src.count(anchor3) == 1
src = src.replace(anchor3, add3)
print("[3] TrustBound selfhdr attempt added")

# ---------- 4) CmdiEcho: the self-named header echo-oracle attempt ----------
anchor4 = '''        # GTP-13d: resolver NAME channel — the command expression as the
        # param NAME (resolvers feed the exec sink with the submitted NAME).
        _ce = resolver_key_param(ep)'''
add4 = '''        # GTP-13d: the SELF-NAMED HEADER channel — the command expression
        # through the header named after the test (getHeader("<seg>") sinks).
        _seh = selfname_header_mutation(ep, "localhost; echo $((6*7))")
        if _seh is not None:
            self._probes += 1
            _rh = self.engine.send(_seh)
            if _rh is not None and not _rh.error and _rh.status and "42" in (_rh.body or ""):
                _rhb = self.engine.send(selfname_header_mutation(ep, "localhost") or _seh)
                if _rhb is None or _rhb.error or "42" not in (_rhb.body or ""):
                    return Finding("command_injection", Severity.CRITICAL, ep.url,
                                   "<self-header>", ep.method,
                        [Evidence("execution_oracle",
                                  "command output oracle through the SELF-NAMED HEADER "
                                  "channel: 'echo $((6*7))' evaluated server-side -> literal "
                                  "'42' in the response while the header baseline carries none",
                                  _rh.request_id, (_rh.body or "")[:200])],
                        status=FindingStatus.CANDIDATE)
        # GTP-13d: resolver NAME channel — the command expression as the
        # param NAME (resolvers feed the exec sink with the submitted NAME).
        _ce = resolver_key_param(ep)'''
assert src.count(anchor4) == 1
src = src.replace(anchor4, add4)
print("[4] CmdiEcho selfhdr attempt added")

open(P, "w").write(src)
print("detect.py wave-1b written")
