"""PART ZERO patcher — jwt_signature_not_enforced (CWE-347).

Fires when the CORRUPTED-SIGNATURE control of the confusion/none
differentials is itself accepted (the endpoint does not verify token
signatures at all). Discovered live by run 9 against crAPI challenge 15.

Patches (each asserted):
  burhan/modernsec.py  — the shared helper + fam1/fam2 wiring + VR replay
  burhan/intel.py      — the VR-35 re-verification branch
  burhan/compliance.py — CWE-347 / OWASP A07 mapping
  burhan/report.py     — Burhan-JWT-004
  fixtures/vulnapp.py  — SIGNOFF=1 mode (dashboard ignores signatures)
"""
import re

# ----------------------------------------------------------------- modernsec
p = "burhan/modernsec.py"
s = open(p).read()

# 1) the shared helper before the JWT families section
anchor = "# --------------------------------------------------------- \u00a74 the JWT families"
helper = '''def _sig_not_enforced(st: "_St", prot: Endpoint, ct, hdr: dict,
                       claims: dict, recipe: str, variant: str):
    """CWE-347, the broader class under the confusion/none differentials:
    the CORRUPTED-SIGNATURE control itself was ACCEPTED \u2014 the endpoint does
    not verify token signatures at all. Discovered live by run 9 against
    crAPI challenge 15 (both differentials saw the control pass); this is
    the finding that situation deserves. Deduped per endpoint: fam1 and
    fam2 each hold a corrupted-signature control."""
    if any(f.type == "jwt_signature_not_enforced" and f.endpoint_url == prot.url
           for f in st.findings):
        return
    st.find("jwt_signature_not_enforced", Severity.HIGH, prot, "-", [
        Evidence("signature_control_accepted",
                 f"signature not enforced (CWE-347): a token with a CORRUPTED "
                 f"signature (one mid-signature character flipped) was ACCEPTED "
                 f"(HTTP {ct.status}) by the protected endpoint \u2014 {variant}. "
                 f"original alg={hdr.get('alg')!r}; claims: {sorted(claims)}",
                 ct.request_id),
        Evidence("probe_recipe", recipe, ct.request_id)])


# --------------------------------------------------------- \u00a74 the JWT families'''
assert anchor in s, "anchor"
s = s.replace(anchor, helper, 1)

# 2) fam1: fire on control acceptance; keep the honest boundaries
old = '''            elif _ok(pr) and _ok(ct):
                st.boundary(fam1, "OBSERVED_ANOMALY",
                            "the protected endpoint accepted the forged token AND the "
                            "corrupted control \u2014 the verifier does not check signatures "
                            "at all; recorded as a boundary, not a finding")
            else:
                st.boundary(fam1, "TESTED_NEGATIVE",
                            f"the differential held: forged rejected (HTTP "
                            f"{getattr(pr, 'status', 0)}), control rejected (HTTP "
                            f"{getattr(ct, 'status', 0)})")'''
new = '''            else:
                if _ok(ct):
                    # run-9 class (crAPI challenge 15, live): the control itself
                    # was accepted \u2014 signatures are not enforced at all
                    _sig_not_enforced(st, prot, ct, hdr, claims,
                                      recipe + f"; jwks={jwks_used}",
                                      "the confusion differential\\u2019s control")
                if _ok(pr) and _ok(ct):
                    st.boundary(fam1, "OBSERVED_ANOMALY",
                                "the protected endpoint accepted the forged token AND "
                                "the corrupted control \u2014 the confusion differential "
                                "cannot isolate (both arms passed); the signature "
                                "bypass is reported as jwt_signature_not_enforced")
                elif _ok(ct):
                    st.boundary(fam1, "OBSERVED_ANOMALY",
                                "the corrupted control was ACCEPTED while the forged "
                                "token was not \u2014 reported as jwt_signature_not_enforced")
                else:
                    st.boundary(fam1, "TESTED_NEGATIVE",
                                f"the differential held: forged rejected (HTTP "
                                f"{getattr(pr, 'status', 0)}), control rejected (HTTP "
                                f"{getattr(ct, 'status', 0)})")'''
assert old in s, "fam1"
s = s.replace(old, new, 1)

# 3) fam2: same treatment for the corrupted-original control
old = '''    elif _ok(pr2) and _ok(ct2):
        st.boundary(fam2, "OBSERVED_ANOMALY",
                    "the verifier accepted the none-variant AND the corrupted original "
                    "\u2014 it does not verify signatures at all; recorded as a boundary, "
                    "not a finding")
    else:
        st.boundary(fam2, "TESTED_NEGATIVE",
                    f"the differential held: none-variant rejected (HTTP "
                    f"{getattr(pr2, 'status', 0)}), corrupted original rejected "
                    f"(HTTP {getattr(ct2, 'status', 0)})")'''
new = '''    elif _ok(pr2) and _ok(ct2):
        _sig_not_enforced(st, prot, ct2, hdr, claims, recipe,
                          "the none-acceptance differential\\u2019s control")
        st.boundary(fam2, "OBSERVED_ANOMALY",
                    "the verifier accepted the none-variant AND the corrupted original "
                    "\u2014 it does not verify signatures at all; the signature bypass is "
                    "reported as jwt_signature_not_enforced")
    elif _ok(ct2):
        _sig_not_enforced(st, prot, ct2, hdr, claims, recipe,
                          "the none-acceptance differential\\u2019s control")
        st.boundary(fam2, "OBSERVED_ANOMALY",
                    "the corrupted ORIGINAL was ACCEPTED while the none-variant was "
                    "not \u2014 reported as jwt_signature_not_enforced")
    else:
        st.boundary(fam2, "TESTED_NEGATIVE",
                    f"the differential held: none-variant rejected (HTTP "
                    f"{getattr(pr2, 'status', 0)}), corrupted original rejected "
                    f"(HTTP {getattr(ct2, 'status', 0)})")'''
assert old in s, "fam2"
s = s.replace(old, new, 1)

# 4) the VR-35 replay, appended next to replay_none's definition
anchor2 = "def replay_none(engine, finding):"
replay = '''def replay_sig347(engine, finding):
    """VR-35: a FRESH corrupt acceptance \u2014 fresh harvest, fresh corrupted-
    signature token, fresh probe; the acceptance must reproduce."""
    rec = recipe_of(finding)
    auth, prot = rec.get("auth", ""), rec.get("protected") or getattr(
        finding, "endpoint_url", "")
    if not auth or not prot:
        return False, "recipe incomplete (auth/protected missing) \u2014 cannot re-run"
    token = _fresh_harvest(engine, auth)
    if not token:
        return False, "no JWT on the fresh harvest"
    hdr = _decode_seg(token.split(".")[0])
    claims = _decode_seg(token.split(".")[1])
    bad = _corrupt_sig(token)
    r = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {bad}"}, note="modern-vr35"))
    ok = _ok(r)
    return ok, (f"fresh corrupted-signature token (orig alg={hdr.get('alg')!r}) "
                f"-> HTTP {getattr(r, 'status', 0)} on {prot}")


def replay_none(engine, finding):'''
assert anchor2 in s, "replay anchor"
s = s.replace(anchor2, replay, 1)
open(p, "w").write(s)
print("modernsec patched")

# --------------------------------------------------------------------- intel
p = "burhan/intel.py"
s = open(p).read()
anchor = '''        elif f.type == "jwt_none_acceptance":'''
new = '''        elif f.type == "jwt_signature_not_enforced":
            # VR-35 (run-9 class): a FRESH corrupted-signature token against a
            # FRESH harvest — the acceptance must reproduce.
            from .modernsec import replay_sig347
            ok35, notes35 = replay_sig347(self.engine, f)
            v = Verification(method="re-test:fresh-corrupt-acceptance",
                             passed=ok35, confidence=0.9 if ok35 else 0.15,
                             rounds=2, notes=notes35)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok35 else FindingStatus.REJECTED

        elif f.type == "jwt_none_acceptance":'''
assert anchor in s, "intel anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("intel patched")

# --------------------------------------------------------------- compliance
p = "burhan/compliance.py"
s = open(p).read()
anchor = '''    "jwt_none_acceptance": {'''
new = '''    "jwt_signature_not_enforced": {
        "cwe": "CWE-347",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "jwt_none_acceptance": {'''
assert anchor in s, "compliance anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("compliance patched")

# -------------------------------------------------------------------- report
p = "burhan/report.py"
s = open(p).read()
anchor = '''    "jwt_none_acceptance":                     "Burhan-JWT-003",'''
new = '''    "jwt_none_acceptance":                     "Burhan-JWT-003",
    "jwt_signature_not_enforced":              "Burhan-JWT-004",'''
assert anchor in s, "report anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("report patched")

# ------------------------------------------------------------------- vulnapp
p = "fixtures/vulnapp.py"
s = open(p).read()
anchor = '''    if hdr.get("alg") == "RS256":'''
new = '''    if os.environ.get("SIGNOFF") == "1":
        # PART ZERO mode: the filter parses the token and reads the claims but
        # NEVER verifies the signature \u2014 any token-shaped Bearer with a
        # parseable payload gets the account (the run-9 crAPI live behavior).
        try:
            json.loads(_b64u_dec(parts[1]) or b"null")
            return (200, '{"account": "demo", "role": "user"}')
        except Exception:
            return (401, '{"error": "malformed token"}')
    if hdr.get("alg") == "RS256":'''
assert anchor in s, "vulnapp anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("vulnapp patched")
print("ALL PATCHES APPLIED")
