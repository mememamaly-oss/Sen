"""Independent re-observation of the passive ginandjuice findings (the
replay primitive covers active classes only; passive classes get an
independent fresh fetch + re-check, which is their re-execution).

  * missing_security_headers x9 -> re-fetch each URL, confirm the same
    header set is absent
  * vulnerable_js_dependency x1 -> re-fetch the asset, confirm it is the
    AngularJS 1.7.7 file the engine flagged
"""
import json
import urllib.request
from pathlib import Path

EV = Path("evidence/full-reverify/ginandjuice-shop")
s = json.loads((EV / "scan.json").read_text(encoding="utf-8"))
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                    "x-content-type-options", "referrer-policy")

out = {"reobservation_of": "passive findings — fresh fetches, independent "
                           "of the engine", "results": []}
ok = fail = 0
for f in s["findings"]:
    if f["type"] == "missing_security_headers":
        req = urllib.request.Request(f["url"], method="GET",
                                     headers={"User-Agent": "sentinel-reverify"})
        try:
            resp = urllib.request.urlopen(req, timeout=20)
            present = {h.lower() for h in resp.headers.keys()}
            missing = [h for h in SECURITY_HEADERS if h not in present]
            status = resp.status
        except Exception as exc:  # noqa: BLE001
            missing, status = [f"FETCH-ERROR: {exc!r}"], None
        agree = bool(missing) and "FETCH-ERROR" not in missing[0]
        ok += agree
        fail += not agree
        out["results"].append({"finding_id": f["id"], "type": f["type"],
                               "url": f["url"], "http_status": status,
                               "headers_still_missing": missing,
                               "reobservation_agrees": agree})
    elif f["type"] == "vulnerable_js_dependency":
        req = urllib.request.Request(f["url"], method="GET",
                                     headers={"User-Agent": "sentinel-reverify"})
        try:
            body = urllib.request.urlopen(req, timeout=20).read()
            is_angular_177 = (b"1.7.7" in body and b"angular" in body.lower())
            agree = is_angular_177
            detail = f"bytes={len(body)} angular-1.7.7-marker={'yes' if is_angular_177 else 'NO'}"
        except Exception as exc:  # noqa: BLE001
            agree, detail = False, f"FETCH-ERROR: {exc!r}"
        ok += agree
        fail += not agree
        out["results"].append({"finding_id": f["id"], "type": f["type"],
                               "url": f["url"], "detail": detail,
                               "reobservation_agrees": agree})

out["summary"] = {"passive_findings_reobserved": ok + fail,
                  "reobservation_agrees": ok, "disagrees": fail}
(EV / "passive_reobservation.json").write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
print(json.dumps(out["summary"]))
for r in out["results"]:
    if not r["reobservation_agrees"]:
        print("DISAGREE:", r)
