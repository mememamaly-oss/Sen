"""Evidence generator for PART ZERO — jwt_signature_not_enforced (CWE-347).

Runs the modernsec battery (fam1/fam2 chain) against the SIGNOFF twin
(RED — the filter reads claims but never verifies signatures) and the
strict twin (BLUE — signatures enforced, differential isolates), plus the
confusion twin discrimination check, and writes the evidence JSONs.
"""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.core import Endpoint, EventBus, Parameter, ParamLocation, ScopeRule  # noqa: E402
from burhan.http_engine import RequestEngine                                      # noqa: E402
from burhan.modernsec import replay_sig347, run_modern_battery                    # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(env_extra):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**os.environ, "PORT": str(port), **env_extra},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return port, proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("fixture never became reachable")


def _battery(base):
    engine = RequestEngine(ScopeRule(allow_private=True,
                                     allowed_hosts=["127.0.0.1"]),
                           EventBus("sig347-evidence"), timeout=8.0)
    login_ep = Endpoint(
        url=f"{base}/auth/api/login", method="POST",
        parameters=[Parameter("email", ParamLocation.JSON, "user@fixture.test"),
                    Parameter("password", ParamLocation.JSON,
                              "fixture-pass-123")])
    dash_ep = Endpoint(url=f"{base}/api/account/dashboard", method="GET")
    engine.auth_harvest_endpoint = login_ep
    return engine, run_modern_battery(engine, [dash_ep, login_ep])


def _run(env_extra, label):
    port, proc = _spawn(env_extra)
    base = f"http://127.0.0.1:{port}"
    try:
        engine, mres = _battery(base)
        sig = [f for f in mres.findings if f.type == "jwt_signature_not_enforced"]
        conf = [f for f in mres.findings if f.type == "jwt_algorithm_confusion"]
        none_f = [f for f in mres.findings if f.type == "jwt_none_acceptance"]
        vr = replay_sig347(engine, sig[0]) if sig else (None, "n/a — no finding")
        return {
            "layer": "jwt-signature-not-enforced",
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": f"fixtures/vulnapp.py (env: {env_extra or 'strict'})",
            "label": label,
            "battery_findings": [f.type for f in mres.findings],
            "fam1_probes_sent": mres.probe_counts["jwt_algorithm_confusion"]["sent"],
            "fam1_boundaries": [b for b in mres.boundaries
                                if b["family"] == "jwt_algorithm_confusion"],
            "fam2_boundaries": [b for b in mres.boundaries
                                if b["family"] == "jwt_none_acceptance"],
            "finding": ({
                "type": sig[0].type, "severity": str(sig[0].severity),
                "url": sig[0].endpoint_url,
                "evidence": [{"kind": e.kind, "detail": e.detail}
                             for e in sig[0].evidence]} if sig else None),
            "vr35_reverify": {"ok": vr[0], "notes": vr[1]},
            "confusion_finding_present": bool(conf),
            "none_acceptance_finding_present": bool(none_f),
        }
    finally:
        proc.terminate()


out_dir = os.path.join(ROOT, "evidence", "layers", "jwt-signature-not-enforced")
os.makedirs(out_dir, exist_ok=True)

red = _run({"SIGNOFF": "1"}, "RED — the filter reads claims, never verifies signatures")
blue = _run({}, "BLUE — signatures enforced: the corrupted control is rejected")
disc = _run({"CONFUSION": "1"},
            "DISCRIMINATION — confusion accepted but corrupted control rejected: "
            "jwt_algorithm_confusion fires, jwt_signature_not_enforced stays silent")

for name, doc in (("RED.json", red), ("BLUE.json", blue),
                  ("DISCRIMINATION.json", disc)):
    with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    print(f"{name}: findings={doc['battery_findings']} vr35={doc['vr35_reverify']['ok']}")

assert red["finding"], "RED must produce the finding"
assert red["vr35_reverify"]["ok"], "RED must survive VR-35"
assert red["fam1_probes_sent"] == 2
assert not red["confusion_finding_present"], "both arms accepted — confusion cannot isolate"
assert not blue["finding"], "BLUE must stay silent"
assert disc["confusion_finding_present"], "discrimination twin must fire confusion"
assert not disc["finding"], "corrupt rejected — sig347 must stay silent"
print("ALL EVIDENCE ASSERTIONS PASS")
