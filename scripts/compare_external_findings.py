#!/usr/bin/env python3
"""compare_external_findings.py — external-verifier vs SENTINEL comparison frame.

Supervisor order 3 (2026-10-03). Takes a vulnerability list from an EXTERNAL
verifier (human pentester report, another scanner export) and compares it
automatically against SENTINEL's strong-class findings per target.

Outputs three buckets:
  (a) GAPS            — the external party found it, SENTINEL did not
  (b) UNCONFIRMED     — SENTINEL found it, the external party did not
                        (SENTINEL's questionable claims)
  (c) CONFIRMED       — both found it (match level reported)

This tool MATCHES, it never adjudicates: a "CONFIRMED" row means the two
lists agree, not that the vulnerability is true; a GAP row means SENTINEL's
output lacks it, not that the external claim is true.

Usage:
  python3 compare_external_findings.py \
      --external examples/external_verifier_sample.json \
      --sentinel build-v421/results/live_v421/ginjuice.json \
                 build-v421/results/live_v421/testfire.json ... \
      --out-md  results/external_comparison_report.md \
      --out-json results/external_comparison_report.json

External input schema (JSON list; CSV also accepted with the same columns):
  [{"target": "ginandjuice.shop",          # host (required)
    "type": "SQL Injection",               # vulnerability class (required)
    "url":  "/catalog",                    # path (optional, improves matching)
    "param": "category",                   # parameter (optional)
    "notes": "..."}]                       # free text (carried into the report)
"""
import argparse, csv, json, os, re, sys
from urllib.parse import urlsplit

# ---------------------------------------------------------------- normalization
# Class synonyms -> SENTINEL canonical type. Extend freely; unknown external
# types are reported UNMATCHED (never silently dropped) so nothing hides.
SYNONYMS = {
    "sql_injection": "sql_injection",
    "sql": "sql_injection", "sqli": "sql_injection",
    "sql injection": "sql_injection", "sqli (boolean-based)": "sql_injection",
    "blind sqli": "sql_injection", "sql injection (blind)": "sql_injection",
    "auth bypass": "sql_injection", "authentication bypass": "sql_injection",

    "xss": "xss_reflected", "reflected xss": "xss_reflected",
    "cross-site scripting": "xss_reflected", "cross site scripting (reflected)": "xss_reflected",
    "xss_reflected": "xss_reflected", "xss (reflected)": "xss_reflected",
    "dom xss": "xss_dom", "dom-based xss": "xss_dom", "xss_dom": "xss_dom",
    "cross site scripting (dom)": "xss_dom",

    "xxe": "xxe", "xml external entity": "xxe", "xml external entity injection": "xxe",

    "csrf": "csrf", "xsrf": "csrf", "cross-site request forgery": "csrf",

    "open redirect": "open_redirect", "open_redirect": "open_redirect",
    "redirect": "open_redirect", "url redirect": "open_redirect",
    "unvalidated redirect": "open_redirect",

    "path traversal": "path_traversal", "path_traversal": "path_traversal",
    "lfi": "path_traversal", "local file inclusion": "path_traversal",
    "directory traversal": "path_traversal",

    "header injection": "http_response_header_injection",
    "crlf injection": "http_response_header_injection",
    "http response splitting": "http_response_header_injection",
    "http_response_header_injection": "http_response_header_injection",

    "ssti": "ssti", "server-side template injection": "ssti",
    "template injection": "ssti",

    "ssrf": "ssrf", "server-side request forgery": "ssrf",
    "command injection": "command_injection", "rce": "command_injection",
    "nosql injection": "nosql_injection", "nosql_injection": "nosql_injection",
    "idor": "idor", "bola": "idor", "insecure direct object reference": "idor",
    "broken object level authorization": "idor",
}

# The campaign's strong classes (active-evidence findings). Passive classes
# (missing headers / banners) are excluded by default — see --include-passive.
STRONG_CLASSES = {
    "sql_injection", "xxe", "xss_reflected", "xss_dom", "xss_stored",
    "path_traversal",
    "http_response_header_injection", "csrf", "open_redirect", "ssti",
    "ssrf", "command_injection", "nosql_injection", "idor",
    "deserialization", "jwt_flaw", "race_condition", "logic_flaw",
}


def canon_type(raw):
    t = (raw or "").strip().lower()
    return SYNONYMS.get(t)


def canon_host(raw):
    """Extract bare host from target/URL-ish input."""
    s = (raw or "").strip()
    if "://" in s:
        s = urlsplit(s).netloc
    s = s.split("/")[0].split(":")[0].split("?")[0].strip().lower()
    return s[4:] if s.startswith("www.") else s


# Gruyere (and similar sandboxes) provision an EPHEMERAL per-session instance
# ID as the first path segment — "/<39 digits>/login". Two scans of the same
# flaw get different IDs, so the segment is sandbox state, not vulnerability
# identity. Normalize it away (all-digit first segment, >= 15 digits).
_INSTANCE_ID = re.compile(r"^/\d{15,}(?=/|$)")


def canon_path(raw):
    s = (raw or "").strip()
    if "://" in s:
        s = urlsplit(s).path or "/"
    s = s.split("?")[0]
    if not s.startswith("/"):
        s = "/" + s
    s = _INSTANCE_ID.sub("", s) or "/"
    return s.rstrip("/") or "/"


def canon_param(raw):
    return (raw or "").strip().lower() or None


# ---------------------------------------------------------------- inputs
def load_external(path):
    ext = []
    if path.endswith(".json"):
        data = json.load(open(path))
        if isinstance(data, dict):  # tolerate {"findings": [...]} wrappers
            data = data.get("findings") or data.get("vulnerabilities") or [data]
        for r in data:
            ext.append(r)
    else:
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                ext.append(r)
    out = []
    for i, r in enumerate(ext):
        host = canon_host(r.get("target") or r.get("host") or r.get("url"))
        ctype = canon_type(r.get("type") or r.get("vulnerability") or r.get("class"))
        path = canon_path(r.get("url") or r.get("path"))
        param = canon_param(r.get("param") or r.get("parameter"))
        out.append({"idx": i, "raw": r, "host": host, "type": ctype,
                    "path": path, "param": param})
    return out


def load_sentinel(paths, include_passive=False):
    """Load strong findings from scan JSONs; DEDUP across scans — for the same
    (host, type, path, param) keep the LAST scan's record (scans are expected
    in chronological order; a re-scan supersedes its predecessor)."""
    dedup = {}
    order = []
    for p in paths:
        d = json.load(open(p))
        host = canon_host(d.get("target") or "")
        for f in d.get("findings", []):
            t = f.get("type")
            if not include_passive and t not in STRONG_CLASSES:
                continue
            rec = {"host": host, "type": t,
                   "path": canon_path(f.get("url")),
                   "param": canon_param(f.get("parameter")),
                   "status": f.get("status"), "run": d.get("run_id"),
                   "source": os.path.basename(p)}
            key = (rec["host"], rec["type"], rec["path"], rec["param"] or "")
            if key not in dedup:
                order.append(key)
            dedup[key] = rec
    return [dedup[k] for k in order]


# ---------------------------------------------------------------- matching
# XSS stored-vs-reflected bridge: external lists often type a stored XSS as a
# generic "Cross-Site Scripting" (canon: xss_reflected) while SENTINEL reports
# the same page+param flaw as xss_stored. When host+path+param all agree and
# only the reflected/stored subclass differs, the two rows describe the same
# flaw surface — match at STRONG with an explicit bridge marker (transparent
# in the report; never silently).
_XSS_PAIR = {"xss_reflected", "xss_stored"}


def match_level(ext, sen):
    """(host, class) must agree. Returns best level: EXACT > STRONG > CLASS.

    Two documented normalizations (v4.2.3 re-gate round):
      * ephemeral sandbox instance-ID path segments are stripped (canon_path)
      * xss_reflected/xss_stored subclass disagreement bridges at STRONG when
        host+path+param agree (level reported as "STRONG (xss-bridge)")
    """
    if ext["host"] != sen["host"]:
        return None
    type_mismatch = ext["type"] != sen["type"]
    if type_mismatch and not ({ext["type"], sen["type"]} <= _XSS_PAIR):
        return None
    if ext["path"] == sen["path"]:
        if type_mismatch:
            # bridge only when the param identity is explicit on both sides
            if ext["param"] and sen["param"] and ext["param"] == sen["param"]:
                return "STRONG (xss-bridge)"
            return None
        if ext["param"] and sen["param"] and ext["param"] == sen["param"]:
            return "EXACT"
        if not ext["param"] or not sen["param"]:
            return "STRONG"
        return "STRONG"  # same path, different param: still the same endpoint flaw
    # different paths but same host+class: class-level agreement only when
    # the external entry has no path or SENTINEL's path is unknown
    if ext["path"] in ("/", "") or sen["path"] in ("/", ""):
        return "CLASS"
    return None


def compare(ext_list, sen_list):
    confirmed, gaps, unconfirmed, unmatched_ext = [], [], [], []
    sen_used = [False] * len(sen_list)
    for e in ext_list:
        if not e["host"] or not e["type"]:
            unmatched_ext.append({"reason": "unparseable host/type", "raw": e["raw"]})
            continue
        best, best_i = None, None
        for i, s in enumerate(sen_list):
            if sen_used[i]:
                continue
            lvl = match_level(e, s)
            if lvl and (best is None or lvl == "EXACT"):
                best, best_i = lvl, i
                if lvl == "EXACT":
                    break
        if best_i is not None:
            sen_used[best_i] = True
            confirmed.append({"external": e["raw"], "sentinel": sen_list[best_i],
                              "level": best})
        else:
            gaps.append({"external": e["raw"], "host": e["host"],
                         "type": e["type"], "path": e["path"], "param": e["param"]})
    for i, s in enumerate(sen_list):
        if not sen_used[i]:
            unconfirmed.append(s)
    return {"confirmed": confirmed, "gaps": gaps,
            "unconfirmed": unconfirmed, "unmatched_external": unmatched_ext}


# ---------------------------------------------------------------- reporting
def report_md(res, ext_path, sen_paths):
    L = ["# External-Verifier vs SENTINEL — Comparison Report", "",
         f"External list: `{ext_path}`",
         f"SENTINEL scans: {', '.join('`' + p + '`' for p in sen_paths)}", "",
         "This tool MATCHES lists; it never adjudicates correctness.",
         "CONFIRMED = the two lists agree (still engine-self-judged on SENTINEL's side).", ""]
    L += [f"## (a) GAPS — external found, SENTINEL did not [{len(res['gaps'])}]"]
    if res["gaps"]:
        for g in res["gaps"]:
            L += [f"- **{g['type']}** @ {g['host']}{g['path']}"
                  + (f" param `{g['param']}`" if g["param"] else "")
                  + f" — external row: {json.dumps(g['external'], ensure_ascii=False)}"]
    else:
        L += ["- none"]
    L += ["", f"## (b) UNCONFIRMED — SENTINEL found, external did not [{len(res['unconfirmed'])}]"]
    if res["unconfirmed"]:
        for s in res["unconfirmed"]:
            L += [f"- **{s['type']}** @ {s['host']}{s['path']}"
                  + (f" param `{s['param']}`" if s["param"] else "")
                  + f" [{s['status']}, run {s['run']}, {s['source']}]"]
    else:
        L += ["- none"]
    L += ["", f"## (c) CONFIRMED by both [{len(res['confirmed'])}]"]
    if res["confirmed"]:
        for c in res["confirmed"]:
            s = c["sentinel"]
            L += [f"- **{s['type']}** @ {s['host']}{s['path']}"
                  + (f" param `{s['param']}`" if s["param"] else "")
                  + f" — match level {c['level']} | SENTINEL: {s['status']}, run {s['run']}"]
    else:
        L += ["- none"]
    if res["unmatched_external"]:
        L += ["", "## Unparsed external rows (never silently dropped)"]
        L += [f"- {json.dumps(u['raw'], ensure_ascii=False)} — {u['reason']}"
              for u in res["unmatched_external"]]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--external", required=True)
    ap.add_argument("--sentinel", nargs="+", required=True)
    ap.add_argument("--out-md", default="results/external_comparison_report.md")
    ap.add_argument("--out-json", default="results/external_comparison_report.json")
    ap.add_argument("--include-passive", action="store_true",
                    help="include passive classes (headers/banners) — off by default")
    a = ap.parse_args()

    ext = load_external(a.external)
    sen = load_sentinel(a.sentinel, a.include_passive)
    res = compare(ext, sen)
    os.makedirs(os.path.dirname(os.path.abspath(a.out_md)), exist_ok=True)
    with open(a.out_md, "w") as fh:
        fh.write(report_md(res, a.external, a.sentinel))
    with open(a.out_json, "w") as fh:
        json.dump({"external_source": a.external, "sentinel_sources": a.sentinel,
                   "counts": {k: len(v) for k, v in res.items()}, **res}, fh, indent=1)
    print(f"external rows: {len(ext)} | sentinel strong findings: {len(sen)}")
    print(f"(a) gaps: {len(res['gaps'])} | (b) unconfirmed: {len(res['unconfirmed'])} "
          f"| (c) confirmed: {len(res['confirmed'])} | unparsed: {len(res['unmatched_external'])}")
    print("wrote", a.out_md, "and", a.out_json)


if __name__ == "__main__":
    main()
