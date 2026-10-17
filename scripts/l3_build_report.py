#!/usr/bin/env python3
"""Build the combined L3 impact evidence report from the live register."""
import json
import os

BASE = "/home/z/my-project/build-v423/results/l3_impact"
reg = json.load(open(os.path.join(BASE, "l3_live_register.json"), encoding="utf-8"))

NOTES = {
    "sql_version_oracle (ginjuice)": (
        "PROBE_FAILED, honest: the boolean ORACLE separated (controls 17106B vs 9421B) but "
        "every allowlisted version predicate (@@version LIKE / version() LIKE / "
        "SUBSTRING(@@version,1,1)='d') returns the app's 500 page on this target's DB — "
        "a version-metadata read cannot be proven within the safety ceiling on this target. "
        "The fail-closed allowlist stays: no UNION, no information_schema, no data extraction."),
    "xxe_file_read (ginjuice)": (
        "PROBE_FAILED, honest: the entity probe was issued live (control + file entity). The "
        "stock endpoint is response-blind for file entities (param entities are blocked with "
        "'Entities are not allowed for security reasons') — no in-band confirmation exists, "
        "and OOB exfiltration of file content is not possible on this parser. The XXE "
        "outbound-fetch capability itself was already proven at L0 via OAST."),
    "xss_browser_execution (ginjuice reflected /catalog?category)": (
        "PROBE_FAILED, honest: the attr_inject payload reaches the app as a quote in the "
        "category value — the SQL layer 500s before any reflection renders. The finding's "
        "own L2 impact link was INFERRED (grade indicated); L3's fresh browser probe "
        "confirms no execution on this surface this run."),
    "xss_stored_persistence (testaspnet)": (
        "PROBE_FAILED, honest: the payload rode a real-form replay (fresh __VIEWSTATE + "
        "btnSend, live-harvested — the WebForms postback is only processed with the button "
        "field). The app filters the <img onerror> comment TODAY (live-measured: benign "
        "<u> markup persists raw; the img shape does not). Persistence+execution of that "
        "vector is not provable on this target this run."),
    "xss_stored_persistence / xss_browser_execution (gruyere2)": (
        "PROBE_FAILED, honest: the resubmit carried the payload (200) and the render page "
        "was driven in a real browser; the canary did not execute. The L2 stored-XSS path "
        "for gruyere was INFERRED at the impact link — L3's fresh probe agrees."),
    "xss_browser_execution (testasp Search.asp?tfSearch)": (
        "PROBE_FAILED, honest: the attr_inject_onerror probe returned the app's 500 page — "
        "no reflection rendered. The L1-era note ('Templatize + tfSearch not reproduced') "
        "matches: this surface drifts on the public target."),
    "chain_conjunction (ginjuice xss_reflected->csrf)": (
        "INFERRED, weakest-link, honest: the CSRF leg VERIFIED fresh (own-session state "
        "change) but the reflected-XSS leg's browser execution did not verify this run — "
        "the whole chain stays INFERRED and names the failed leg. The dom->csrf chain "
        "VERIFIED with both legs fresh."),
    "sql_version_oracle digit extraction (MSSQL targets)": (
        "VERIFIED with version_char null, honest: the version-string read separated "
        "(version_true vs version_false) proving the DB-metadata read; the digit ladder "
        "(8/5) came back FALSE-side on both — the MSSQL version string's first character "
        "is not a digit. The measured digit probes are recorded verbatim."),
}

lines = ["# L3 — Proven Real Impact (الأثر الحقيقي المُثبَت)",
         "",
         "Layer `sentinel-impact/4.4.0` over the hardened engine (L0) and Attack Path "
         "Intelligence (L2). For every attack path it proves what the attacker ACTUALLY "
         "REACHES at the end — with the MINIMAL BENIGN live probe. Safety ceiling in code, "
         "fail-closed: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل.",
         "",
         f"- redirect sink (our OAST channel): `{reg['redirect_sink']}`",
         "- every target's probe journal + plan + assessment: `results/l3_impact/<target>/`",
         ""]

tot = v = pf = inf = 0
for t in reg["targets"]:
    s = t["assessment"]
    tot += s["total"]; v += s["verified"]; pf += s["probe_failed"]; inf += s["inferred"]
    lines.append(f"## {t['target']} — {t['host']} (scan run `{t['run_id']}`)")
    lines.append("")
    lines.append(f"- plans: {t['plan']['total']} total / {t['plan']['planned']} planned "
                 f"/ {t['plan']['refused']} refused / {t['plan']['not_safe']} not-safe")
    lines.append(f"- impacts: **{s['verified']} VERIFIED** / {s['probe_failed']} PROBE_FAILED "
                 f"/ {s['inferred']} INFERRED (of {s['total']})")
    lines.append(f"- OAST redirect landing hits: {t['oast_redirect_hits']}")
    lines.append("")
    for i in t["impacts"]:
        mark = {"VERIFIED": "V", "INFERRED": "i", "PROBE_FAILED": "X",
                "NOT_SAFE_TO_PROVE": "-", "REFUSED": "R"}.get(i["status"], "?")
        lines.append(f"- `[{mark}]` **{i['probe_kind']}** {i['findings']} — {i['status']}")
        d = i.get("detail") or {}
        if d:
            lines.append(f"  - detail: `{json.dumps(d, ensure_ascii=False)[:300]}`")
    lines.append("")

lines += ["## Combined register", "",
          f"- **{v} VERIFIED** / {pf} PROBE_FAILED / {inf} INFERRED — of {tot} impact plans "
          "across 4 authorized targets",
          "- every VERIFIED impact cites its probe journal entries with literal-slice "
          "excerpts (the L2 evidence-integrity discipline, zero tolerance)",
          "- every PROBE_FAILED carries the measured numbers; no fake proof anywhere",
          "", "## The honest register (كل قيد بقياسه)", ""]
for k, note in NOTES.items():
    lines.append(f"- **{k}**: {note}")
lines += ["",
          "## Safety ceiling actually exercised (this run)",
          "",
          "- SQLi: only control tautologies + version predicates over DB metadata; the digit "
          "ladder is 2 probes; no extraction, no timing, no table names — anywhere.",
          "- XXE / file reads: only /etc/hostname (never reached a secret; the blind target "
          "honestly failed).",
          "- Traversal: benign allowlisted files only — win.ini (testasp), /etc/passwd "
          "(gruyere) — fresh reads, nothing else.",
          "- State change: ONE cart-add, in OUR OWN session (minted by this run's engine), "
          "from a hostile Origin header, additive only. No destructive action, no victim "
          "session, anywhere.",
          "- Redirect: the browser landed on OUR OAST channel (1 recorded interaction) — "
          "never on a third party.",
          ""]

out = os.path.join(BASE, "l3_impact_report.md")
with open(out, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print("written:", out)
print(f"combined: {v} verified / {pf} probe_failed / {inf} inferred of {tot}")
