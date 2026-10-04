#!/usr/bin/env python3
"""L2 live evidence report — per-link raw evidence for every attack path.

Reads the v4.3.0 live scan results, rebuilds the attack paths, and renders a
human-readable markdown report where EVERY link of EVERY path shows:
  * its statement and status (verified / inferred / unproven)
  * its evidence references — finding ids, journal request ids, twin rows —
    each with the raw excerpt AND, for journal refs, the FULL raw request
    (method, URL, headers, body) and response line from the journal.
Also cross-checks every journal citation: the excerpt must be a literal
substring of the cited journal entry (substring-verifiable evidence), and any
violation is reported as a FAILED CHECK at the bottom. Zero requests: the
journal is replayed from the saved scan artifacts, never re-sent.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE = os.path.join(ROOT, "build-v423", "results", "live_v430")
OUT = os.path.join(ROOT, "build-v423", "results", "l2_live_report.md")

TARGETS = ["testaspnet", "ginjuice", "gruyere2", "testasp"]


def raw_fields(entry):
    """All raw string fields of a journal entry — the ONLY valid surface for
    substring verification of an excerpt (json.dumps escapes quotes and would
    produce false negatives for XML/quoted excerpts — harness bug fixed round 6)."""
    req, resp = entry.get("request") or {}, entry.get("response") or {}
    out = [str(req.get("url") or ""), str(req.get("body") or "")]
    out += [str(v) for v in (req.get("headers") or {}).values()]
    out += [str(resp.get("body") or "")]
    out += [str(v) for v in (resp.get("headers") or {}).values()]
    return out


def journal_entry_block(journal, rid):
    e = journal.get(rid)
    if not e:
        return f"    !! cited request {rid} NOT IN JOURNAL"
    req, resp = e.get("request", {}), e.get("response", {})
    lines = [f"    REQUEST  {req.get('method','?')} {req.get('url','?')}"]
    for k, v in (req.get("headers") or {}).items():
        lines.append(f"      {k}: {str(v)[:100]}")
    body = str(req.get("body") or "")
    if body:
        lines.append(f"      body: {body[:160]}{'...' if len(body) > 160 else ''}")
    lines.append(f"    RESPONSE {resp.get('status','?')}")
    for k, v in (resp.get("headers") or {}).items():
        lines.append(f"      {k}: {str(v)[:100]}")
    rb = str(resp.get("body") or "")
    if rb:
        lines.append(f"      body[0:200]: {rb[:200]}")
    return "\n".join(lines)


def render_target(name, rep, md, checks):
    ap = rep.get("attack_paths") or {}
    paths, s = ap.get("paths", []), ap.get("summary", {})
    findings = {f["id"]: f for f in rep.get("findings", [])}
    journal = (rep.get("stats") or {}).get("request_journal") or {}
    md.append(f"\n## {name} — {rep.get('target','')} (run {rep.get('run_id','')}, scanner {rep.get('scanner','')})\n")
    src = rep.get("l2_source")
    if src:
        md.append(f"**L2 SOURCE (honesty note): {src}**\n")
    else:
        md.append("**L2 SOURCE: fresh v4.3.0 live scan — attack paths integrated "
                  "in the scan pipeline (orchestrator.report())**\n")
    md.append(f"**{s.get('paths_total',0)} paths: {s.get('paths_verified',0)} VERIFIED / "
              f"{s.get('paths_inferred',0)} INFERRED** ({s.get('singles',0)} single-finding, "
              f"{s.get('chains',0)} chains) — weak-link histogram: `{s.get('weak_link_histogram',{})}`\n")
    md.append(f"Seeds used: `{', '.join(s.get('seed_findings', []))}`; non-seed findings (annotation-only "
              f"classes): `{json.dumps(s.get('non_seed_findings', {}))}`\n")
    for p in paths:
        md.append(f"\n### {p['id']} — {p['classification']} — {p['title']}")
        if p["classification"] == "VERIFIED":
            md.append("*Every link below carries verified evidence. The path is fully proven.*")
        else:
            md.append(f"**INFERRED — weak links: {', '.join(p['weak_links'])}. The path is NOT presented "
                      "as proof; the unproven links are named above.**")
        md.append(f"\nfindings: {', '.join(p['findings'])} | chain_rule: {p.get('chain_rule') or '—'}"
                  f" | mitigations absent: "
                  f"{json.dumps([m['header'] for m in p.get('mitigations_absent', [])])}")
        for h in p.get("hops", []):
            md.append(f"\n**HOP {h['step']}** [{h['status'].upper()}] (finding {h['finding_id']}) — {h['statement']}")
            for e in h.get("evidence", []):
                md.append(f"  - evidence: {e['kind']} `{e['ref']}` — `{e['excerpt'][:110]}`")
        md.append("")
        md.append("| Link | Status | Statement |")
        md.append("|---|---|---|")
        for l in p["links"]:
            md.append(f"| **{l['slot']}** | {l['status']} | {l['statement'][:220]} |")
        md.append("\n<details><summary>raw evidence, link by link</summary>\n")
        for l in p["links"]:
            md.append(f"\n**[{l['slot'].upper()}] — {l['status']}**\n")
            md.append(f"  {l['statement']}\n")
            for e in l["evidence"]:
                md.append(f"  - `{e['kind']}` ref `{e['ref']}` excerpt: `{e['excerpt'][:140]}`")
                if e["kind"] == "finding":
                    f = findings.get(e["ref"])
                    if f:
                        md.append(f"    finding: {f['type']} {f['method']} {f['url']} param={f['parameter']} "
                                  f"status={f['status']} conf={f.get('confidence')}")
                        for ev in (f.get("evidence") or [])[:3]:
                            md.append(f"      evidence[{ev.get('kind')}]: {ev.get('detail','')[:150]}")
                        v = f.get("verification") or {}
                        md.append(f"      verification: {v.get('method')} passed={v.get('passed')} "
                                  f"conf={v.get('confidence')} rounds={v.get('rounds')}")
                elif e["kind"] == "journal":
                    raw = json.dumps(journal.get(e["ref"], {}))
                    if e["ref"] not in journal:
                        checks.append(f"{name}/{p['id']}/{l['slot']}: journal ref {e['ref']} MISSING")
                    else:
                        fields = raw_fields(journal[e["ref"]])
                        if not (e["excerpt"] and any(e["excerpt"] in f for f in fields)):
                            checks.append(f"{name}/{p['id']}/{l['slot']}: excerpt NOT a literal slice of "
                                          f"journal {e['ref']}: {e['excerpt'][:60]!r}")
                    md.append(journal_entry_block(journal, e["ref"]))
                elif e["kind"] == "twin":
                    md.append(f"    twin row: {e['excerpt'][:160]}")
                elif e["kind"] == "scan_artifact":
                    md.append(f"    artifact: {e['excerpt'][:160]}")
        md.append("\n</details>\n")
    return paths


def main():
    md = ["# SENTINEL v4.3.0 — L2 Attack Path Intelligence: LIVE EVIDENCE REPORT",
          "",
          f"Generated from live scan results of the authorized targets "
          f"({', '.join(TARGETS)}). gruyere2 and testasp are FRESH v4.3.0 live "
          "scans (attack paths integrated in the pipeline). testaspnet and "
          "ginjuice are v4.3.0 L2 projections over their REAL v4.2.3 live "
          "journals (this environment kills background processes and caps "
          "foreground calls at 600s; those scans take 936s/620s — the engine "
          "is verdict-identical per the gates and L2 is a zero-request pure "
          "projection; a fresh ginjuice re-scan attempt overran the window "
          "and was discarded). Every path is classified by the weakest-link "
          "rule: "
          "a path is VERIFIED only when ALL seven links (Identity, Entry, Action, "
          "Object, Authorization, State, Impact) trace to verified evidence — "
          "finding records, raw request-journal entries, twin rows, scan artifacts. "
          "Any inferred link makes the whole path INFERRED and the weak links are "
          "named. This report replays the saved journals; it sends zero requests.",
          ""]
    checks = []
    total = {"paths": 0, "verified": 0, "inferred": 0}
    for t in TARGETS:
        p = os.path.join(LIVE, f"{t}.json")
        if not os.path.exists(p):
            md.append(f"\n## {t}: RESULT FILE MISSING ({p})\n")
            continue
        rep = json.load(open(p, encoding="utf-8"))
        paths = render_target(t, rep, md, checks)
        total["paths"] += len(paths)
        total["verified"] += sum(1 for x in paths if x["classification"] == "VERIFIED")
        total["inferred"] += sum(1 for x in paths if x["classification"] == "INFERRED")
    md.insert(4, f"\n**TOTAL: {total['paths']} paths — {total['verified']} VERIFIED / "
                 f"{total['inferred']} INFERRED**\n")
    md.append("\n## Evidence cross-checks\n")
    if checks:
        md.append("**FAILED CHECKS — citations that did not verify:**")
        for c in checks:
            md.append(f"- {c}")
    else:
        md.append("**ALL CHECKS PASSED** — every journal citation exists in the journal and every "
                  "excerpt is a literal slice of the cited raw entry (substring-verified evidence).")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    print(json.dumps({"written": OUT, "paths": total,
                      "failed_checks": len(checks), "checks": checks[:10]}))


if __name__ == "__main__":
    main()
