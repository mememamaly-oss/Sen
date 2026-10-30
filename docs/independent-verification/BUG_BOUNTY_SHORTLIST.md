# BUG BOUNTY SHORTLIST — programs and the automation question (owner actions)

Goal (Phase 1, item 3): 3–5 ACCEPTED reports on programs that explicitly
permit automated scanning. One accepted report is worth more marketing
than 100 internal tests. Everything below was researched 2026-10-31; policy
pages change — **re-verify the program's automation clause on the day you
scan**, and when a policy is silent, ask the program's triage FIRST.

## The decision rule (applies to every program, always)

1. Find the program's policy section about automated tools / scanners /
   traffic limits.
2. "Allowed (with limits)" → scan, but cap the engine's request budget
   BELOW the stated limit (the engine's `max_requests` exists exactly for
   this).
3. "Prohibited" or silent → do NOT scan with the engine; manual testing
   only, or pick another program.
4. Never scan out-of-scope assets, even for one probe.

## Verified: allows automated tools (with traffic limits)

- **GitHub Security Bug Bounty** (HackerOne: https://hackerone.com/github)
  — the Rules of Engagement state: "We do allow the use of automated tools
  so long as they do not produce excessive amounts of traffic. For example,
  running one nmap scan against one host is [acceptable]" (GitHub bug
  bounty rules of engagement; re-verify the current wording at the
  program page). Scope: github.com and GitHub-owned properties per the
  program's asset list. This is the strongest verified candidate — and the
  engine already produces the artifact GitHub triage values: replayable
  per-finding proofs.

## Platform mechanics worth knowing

- **Open Bug Bounty** (https://www.openbugbounty.org) — coordinated
  disclosure for XSS/CSRF-class findings against sites whose owners listed
  them; per-site rules decide automation. Read the site's own terms on its
  listing BEFORE scanning. Non-intrusive classes only — a good fit for the
  engine's passive/reflected-XSS batteries with a LOW request budget.
- **YesWeHack / Intigriti / Bugcrowd** — each PROGRAM on the platform
  sets its own automation policy (there is no platform-wide allowance).
  Filter program listings for an explicit "automated tools" clause.

## Verified counter-examples (do NOT scan with the engine)

- **GitKraken** — "Use of any automated tools/scanners is strictly
  prohibited and will lead to you being removed from the program."
- Many programs (the majority in 2026) run their own continuous scanning
  and restrict researcher automation — the industry trend in 2025–2026 is
  TIGHTER automation policies driven by AI-generated noise (Google's 2026
  pause of parts of its program is the public example). Assume PROHIBITED
  unless the policy says otherwise.

## Legal practice grounds (build the evidence portfolio TODAY, no bounty)

These are NOT bounty programs, but they are fully legal scan targets whose
results you can publish as methodology evidence:

- self-hosted official bundles (Juice Shop / WebGoat / DVWA / crAPI — the
  VPS runner) — the truth-set comparisons in REPORT.md;
- **ginandjuice.shop** — the authorized deliberately-vulnerable target
  already scanned under its posted permission;
- PortSwigger Web Security Academy labs — designed for exactly this.

## The report template (what to submit — it maps 1:1 to the engine's proof files)

```
Title: <class> in <endpoint> — <one-line impact>
Severity: <proposed, with reasoning>

Summary: what the vulnerability is and who is affected.

Steps to reproduce (numbered, copy-pasteable):
 1. <request 1 — exact method, URL, headers, body>
 2. <request 2 — the differential/probe>
 3. <observed response — the oracle evidence>

Impact: concrete attacker capability (data read? which data? state change?
which action?). No impact = no bounty.

Proof: attach the engine's proof file (hypothesis, preconditions, request
chain, evidence kinds, verification rounds, replay status). If the replay
verdict is REPRODUCTION_VERIFIED, say so — a replayable proof is rare in
submissions and shortens triage.

Mitigation suggestion: one paragraph (defense-in-depth; the engine's
evidence kinds map directly to the failing control).
```

## Realistic expectations (no flattery)

- The engine's strongest bounty classes TODAY: reflected/stored XSS,
  SQLi (with its verified oracles), credential/secret exposure, header
  classes, and CSRF. Its weakest: business-logic (manual), deserialization
  (no battery — CLASS-GAP in the Juice Shop score).
- Well-known programs are scanned continuously by the vendors themselves;
  the engine's edge is NOT finding what their scanners find — it is the
  replayable-proof artifact and the differential oracles. Prioritize
  NEWER/SMALLER programs with explicit automation allowances.
- CVE applications: only for vulnerabilities in OTHER products (not
  bounty targets) — a separate workflow (CNA or GitHub Security Advisory);
  a realistic path only if the engine surfaces a genuinely novel product
  bug during legal practice scanning.

## Anti-goals (do not do these)

- Do not scan a program because "they never complained before".
- Do not let the engine run unbounded on any third-party target — always
  set max_requests below the policy's traffic language.
- Do not submit findings without the impact section — policy-violating
  noise burns the account.
