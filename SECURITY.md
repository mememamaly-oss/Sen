# Security Policy

## Scope

This policy covers security vulnerabilities **in Burhan itself** — the scan
engine (`burhan/`), the SaaS platform (`src/`), the CI integrations
(`.github/`, `integrations/`), and the published artifacts of this
repository.

It does **not** cover the applications Burhan scans. Burhan is a DAST scanner:
finding vulnerabilities in *targets* is the product. If your scanned
application reports issues, use the normal issue tracker.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's **private vulnerability reporting** on this repository
(Security tab → "Report a vulnerability"). That channel keeps the report
private to the maintainers and lets us coordinate a fix before disclosure.

If private reporting is unavailable to you for some reason, open a regular
issue containing **no vulnerability details** — only a request for a
private channel — and a maintainer will provide one.

Please include, where possible:

- the affected component and file(s),
- a minimal reproduction (command line, request, or code),
- the impact you believe it has,
- any mitigations you have already considered.

## What you can expect from us

- **Acknowledgement within 7 days** of a report arriving through the
  private channel. Burhan is maintained by a single maintainer; this is an
  honest, deliberate commitment rather than an enterprise SLA.
- An initial assessment (severity, affected versions, fix approach)
  **within 30 days**.
- Fixes prioritized by severity; critical issues in the current release
  line are addressed first.
- Coordinated disclosure: we credit reporters (unless you prefer to stay
  anonymous) and publish an advisory once a fix is released.

## What we cannot promise

- A bounty program (there is none at the time of writing).
- Security support for anything other than the **latest tagged release**
  and the `main` branch.
- Response-time guarantees during the maintainer's offline periods; the
  timestamps above are targets we are actually prepared to honor, not
  contractual terms.

## Safe-harbor

We will not pursue legal action against anyone who makes a good-faith
effort to comply with this policy, avoids privacy violations, degradation
of user experience, disruption to production systems, and destruction of
data, and who reports findings exclusively through the private channel.

## Signing keys used by this project

- `transparency-log/pubkey.hex` — the Ed25519 public key whose signatures
  appear in `transparency-log/log.jsonl`. Any entry not verifiable with
  this key must be treated as untrusted. See
  `docs/transparency-log-format.md` for the verification procedure and the
  key-rotation policy.
- Scan reports additionally carry a per-run Ed25519 key derived from the
  (public, by design) run seed — see `docs/AUDIT_VERIFICATION.md`.
