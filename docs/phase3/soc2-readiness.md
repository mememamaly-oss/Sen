# Phase 3 — Item 9: SOC 2 Type II readiness (groundwork, 2026-10-31)

> Status: NOT STARTED as an audit. This checklist maps what the codebase
> already does (verifiable) against the five Trust Services Criteria, so the
> owner knows the real gap before paying an auditor. Rule from the plan:
> SOC 2 Type II only at the first enterprise customer — not before.

## Control inventory — what exists TODAY (verifiable in-repo)

| TSC | Control already implemented | Where |
|-----|------------------------------|-------|
| Security | Multi-tenant isolation: every row carries orgId; every query membership-guarded | src/lib/rbac.ts, prisma/schema.prisma |
| Security | Append-only audit log (no deletes/edits) of every action | AuditLog model, src/app/(app)/audit |
| Security | scrypt password storage; login rate limiting; timing equalization | src/lib/passwords.ts, src/lib/auth.ts |
| Security | Server-side session guard on all authenticated pages | src/app/(app)/layout.tsx |
| Security | SSRF policy: private egress only for demo target or explicit operator lab mode; engine re-validates every connection | src/lib/engine.ts, sentinel/http_engine.py |
| Security | Signed, replayable reports (Ed25519; RFC 8032 vectors) | sentinel/audit.py, tests/test_proof_rfc8032.py |
| Security | Credential vault: encrypted at rest, authorized-key reveal, audited | sentinel/vault.py |
| Availability | Single-process standalone deployment + loopback-only upstreams | Caddyfile, scripts/start_prod_server.sh |
| Processing integrity | Verification-gated findings; determinism; rejected candidates exported for audit | engine (verification gate), CI fixture job |
| Confidentiality | Tenant data isolation; robots noindex; no cross-tenant leakage by design | rbac tests in tests/api.integration.test.ts |

## Real gaps (the honest list an auditor will find)

1. **Formal policies** — no written Information Security Policy, change
   management, or incident response plan. (Owner writing task, not code.)
2. **Monitoring/alerting** — no centralized logging/SIEM, no uptime alerting.
   The audit log exists but nothing watches it.
3. **Change management** — git history + CI gates exist; no documented CAB
   approval flow.
4. **Backups/DR** — PostgreSQL backups + restore drills: not implemented
   (docker-compose ships a volume; no backup policy).
5. **Vendor management / HR onboarding** — single-operator reality; an
   auditor will flag key-person concentration.
6. **Observational period** — Type II needs 3–12 months of operating
   evidence; starting the clock early is cheap, auditing early is waste.

## Recommended sequencing (per the plan)

1. First enterprise deal that contractually requires SOC 2 → engage an
   auditor for Type I (point-in-time) immediately.
2. Start the evidence clock (backups, monitoring, policies) on day one of
   that engagement.
3. Convert to Type II after the minimum observation window the auditor
   accepts — do not pay for Type II before evidence exists.
