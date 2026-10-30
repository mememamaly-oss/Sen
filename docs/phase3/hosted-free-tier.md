# Phase 3 — Item 10: Free hosted tier — design (groundwork, 2026-10-31)

> Status: DESIGN ONLY. No hosting deployed (the VPS runner from Phase 1 is
> the prerequisite). Written so the decision is made once, not re-litigated
# per prospect.

## Why a free tier at all

Zero customers means zero case studies. The free tier is a case-study
machine: bounded real scans of the user's own target, in exchange for
aggregated (anonymous) detection statistics and — with consent — a named
case study. It is not a revenue line; it is evidence production.

## Limits (the whole product decision, kept deliberately small)

| Dimension | Free tier | Paid (later) |
|-----------|-----------|--------------|
| Scans | 1 concurrent per account, 3/day | Queues, parallelism |
| Targets | 1 registered target | Unlimited |
| Scope | Public HTTP/HTTPS targets only (no lab mode) | Lab mode, authenticated scans |
| Retention | 14 days (findings + reports) | Contractual |
| Reports | SARIF + HTML download | All formats, signed exports |
| Support | Community/docs only | SLA |

## Hard security boundaries (non-negotiable, already coded)

1. Private egress: NEVER on the free tier — `SENTINEL_ALLOW_PRIVATE_TARGETS`
   stays unset in that deployment; the engine re-validates and fails closed.
2. Authorization to scan: the operator ToS requires ownership of the target;
   abuse = termination (the in-memory rate limiter's documented single-process
   assumption holds — one container per free-tier deployment).
3. Tenant isolation: same RBAC/membership chain as production (this is the
   same codebase; the CI suite re-proves it on every push).

## Cost envelope

- One VPS (~$6/mo class) runs: Caddy + standalone Next + PostgreSQL
  (docker-compose) + engine subprocess scans. The free tier's 1-concurrent
  cap bounds worst-case CPU; the engine's own safety policy bounds requests.
- Watch: scan queue depth and PG volume; the 14-day retention job is the
  first thing to build when this moves from design to code.

## Metrics that decide continuation (review after 60 days)

- ≥ 20 activated accounts (registered a target and ran ≥ 1 scan)
- ≥ 3 unprompted external replays of published reports
- ≥ 1 convertible conversation originating from the free tier
- If none: kill it; the bottleneck is elsewhere (per the valuation analysis,
  the differentiator is proof, not features).
