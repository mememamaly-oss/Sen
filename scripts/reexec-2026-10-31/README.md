# 2026-10-31 strict re-execution — audit-trail scripts

Provenance: the 2026-10-31 session re-executed the crypto order
(Parts 0-3) from scratch against main 0759c85. These are the exact
scripts used (guard + run wrappers). The passive re-observation step
(gj_passive_reobserve.py from scripts/reverify/) was invoked inline
without a wrapper. All engine/replay/scoring methodology scripts live in
scripts/reverify/ (committed 2026-10-30, d51a5c1) and were reused
unmodified. No secrets: the GitHub token was only ever passed via the
GH_TOKEN environment variable, never written to any file.
