=== CLEAN RESTORE BUILD RECORD (2026-10-02) ===
restore dir: /home/z/l1-clean-restore (separate from both working trees)
bun install: 827 packages (8.24s)
prisma db push: OK (SQLite custom.db created; TwinGraph model present)
next build (webpack + standalone): OK — BUILD_ID OhPg_TurrG-Bfk4YTBkP6
tsc --noEmit: 0 errors
routes: /twin present (static shell + API-driven)
engine extract verify: restored build-v411 diff -r vs frozen SENTINEL-v4.1.1-source.tar.gz = 0
NOTE: DATABASE_URL exported by the platform shell overrides .env (prisma/dotenv precedence);
      every restore-tree command must set DATABASE_URL explicitly (documented in RESTORE_INSTRUCTIONS).
