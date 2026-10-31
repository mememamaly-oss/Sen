// Test-environment bootstrap: runs BEFORE any module import (bun --preload).
// The SaaS modules construct a PrismaClient at import time, which requires
// DATABASE_URL; tests use throwaway sqlite files.
process.env.DATABASE_URL = process.env.DATABASE_URL || "file:./tests/unit-test.db";
process.env.NEXTAUTH_SECRET = process.env.NEXTAUTH_SECRET || "test-only-secret";
process.env.BURHAN_DATA_DIR = process.env.BURHAN_DATA_DIR || "/tmp/burhan-test-data";
process.env.NODE_ENV = process.env.NODE_ENV || "test";
