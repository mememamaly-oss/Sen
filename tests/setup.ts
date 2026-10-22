// Test-environment bootstrap: runs BEFORE any module import (bun --preload).
// The SaaS modules construct a PrismaClient at import time, which requires
// DATABASE_URL; tests use throwaway sqlite files.
process.env.DATABASE_URL = process.env.DATABASE_URL || "file:./tests/unit-test.db";
process.env.NEXTAUTH_SECRET = process.env.NEXTAUTH_SECRET || "test-only-secret";
process.env.SENTINEL_DATA_DIR = process.env.SENTINEL_DATA_DIR || "/tmp/sentinel-test-data";
process.env.NODE_ENV = process.env.NODE_ENV || "test";
