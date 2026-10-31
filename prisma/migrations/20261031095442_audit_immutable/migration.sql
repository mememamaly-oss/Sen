-- DropForeignKey
ALTER TABLE "AuditLog" DROP CONSTRAINT "AuditLog_orgId_fkey";

-- DropForeignKey
ALTER TABLE "AuditLog" DROP CONSTRAINT "AuditLog_userId_fkey";

-- AUDIT-LOG IMMUTABILITY (owner order 2026-10-31, part 2.6):
-- the trail is append-only AT THE DATABASE LEVEL. Application logic is
-- bypassable by definition (a compromised app account holds this same
-- Prisma connection); a trigger is not reachable from the application
-- layer at all. Dropping the FKs first: an append-only trail must survive
-- the deletion of the org/user it references (the previous ON DELETE SET
-- NULL silently REWROTE audit rows when an org was deleted — an implicit
-- mutation of the historical record, proven by the red test).

CREATE OR REPLACE FUNCTION sentinel_audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'AuditLog is append-only: % blocked at the database level (trigger audit_log_immutable)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_immutable ON "AuditLog";
CREATE TRIGGER audit_log_immutable
  BEFORE UPDATE OR DELETE ON "AuditLog"
  FOR EACH ROW EXECUTE FUNCTION sentinel_audit_log_immutable();
