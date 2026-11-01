-- Preserve existing rows and write contracts; permit only age-bounded audit pruning.
-- One year is 365 days (31536000 seconds). At the exact boundary the row is retained.
DROP TRIGGER security_audit_no_delete;
CREATE TRIGGER security_audit_no_delete BEFORE DELETE ON security_audit
WHEN OLD.at >= CAST(strftime('%s', 'now') AS INTEGER) - 31536000
BEGIN SELECT RAISE(ABORT, 'security_audit is append-only within retention'); END;

-- The absolute UPDATE prohibition from 0001 remains in place, including for old rows.
CREATE INDEX security_audit_by_time ON security_audit(at);
-- Effective session expiry can be idle expiry, earlier than absolute expiry.
CREATE INDEX sessions_by_idle_expiry ON sessions(idle_expires_at);
