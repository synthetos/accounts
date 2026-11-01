-- Expand-only lookup indexes; compatible with the preceding application/schema version.
CREATE INDEX identities_by_user ON identities(user_id);
CREATE INDEX sessions_by_user_client ON sessions(user_id, client);
CREATE INDEX sessions_by_expiry ON sessions(abs_expires_at);
CREATE INDEX auth_codes_by_expiry ON auth_codes(expires_at);
CREATE INDEX auth_requests_by_expiry ON auth_requests(expires_at);
CREATE INDEX deletion_jobs_due ON deletion_jobs(status, next_at);
CREATE INDEX security_audit_by_user_time ON security_audit(user_id, at);
