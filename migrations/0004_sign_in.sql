-- Compatible additions for A1-03. Existing auth requests predate this flow and expire normally.
ALTER TABLE auth_requests ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0 CHECK (created_at >= 0);

CREATE TABLE login_rate_limits (
  bucket_hash TEXT PRIMARY KEY NOT NULL,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts > 0)
) STRICT;
CREATE INDEX login_rate_limits_by_time ON login_rate_limits(window_start);

CREATE TABLE webhook_deliveries (
  delivery_hash TEXT PRIMARY KEY NOT NULL,
  payload_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX webhook_deliveries_by_expiry ON webhook_deliveries(expires_at);

-- Prevent a callback already in flight when authorization is revoked from creating a new session.
CREATE TABLE provider_revocations (
  provider TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  revoked_at INTEGER NOT NULL,
  PRIMARY KEY (provider, provider_subject)
) STRICT;

INSERT INTO oauth_clients(id,name,kind,redirect_uris_json)
VALUES ('accounts','Synthetos Accounts','binding','[]') ON CONFLICT(id) DO NOTHING;
