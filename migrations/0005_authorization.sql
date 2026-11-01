-- Codes issued before this migration have no origin session and cannot be redeemed.
ALTER TABLE auth_codes ADD COLUMN nonce TEXT;
ALTER TABLE auth_codes ADD COLUMN origin_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE;
ALTER TABLE auth_codes ADD COLUMN step_up_at INTEGER CHECK (step_up_at >= 0);
ALTER TABLE auth_codes ADD COLUMN redemption_id TEXT;
CREATE UNIQUE INDEX auth_codes_redemption ON auth_codes(redemption_id) WHERE redemption_id IS NOT NULL;
-- Only the successful same-subject A1-05 step-up flow may write this marker.
ALTER TABLE sessions ADD COLUMN step_up_at INTEGER CHECK (step_up_at >= 0);
CREATE TABLE authorization_requests (
  resume_hash TEXT PRIMARY KEY NOT NULL CHECK (length(resume_hash)=64 AND resume_hash NOT GLOB '*[^0-9a-f]*'),
  browser_nonce_hash TEXT NOT NULL CHECK (length(browser_nonce_hash)=64 AND browser_nonce_hash NOT GLOB '*[^0-9a-f]*'),
  request_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at>=0),
  expires_at INTEGER NOT NULL CHECK (expires_at>created_at),
  used_at INTEGER CHECK (used_at>=created_at AND used_at<expires_at)
) STRICT;
CREATE INDEX authorization_requests_expiry ON authorization_requests(expires_at);
