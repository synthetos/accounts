-- Existing sessions with an unknown sign-in identity are conservatively revoked on unlink.
ALTER TABLE sessions ADD COLUMN sign_in_identity_id TEXT REFERENCES identities(id) ON DELETE SET NULL;
CREATE INDEX sessions_by_sign_in_identity ON sessions(sign_in_identity_id);
CREATE TABLE management_requests (
  state_hash TEXT PRIMARY KEY NOT NULL CHECK (length(state_hash)=64 AND state_hash NOT GLOB '*[^0-9a-f]*'),
  browser_nonce_hash TEXT NOT NULL CHECK (length(browser_nonce_hash)=64 AND browser_nonce_hash NOT GLOB '*[^0-9a-f]*'),
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('step_up','link')),
  pkce_verifier_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at>=0),
  expires_at INTEGER NOT NULL CHECK (expires_at>created_at),
  used_at INTEGER CHECK (used_at>=created_at AND used_at<expires_at)
) STRICT;
CREATE INDEX management_requests_expiry ON management_requests(expires_at);
