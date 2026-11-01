-- Expand-only baseline. Timestamps are integer Unix seconds; hashes are lowercase SHA-256 hex.
CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL CHECK (
    length(id) = 30 AND substr(id, 1, 4) = 'usr_' AND
    substr(id, 5) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
  ),
  display_name TEXT NOT NULL,
  avatar_url TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'locked', 'deleting')),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  deletion_requested_at INTEGER CHECK (deletion_requested_at >= created_at),
  CHECK ((status = 'deleting') = (deletion_requested_at IS NOT NULL))
) STRICT;

CREATE TABLE identities (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (length(provider) > 0),
  provider_subject TEXT NOT NULL CHECK (length(provider_subject) > 0),
  login TEXT NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  linked_at INTEGER NOT NULL CHECK (linked_at >= 0),
  last_used_at INTEGER CHECK (last_used_at >= linked_at),
  UNIQUE (provider, provider_subject),
  CHECK (email IS NOT NULL OR email_verified = 0)
) STRICT;

CREATE TABLE oauth_clients (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('binding', 'confidential')),
  redirect_uris_json TEXT NOT NULL CHECK (json_valid(redirect_uris_json) AND json_type(redirect_uris_json) = 'array'),
  secret_hash TEXT CHECK (length(secret_hash) = 64 AND secret_hash NOT GLOB '*[^0-9a-f]*'),
  backchannel_logout_uri TEXT,
  CHECK ((kind = 'binding' AND secret_hash IS NULL) OR (kind = 'confidential' AND secret_hash IS NOT NULL))
) STRICT;

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client TEXT NOT NULL REFERENCES oauth_clients(id),
  -- Cross-database reference to run.devices: enforced by run code exchange, never a cross-DB FK.
  device_record_id TEXT,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  last_seen_at INTEGER NOT NULL CHECK (last_seen_at >= created_at),
  idle_expires_at INTEGER NOT NULL,
  abs_expires_at INTEGER NOT NULL,
  auth_at INTEGER NOT NULL CHECK (auth_at >= 0 AND auth_at <= created_at),
  shared_computer INTEGER NOT NULL DEFAULT 0 CHECK (shared_computer IN (0, 1)),
  ua_summary TEXT,
  ip_hash TEXT,
  country TEXT,
  revoked_at INTEGER CHECK (revoked_at >= created_at),
  revoke_reason TEXT,
  CHECK (idle_expires_at > created_at AND idle_expires_at <= abs_expires_at),
  CHECK (last_seen_at < abs_expires_at),
  CHECK (client <> 'run' OR (device_record_id IS NOT NULL AND length(device_record_id) > 0)),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
) STRICT;

CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY NOT NULL CHECK (length(code_hash) = 64 AND code_hash NOT GLOB '*[^0-9a-f]*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client TEXT NOT NULL REFERENCES oauth_clients(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL CHECK (length(code_challenge) = 43 AND code_challenge NOT GLOB '*[^A-Za-z0-9_-]*'),
  auth_at INTEGER NOT NULL CHECK (auth_at >= 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > auth_at),
  used_at INTEGER CHECK (used_at >= auth_at AND used_at < expires_at)
) STRICT;

CREATE TABLE auth_requests (
  state_hash TEXT PRIMARY KEY NOT NULL CHECK (length(state_hash) = 64 AND state_hash NOT GLOB '*[^0-9a-f]*'),
  browser_nonce_hash TEXT NOT NULL CHECK (length(browser_nonce_hash) = 64 AND browser_nonce_hash NOT GLOB '*[^0-9a-f]*'),
  client TEXT NOT NULL REFERENCES oauth_clients(id),
  redirect_uri TEXT NOT NULL,
  return_to TEXT NOT NULL,
  pkce_verifier_enc TEXT NOT NULL CHECK (length(pkce_verifier_enc) > 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > 0),
  used_at INTEGER CHECK (used_at >= 0 AND used_at < expires_at)
) STRICT;

CREATE TABLE deletion_jobs (
  user_id TEXT NOT NULL REFERENCES users(id),
  product TEXT NOT NULL REFERENCES oauth_clients(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'retry', 'completed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_at INTEGER NOT NULL CHECK (next_at >= 0),
  PRIMARY KEY (user_id, product)
) STRICT;

-- Deliberately no cascading user/session FK: account deletion must not erase the audit trail.
CREATE TABLE security_audit (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT,
  at INTEGER NOT NULL CHECK (at >= 0),
  session_id TEXT,
  client TEXT,
  event TEXT NOT NULL CHECK (length(event) > 0),
  detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json) AND json_type(detail_json) = 'object'),
  ip_hash TEXT
) STRICT;

CREATE TRIGGER security_audit_no_update BEFORE UPDATE ON security_audit
BEGIN SELECT RAISE(ABORT, 'security_audit is append-only'); END;
CREATE TRIGGER security_audit_no_delete BEFORE DELETE ON security_audit
BEGIN SELECT RAISE(ABORT, 'security_audit is append-only'); END;
