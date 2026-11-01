-- One bounded counter per registered client, shared across Worker isolates.
CREATE TABLE introspection_rate_limits (
  client TEXT PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
  window_start INTEGER NOT NULL CHECK(window_start >= 0),
  attempts INTEGER NOT NULL CHECK(attempts >= 1)
) STRICT;
