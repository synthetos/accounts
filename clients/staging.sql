-- The run relying party for the staging identity database (A1-07; docs/RP_CONTRACT.md "Registration").
-- Reviewed configuration, applied by the deploy-staging job after the migrations and before the Worker.
-- Exactly one exact HTTPS callback: run's own host for this environment. Idempotent.
INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash)
VALUES ('run','Synthetos Run','binding','["https://staging.run.synthetos.com/auth/callback"]',NULL)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,
  redirect_uris_json=excluded.redirect_uris_json,secret_hash=NULL;
