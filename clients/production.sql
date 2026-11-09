-- The run relying party for the production identity database (A1-07; docs/RP_CONTRACT.md "Registration").
-- Reviewed configuration, applied by the deploy-production job after the migrations and before the Worker.
-- Exactly one exact HTTPS callback: run's own host for this environment. Idempotent.
INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash)
VALUES ('run','Synthetos Run','binding','["https://run.synthetos.com/auth/callback"]',NULL)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,
  redirect_uris_json=excluded.redirect_uris_json,secret_hash=NULL;
