-- Synthetic test records only. Never seed these into a deployed database.
INSERT INTO users(id, display_name, created_at) VALUES
  ('usr_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'Fixture One', 1000),
  ('usr_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'Fixture Two', 1000);
INSERT INTO identities(id, user_id, provider, provider_subject, login, linked_at) VALUES
  ('idn_fixture_1', 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'github', '100000001', 'fixture-login', 1000);
INSERT OR IGNORE INTO oauth_clients(id, name, kind, redirect_uris_json) VALUES
  ('accounts', 'Accounts fixture', 'binding', '["https://accounts.example.test/callback"]'),
  ('run', 'Run fixture', 'binding', '["https://run.example.test/auth/callback"]');
