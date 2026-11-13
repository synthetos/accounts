# Production provisioning

Owner decision, 2026-11-13. The owner approves the protected production jobs; no local wrangler or dashboard provisioning.

Run `production-provision` on main and approve production. It looks up `identity` with the separate D1: Edit credential, creates only when absent, and prints its non-secret id. Submit that id in a reviewed PR replacing `IDENTITY_DATABASE_ID_PLACEHOLDER`. The existing deploy-production job still requires preflight, migrations and relying-party registration before deploying its attested artifact. `GITHUB_ALLOWED_IDS` stays exactly `["231731"]`.

After the first accounts deploy, run `production-secrets` on main, choosing accounts, and approve production. After run's run-auth provisioning/id PR/deploy, repeat with Worker run. This workflow reads only protected production GitHub environment secrets, sets only missing Worker secrets, and never prints values. No staging fallback or key generation is used for production. Existing Worker secrets are retained on retries.

Required production environment inputs (must already be supplied by trusted automation; this workflow does not generate GitHub environment secrets or ask the owner to copy them): accounts uses APP_CLIENT_SECRET, OAUTH_STATE_KEY, FORM_KEY, RATE_KEY, APP_WEBHOOK_SECRET and ID_TOKEN_PRIVATE_JWK; run uses RUN_STATE_KEY and RUN_RATE_KEY. The two APP names map to GITHUB_CLIENT_SECRET and GITHUB_WEBHOOK_SECRET respectively. CLOUDFLARE_API_TOKEN is confined to secret-setting steps; CLOUDFLARE_D1_API_TOKEN is confined to database provisioning/migrations. CLOUDFLARE_ACCOUNT_ID is an environment variable. Missing secrets fail closed; no key contents belong in logs, source, issues or review reports.

Production uses the existing Synthetos GitHub App 5562809 with callback https://accounts.synthetos.com/auth/github/callback. Nothing is created at GitHub. See run's docs/ops/go-live-staging.md §7 for the ordered owner checklist and unchanged prerequisites and acceptance checks.
