# Production provisioning

Owner decision, 2026-11-13. The owner approves protected production jobs; no local wrangler or dashboard resource provisioning.

Run `production-provision` on main and approve production. It looks up `identity` with the separate D1: Edit credential, creates only when absent, and prints its non-secret id. Submit that id in a reviewed PR replacing `IDENTITY_DATABASE_ID_PLACEHOLDER`. The existing deploy-production job still requires preflight, migrations and relying-party registration before deploying its attested artifact. `GITHUB_ALLOWED_IDS` stays exactly `["231731"]`.

One owner credential step: create a new client secret on the existing Synthetos GitHub App and save it as `APP_CLIENT_SECRET` in this repository's protected **production** environment. Do not use staging's client secret. Do not place its contents in logs, source, issues or reviews.

After the first accounts deploy, run `production-secrets` on main, choosing accounts, and approve production. After run's run-auth provisioning/id PR/deploy, repeat with Worker run. The exact staging generation plan is reused, but every missing random/signing value is freshly generated for the selected production Worker. Values go straight from runner memory to the Worker secret store: never printed or written elsewhere. Existing Worker secrets are retained, so retries do not invalidate sessions. Only APP_CLIENT_SECRET comes from the production GitHub environment and maps to GITHUB_CLIENT_SECRET; a missing client secret is reported by name, never replaced by a staging value.

CI generates accounts' OAUTH_STATE_KEY, FORM_KEY, RATE_KEY, GITHUB_WEBHOOK_SECRET and ID_TOKEN_PRIVATE_JWK, and run's RUN_STATE_KEY and RUN_RATE_KEY. Staging generates its webhook secret too, so no additional owner webhook-secret input is required. CLOUDFLARE_API_TOKEN is confined to secret-setting steps; CLOUDFLARE_D1_API_TOKEN is confined to database provisioning/migrations. CLOUDFLARE_ACCOUNT_ID is an environment variable.

Production uses the existing Synthetos GitHub App 5562809 with callback https://accounts.synthetos.com/auth/github/callback. No new app is created. See run's docs/ops/go-live-staging.md §7 for the ordered checklist and unchanged prerequisites and acceptance checks.
