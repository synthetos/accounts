# Synthetos Accounts

Foundations for accounts.synthetos.com, following RUN_PLAN §3 and Track A1.
GitHub sign-in and accounts sessions are implemented locally. The Worker defaults
to a 503 response until explicitly configured; no authentication endpoint is live.

## Current validation status

A1-01 and A1-02 are independently accepted. A1-03 is implemented and awaiting review:

- Frozen clean installation with lifecycle scripts disabled.
- TypeScript, ESLint, dependency-cruiser and dependency licences.
- 58 unit/schema/policy tests, including independent crypto vectors, audit retention
  boundaries and GitHub sign-in failure cases.
- Stryker: **94.54%**, 519 killed / 549 total, 30 survivors, no timeouts or errors;
  threshold remains 90%. Every mutated source file scores above 90%.
- Local Wrangler D1: migration application, repeated application, fixture seed,
  provider/subject uniqueness rejection and audit retention guards.
- Built Worker on local workerd/D1: complete sign-in with intercepted GitHub requests,
  session validation and callback replay refusal. No requests reach GitHub.
- Two clean source-copy builds produce identical bytes; the separate build
  toolchain installs only TypeScript, and the built Worker passes its smoke check.

The initial sandbox restrictions were removed before the mutation and D1 runs.
The independent collaborator has accepted A1-01 and A1-02. A1-03 review and
confirmation of the later licence-gate and encoding regressions remain pending.
No hosted CI run, push, resource provisioning
or deployment has been performed. These are foundations, not a
production-ready identity service.

## Layout

- `packages/auth-core`: no runtime dependencies; WebCrypto, Fetch request objects
  and cookie serialization. No network calls or persistence.
- `packages/idp`: provider interface and GitHub App adapter; zero npm dependencies.
- `workers/accounts`: browser-bound sign-in, accounts sessions, revocation webhook
  and storage. OIDC/RPC and account-management pages come in A1-04/A1-05.
- `migrations`: forward identity schema migrations and indexes, with synthetic test fixtures.
- `ci/build-toolchain`: TypeScript only, pinned independently of test tools.
- `ci/deploy-toolchain`: Wrangler only, pinned separately from the build.
- `tools`: build reproducibility and policy checks.

## Local commands

Use Node 22.22.0 and the pnpm version/hash in `packageManager`.

```sh
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm check
```

Never use an unfrozen install in CI. The auth tests can also run without
installing anything:

```sh
node --test packages/auth-core/test/*.test.mjs
```

## Auth contracts

`randomToken()` returns 256-bit base64url values for session tokens, state,
browser nonces and authorization codes. Store only `hashToken()` digests for
bearer tokens. Storage-backed single use, TTL and browser nonce verification
belong to A1-03/A1-04; these primitives alone do not implement an OAuth flow.

Cookie helpers accept only canonical 32-byte token values. They always set
Secure, HttpOnly, Path=/ and the caller's Strict/Lax policy, never Domain.
Omit Max-Age for a shared-computer browser-session cookie. Duplicate incoming
cookies fail closed. The server must separately enforce idle/absolute expiry.

API mutation guards require exact HTTPS Origin, same-origin fetch metadata
when present, the custom header and JSON (binary only when explicitly enabled).
Form routes instead verify an HMAC token bound to session, action and expiry.
These guards do not establish user authentication or resource authorization.

ID tokens use ES256/P-256 with a fixed JWT header and single audience. Verification
requires a caller-supplied trusted key, issuer, audience, key id, current time
and lifetime cap, plus an explicit `clockToleranceSeconds` integer from 0 to 60.
Tolerance applies only to future `iat`/`nbf`; `exp` remains strict and the lifetime
cap is unchanged. Signing and verification both reject audience arrays.
Pass the expected nonce when the authorization request used
one. Never choose a key or issuer from unverified token URLs. This is an ID-token
helper, not a generic access-token or multi-audience OIDC implementation.

## GitHub sign-in (A1-03)

`GET /login` renders a script-free form with a nonce cookie and synchronizer token.
`POST /login` requires the exact Origin, form token and cookie, limits starts to
10 per hashed edge IP per 10 minutes, and redirects to GitHub with state and S256
PKCE. The callback consumes state atomically only when its browser cookie matches.
The verifier is encrypted with AES-GCM and bound to the origin and state/nonce
hashes. OAuth's callback GET is the protocol exception to the form mutation rule.
Return paths are restricted local paths; arbitrary redirect URLs are never accepted.

The adapter uses the [GitHub App user-authorization flow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app).
It requests no scope or refresh token, calls `/user` once and persists only the
selected identity fields. Email is discarded even if GitHub returns it. Tokens
are neither persisted nor logged. Redirects are handled manually and rejected on
both outbound requests. Profile avatars are stored as metadata, never fetched or
rendered. Public provider errors and request errors contain no upstream details.

Accounts session cookies are host-only, Secure, HttpOnly and SameSite=Lax, with
30-day absolute and 14-day idle expiry. D1 holds only token hashes. Every request
opens a [first-primary D1 session](https://developers.cloudflare.com/d1/best-practices/read-replication/);
validation checks account status and revocation, with idle timestamp writes at
most every five minutes. New sessions are refused for locked/deleting users and
for flows that began before a recorded GitHub revocation.

`POST /webhooks/github` verifies HMAC-SHA256 over the body with WebCrypto and
deduplicates delivery IDs for seven days in the same D1 batch as revocation.
Distinct legitimate revocations can have identical bodies, so payload hashes are
not unique. GitHub's signature covers the body, not the delivery-ID header; this
is delivery-ID replay protection, not an independent signed freshness guarantee.

Required bindings/configuration: `AUTH_ENABLED=true`, exact HTTPS `ACCOUNT_ORIGIN`,
`IDENTITY` D1, and the new zero-permission app's `GITHUB_APP_ID`, `GITHUB_CLIENT_ID`
and `GITHUB_CLIENT_SECRET`. The forum app ID is explicitly refused. Secrets
`OAUTH_STATE_KEY`, `FORM_KEY` and `RATE_KEY` are independent canonical base64url
32-byte keys; `GITHUB_WEBHOOK_SECRET` must contain at least 32 UTF-8 bytes. Never
reuse production secrets in fixtures. Invocation observability is explicitly
disabled, and application code does not log requests, credentials or upstream errors.
No real app registration, secrets or database bindings are included in this repo.

Before release, A1-07 must provide those resources, the production tester allowlist
and staging Access protection. Scheduled retention for old login requests, rate
buckets, revocation metadata and audit/session rows still needs implementation;
webhook delivery cleanup occurs on webhook processing. Account management and
step-up are A1-05. A1-04 must persist and echo the RP nonce in a forward migration.

Tests use the [RFC 7636 appendix B vector](https://www.rfc-editor.org/rfc/rfc7636#appendix-B)
and independent Node crypto signing/verification. JWT validation follows the
algorithm and claim checks described in [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725).

## CI and release controls

The workflow is JSON (a YAML subset) so policy tests parse it without a custom
YAML parser. Verify has no secrets. Build installs only TypeScript and compares
two clean builds byte for byte. The attestation job has no repository checkout
or script execution. Deploy jobs alone receive the Cloudflare token, verify the
artifact provenance against the exact commit/workflow, and use `--no-bundle`.

Before enabling `ACCOUNTS_DEPLOY_ENABLED`, the owner must create the repository,
review A1-07 configuration, set the dedicated account bindings and routes, and
configure protected staging/production environments. Production requires owner
approval. Configure native branch protection with two trusted approving reviews,
Code Owner review, stale-review dismissal and required verify/build/e2e checks.
These server settings cannot be enforced by PR-editable CI alone.

Nothing has been pushed, deployed, or provisioned. The build/deploy lockfiles
and action pins were taken from run commit `dc5accd`; no run files were changed.
