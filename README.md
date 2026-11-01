# Synthetos Accounts

Foundations for accounts.synthetos.com, following RUN_PLAN §3 and Track A1.
GitHub sign-in, accounts sessions and the A1-04 OIDC/RPC handoff are implemented locally. The Worker defaults
to a 503 response until explicitly configured; no authentication endpoint is live.

## Current validation status

A1-01 through A1-05 are independently accepted. The accounts release-gate implementation
at `3d791a6` passes local validation and awaits independent review:

- Frozen clean installation with lifecycle scripts disabled.
- TypeScript, ESLint, dependency-cruiser and dependency licences.
- 138 unit/schema/policy/type-contract tests, including independent crypto vectors, audit retention
  boundaries and GitHub sign-in failure cases.
- Full-scope Stryker at `3d791a6`: **91.47%**, 2,420 killed, 3 timed out and 226 survivors
  across 2,649 mutants; no runtime or compilation error statuses. Each identity package
  independently passes the unchanged 90% threshold (details below).

- Local Wrangler D1: migration application, repeated application, fixture seed,
  provider/subject uniqueness rejection and audit retention guards.
- Built Worker on local workerd/D1: complete sign-in with intercepted GitHub requests,
  session validation and callback replay refusal; OIDC/JWKS, concurrent redemption,
  named/default/wrong RPC binding checks and forum/run isolation; introspection claims
  and its 600/601 per-client quota boundary; same-subject
  step-up success, replay and wrong-subject revocation. No requests reach GitHub.
- Five real Chromium login/account form-navigation controls, checking CSP and Origin
  and blocked network fallback. See [browser test instructions](test/browser/README.md).
- Two clean source-copy builds produce 47 byte-identical files; the separate build
  toolchain installs only TypeScript, and the built Worker passes its smoke check.

The validation includes the introspection rate-limit/response-contract revision,
three local D1/workerd gates and a staging Wrangler dry run with bundling disabled.

The initial sandbox restrictions were removed before the mutation and D1 runs.
Independent review accepted A1-03 at `6b240ff`, A1-04 at `7c29b4e`/`7e7db46`,
and A1-05 at `831350f` (with regression follow-up `8349842`).
No hosted CI run, push, resource provisioning
or deployment has been performed. These are foundations, not a
production-ready identity service.

## Layout

- `packages/auth-core`: no runtime dependencies; WebCrypto, Fetch request objects
  and cookie serialization. No network calls or persistence.
- `packages/idp`: provider interface and GitHub App adapter; zero npm dependencies.
- `workers/accounts`: browser-bound sign-in, accounts sessions, revocation webhook
  and storage, plus authorization-code OIDC and the named run RPC entrypoint.
  Server-rendered account management, linked identities and step-up are implemented.
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
PKCE. Each attempt prunes at most 100 expired rate-limit buckets; active windows
are preserved. The callback consumes state atomically only when its browser cookie matches.
The verifier is encrypted with AES-GCM and bound to the origin and state/nonce
hashes. OAuth's callback GET is the protocol exception to the form mutation rule.
Return paths are restricted local paths; arbitrary redirect URLs are never accepted.
The login HTML alone uses `form-action 'self' https://github.com` to permit the
form's redirect chain, and `Referrer-Policy: same-origin` to preserve its POST's
Origin. Using `no-referrer` on a form document produces `Origin: null` under the
[Fetch Origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header).
The exact-Origin check stays mandatory. Redirects, callbacks, non-form responses
and errors retain `no-referrer` and `form-action 'self'`; no Referer is sent to
GitHub. A browser-bound cancellation consumes the state, clears only the pre-auth
cookie and offers a retry link, without exchanging a code or creating a session.

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
and `GITHUB_CLIENT_SECRET`, plus `GITHUB_ALLOWED_IDS`. The forum app ID is explicitly refused. Secrets
`OAUTH_STATE_KEY`, `FORM_KEY` and `RATE_KEY` are independent canonical base64url
32-byte keys; `GITHUB_WEBHOOK_SECRET` must contain at least 32 UTF-8 bytes. Never
reuse production secrets in fixtures. Invocation observability is explicitly
disabled, and application code does not log requests, credentials or upstream errors.
No real app registration, secrets or database bindings are included in this repo.

D37 admission is enforced at `Store.signIn` before any user, identity or session is
created. `GITHUB_ALLOWED_IDS` is a JSON array of canonical positive numeric GitHub
ID strings (for example `["12345"]`), not logins. It permits at most 1,000 unique
safe-integer IDs and 100,000 configuration characters. Missing/malformed config
fails closed with 503; a non-listed identity receives 403 and a `sign_in.denied`
audit row with no raw provider data. Request parameters cannot alter admission.
Both checked-in environment defaults are `[]`; nobody can sign in until trusted
configuration supplies IDs. There is no bypass switch. Removing an ID blocks
new sign-ins; use explicit session revocation to invalidate an existing session.
Step-up/link remain bound to an already admitted account and cannot create users.

Before release, A1-07 must provide those resources, owner-approved tester IDs
and staging Access protection. Scheduled retention for old login requests, rate
buckets when there is no login traffic, revocation metadata and audit/session rows still needs implementation;
webhook delivery cleanup occurs on webhook processing. Account management and
step-up are implemented in A1-05; full export and deletion processing remain A2-08.
See [account management](docs/ACCOUNT_MANAGEMENT.md). A1-04 persists and echoes the RP nonce in migration `0005`.
See [the RP contract](docs/RP_CONTRACT.md) for supported endpoints, RPC methods,
client registration, device binding and remaining integration requirements.

The real Chromium browser check is a required secret-free CI job against the build
artifact. Stryker now mutates auth-core, idp and all accounts Worker executable
source at the unchanged 90% threshold; declaration files alone are excluded.
The complete run at `3d791a6` passed both Stryker's combined gate and the independent
package gates, with native fetch blocked in every test process:

| Mutation scope | Killed | Timed out | Survived | Score |
|---|---:|---:|---:|---:|
| auth-core | 519 | 0 | 30 | 94.54% |
| idp | 193 | 1 | 13 | 93.72% |
| accounts Worker | 1,708 | 2 | 183 | 90.33% |

The three timeouts were inspected: two mutations remove the bodies of bounded
read loops, making them infinite, and one reverses the ULID loop counter. No
unexplained timeout was counted. The run completed in 24 minutes 17 seconds.
All 17 source snapshots in the report match the committed runtime files.
Reports are written to `reports/release-mutation.json` and `.html`. The package
check refuses missing groups, unresolved statuses and scores below 90% without
rounding. It gates each package, not every individual file.

The first expanded baseline was 75.31%; a later 90.42% combined result still had
only 88.85% on the Worker. The additional tests cover idle-refresh races, write
throttling, production defaults, response contracts and webhook persistence.
The interrupted run affected by machine load was discarded. Test files now run
one at a time inside each of four mutation runners, with a 30-second timeout,
to bound nested test-process fan-out.

Confidential HTTPS RPs have authenticated RFC 7662 `/introspect`;
forumbot still needs its bounded positive-cache/write-path integration and fail-closed tests.
A1-05's script-free form documents preserve the exact POST Origin with
`Referrer-Policy: same-origin`; only the login form gets the GitHub CSP allowance.

Tests use the [RFC 7636 appendix B vector](https://www.rfc-editor.org/rfc/rfc7636#appendix-B)
and independent Node crypto signing/verification. JWT validation follows the
algorithm and claim checks described in [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725).

## CI and release controls

The workflow is JSON (a YAML subset) so policy tests parse it without a custom
YAML parser. Verify has no secrets. Build installs only TypeScript and compares
two clean builds byte for byte. Browser runs real Chromium controls on the downloaded artifact before attestation.
The attestation job has no repository checkout
or script execution. Deploy jobs alone receive the Cloudflare token, verify the
artifact provenance against the exact commit/workflow, and use `--no-bundle`.

Before enabling `ACCOUNTS_DEPLOY_ENABLED`, the owner must create the repository,
review A1-07 configuration, set the dedicated account bindings and routes, and
configure protected staging/production environments. Production requires owner
approval. Configure native branch protection with two trusted approving reviews,
Code Owner review, stale-review dismissal and required verify/build/e2e/browser checks.
These server settings cannot be enforced by PR-editable CI alone.

Nothing has been pushed, deployed, or provisioned. The build/deploy lockfiles
and action pins were taken from run commit `dc5accd`; no run files were changed.

Native unit and mutation commands preload `workers/accounts/test/no-network.mjs`.
This makes fallback to a real provider fail even when a mutation removes an
injected fetch. Use `pnpm test`/`pnpm mutation`, or include that `--import` when
running individual Worker test files. Platform tests instead use local workerd
with an explicit synthetic outbound handler.
