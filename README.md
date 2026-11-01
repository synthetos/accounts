# Synthetos Accounts

Foundations for accounts.synthetos.com, following RUN_PLAN §3 and Track A1.
The Worker is deliberately a 503 shell. No authentication endpoint is live.

## Current validation status

A1-01 and A1-02 implementation and local acceptance checks pass:

- Frozen clean installation with lifecycle scripts disabled.
- TypeScript, ESLint, dependency-cruiser and dependency licences.
- 47 unit/schema/policy tests, including independent crypto vectors and audit retention boundaries.
- Stryker: **94.54%**, 519 killed / 549 total, 30 survivors, no timeouts or errors;
  threshold remains 90%. Every mutated source file scores above 90%.
- Local Wrangler D1: migration application, repeated application, fixture seed,
  provider/subject uniqueness rejection and audit retention guards.
- Two clean source-copy builds produce identical bytes; the separate build
  toolchain installs only TypeScript, and the built Worker passes its smoke check.

The initial sandbox restrictions were removed before the mutation and D1 runs.
The A1-01, A1-02 and licence-gate collaborator reviews have been addressed; confirmation of
the fixes remains pending. No hosted CI run, push, resource provisioning
or deployment has been performed. These are foundations, not a
production-ready identity service.

## Layout

- `packages/auth-core`: no runtime dependencies; WebCrypto, Fetch request objects
  and cookie serialization. No network calls or persistence.
- `workers/accounts`: service shell; session and provider routes come in A1-03+.
- `migrations`: expand-only identity schema and indexes, with synthetic test fixtures.
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
