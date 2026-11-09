# Relying-party contract (A1-04)

This is a restricted first-party authorization-code profile, following
[OIDC Core's code flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
and [PKCE S256](https://www.rfc-editor.org/rfc/rfc7636#section-4).
It is not a claim of full OIDC conformance. Only `response_type=code`, `scope=openid`,
query responses, S256, ES256 and single string audiences are supported. Implicit,
hybrid, refresh tokens, dynamic registration, request objects, additional scopes
and prompt modes other than `none` are refused. There is no UserInfo endpoint.

## Registration and browser handoff

Register each client in `oauth_clients` through reviewed configuration (A1-07: run is registered by
`clients/staging.sql` and `clients/production.sql`, applied by the matching deploy job, each with only its
own environment's callback). Redirects
must be exact HTTPS strings with no credentials or fragments; no prefix, wildcard,
normalization or subdomain matching. `run` is a binding client with exactly one
registered callback. Confidential clients have a SHA-256 secret hash; provision
an independent random 256-bit secret, never a GitHub secret. No production clients
or secrets are provisioned by these migrations.

The RP starts a flow with independent random state, an OIDC nonce and an S256
verifier. Store the verifier, exact redirect, validated local return path and
SHA-256 of the RP's random pre-auth cookie nonce server-side. The pre-auth cookie
must be host-only, Secure, HttpOnly and Lax, with a ten-minute expiry. Consume that
flow once on callback and verify its browser nonce **before exchanging a code**.
A code/verifier alone does not establish that the callback belongs to this browser.

Send `/authorize` these parameters: `client_id`, `redirect_uri`, `response_type=code`,
`scope=openid`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.
State and optional nonce are nonempty, at most 1024 characters and contain no
whitespace/control characters. All parameters are single-valued. Unknown parameters
are refused. `prompt=none` returns `login_required` to the verified redirect when
there is no active accounts session. Other malformed requests fail locally without
redirecting to caller-controlled destinations.

When sign-in is needed, accounts saves an AES-GCM encrypted continuation, bound to
an independent `__Host-acct_authorize` nonce cookie. Its random `/authorize/resume/`
path fits the existing local-only login return-path rule. It expires in ten minutes,
is consumed once, and revalidates client registration before issuing a code.
No RP state or nonce is stored in plaintext in that continuation. Continuation
creation is rate-limited; each creation prunes at most 100 expired continuations.

Codes are random 256-bit values, stored only as SHA-256 hashes, valid for sixty
seconds. They bind the user, client, exact redirect, S256 challenge, nonce and
originating accounts session. Exchange rechecks that session and the user's active
status, as well as current client registration. One D1 batch consumes the code,
creates the client session and inserts its audit entry. A unique per-attempt
redemption marker prevents two exchanges in the same second from both succeeding.
A failed batch rolls back all three writes. Code issuance also inserts an
`authorization.code_issued` audit row in the same transaction, recording client,
origin session, user and original `auth_at`, without code, nonce or state.
First-party SSO is silent; there is no additional consent page.

## Run binding

Bind the accounts Worker with `entrypoint: "RunEntrypoint"`.
[Named WorkerEntrypoints](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/)
fix the client in code; the default export has no RPC methods. A missing entrypoint
refuses configuration rather than falling back. Dedicated-account isolation remains
required: possession of this binding is a privileged capability, not proof of a
particular caller Worker identity.

`exchangeCode(code, verifier, {redirectUri, deviceRecordId, sharedComputer?})`
returns `{sessionToken, idToken, expiresIn, session}`. Context comes from the trusted
run Worker, never an unchecked browser object. Before setting `__Host-run_sid`, run
must create/check the device row against `session.sub`; on failure it must revoke
the new session and refuse sign-in. Cookie creation is the final success step,
never the default: the A1-06 handoff wrapper must exchange, bind, and only then
construct the Set-Cookie response; its failure branch must revoke the new session.
A1-06 must inject a device-bind failure and assert both revocation and absence of
Set-Cookie. That test belongs to run, whose files are not changed here.
The cross-database device association cannot
be enforced with an identity-D1 foreign key.

The cookie is host-only, Secure, HttpOnly, Path=/ and SameSite=Strict. Normal run
sessions have 12-hour idle and 7-day absolute limits. Shared-computer sessions have
one-hour idle and the same absolute limit; run must omit cookie Max-Age for them.
Do not extend the cookie beyond the returned absolute expiry.

Every user-affecting RPC accepts a session token and derives the user from it:

- `validateSession(token)` returns the session view or null. It reads the primary
  on every invocation; active user, client, revocation, idle and absolute expiry
  are checked. Idle timestamps are updated at most once per five minutes and
  capped at absolute expiry. Do not cache this result across API requests.
- `revokeSession(token)` revokes that session only.
- `revokeAll(token)` revokes this user's **run** sessions only. Global account
  management belongs to the accounts UI in A1-05.
- `listSessions(token)` lists up to 100 newest active run sessions for that user,
  with session IDs and coarse metadata, never bearer hashes or tokens.
- `requestDeletion(token)` requires a server-written `step_up_at` strictly within
  ten minutes and not in the future. Ordinary recent sign-in is insufficient.
  It atomically marks the user deleting, revokes all clients' sessions, queues all
  registered products and audits the request. A1-05 supplies the same-subject
  step-up writer and management UI. An RP session gets this marker only from a
  new code exchange after verification; ordinary sign-in does not set it. Product fan-out/retries/finalization are still future work.

All methods enforce `client=run`; a forum or accounts token cannot be substituted.
The RP must enforce its own CSRF, Origin and browser authorization checks before
invoking RPC mutations. RPC errors contain only static refusal codes, never D1
statements, token bindings or upstream errors. No method accepts a raw user ID or
caller-selected client.

## Confidential HTTPS clients

`POST /token` requires `client_secret_basic`, `application/x-www-form-urlencoded`
and no browser Origin. Encode each Basic credential component as form-url-encoded
before joining with a colon. The body contains exactly `grant_type=authorization_code`,
`code`, `code_verifier` and the registered `redirect_uri`. Cookies are not used for
client authentication. The run binding client cannot use this public endpoint.
The response contains `access_token` (opaque client session), `token_type=Bearer`,
`expires_in`, `id_token` and `scope=openid`. Current confidential session defaults
are 12-hour idle / 7-day absolute.

`POST /introspect` implements the restricted [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)
backchannel with the same Basic authentication, form media type and no-Origin rule.
Send `token=<opaque access_token>` and optionally `token_type_hint=access_token`;
unknown hints are ignored. Unknown/duplicate parameters are refused. Authentication
runs before token lookup; invalid client credentials return 401 `invalid_client`.
Cookie-only and browser callers cannot use this endpoint, and it has no CORS.
Cookies never authenticate a call; a cookie accompanying valid Basic credentials
is ignored. Each authenticated client gets 600 attempts per fixed 60-second window,
shared in primary D1 across isolates. Invalid credentials do not consume another
client's quota. Excess calls return 429 `rate_limited`, `Retry-After: 60`, and no-store.
The counter saturates at 601 and one row per registered client bounds storage;
removing the client cascades its counter. Size/parameter failures also consume quota.

Every call validates the opaque session against primary D1, scoped to the authenticated
client. Revoked, expired, malformed, foreign-client or locked/deleting-user sessions
return exactly `{"active":false}`. Canonical, unknown, foreign and malformed tokens
take the same parameterized primary UPDATE + SELECT path; malformed tokens use a
domain-separated dummy hash and can never return active:true. This avoids an
early-return token lookup shortcut; it does not promise constant database/network latency.
Active responses contain only `active`, `client_id`, `sub`, `iat`, `exp`, `auth_time`,
`sid` and `identities`. Each identity contains only `provider`, provider subject `id`
and display-only `login`, matching the ID token. No identity row id, IP hash, country,
other session or credential is disclosed. `iat` is session issuance time;
`auth_time` is the original authentication time, as in the ID token. `exp` is the earlier
idle/absolute expiry. Validation renews idle expiry at most every five minutes,
without extending absolute expiry. All responses are no-store.

Forumbot must use its configured trusted HTTPS accounts endpoint with redirects refused, require
`active === true` and its expected `client_id`, and fail closed when a fresh check
fails. It may cache only active:true results in its own application state, keyed
by both client and token hash, for at most 60 seconds from the introspection
request's start and never past `exp`. No negative or error result may be cached.
The HTTP response remains no-store; this narrowly scoped application cache is
explicitly authorized by the RP contract, not by intermediary caching headers.
Every request must re-introspect once that cache expires; in particular a post or
edit must not proceed using an expired entry. Timeouts, outages and 429 responses
never extend a cache deadline or permit stale-while-revalidate. An ID token alone
is not a live revocation check. Revocation can therefore remain cached for up to
one minute; an already accepted operation is not cancelled retroactively.

Follow-up under RUN_PLAN §3.6: signed HTTPS logout and deletion notices to RPs
will invalidate their application caches immediately. Notices need signature,
replay, retry and delivery-failure tests; they are not implemented here.
Introspection remains the reliable fallback when a notice is lost. Forumbot's
cache and write-path integration tests belong to that RP and remain outstanding.

## Identity and signing

Key users by `sub` (`usr_<ULID>`); key provider identities by `(provider, id)`.
`identities[].login` is display-only and can change. Never merge by login or email.
ID tokens contain `iss`, string `aud`, `sub`, `iat`, `exp`, `auth_time`, `identities`
and the exact nonce if supplied. They expire after 60 seconds, independent of the
opaque session lifetime. Validate signature, trusted issuer/key source, expected
audience/nonce, lifetime and timestamps. Auth-core requires an explicit clock
allowance (0..60 seconds for iat/nbf only); expiry remains strict.

`ID_TOKEN_PRIVATE_JWK` is the secret P-256 private JWK. The `kid` is derived
automatically as the base64url SHA-256 [RFC 7638 thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
of the required public members in canonical order (`crv`, `kty`, `x`, `y`).
There is no separately configured ID_TOKEN_KID; changing public key material
changes its identifier. Optional JWK metadata does not affect it.
`ID_TOKEN_PREVIOUS_JWKS`, if set, is a JSON array of at most four public EC keys
with distinct public-key thumbprints. An optional supplied `kid` must match the
derived thumbprint; private keys and duplicate thumbprints are refused. `/jwks` publishes only public allowlisted coordinates and
metadata, never `d` or caller-supplied key URLs. Signing configuration is checked
before consuming a code. Rotate by publishing the new public key ahead of issuer
switch-over and retaining previous public keys for at least ten minutes after
the switch (longer than token lifetime, clock allowance and RP cache lifetime).
RPs may refresh only this fixed trusted issuer's JWKS on an unknown kid; no
unverified JWT URL is ever fetched. Responses use no-store and no CORS.

## Production sign-in app and deployment configuration

The owner registered this zero-permission public GitHub App for accounts
(non-secret values, recorded 2026-11-01):

| Setting | Value |
|---|---|
| Name / slug | `Synthetos` / `synthetos` |
| `GITHUB_APP_ID` | `5562809` |
| `GITHUB_CLIENT_ID` | `Iv23liIlkNxE7f3oEyX4` |
| `ACCOUNT_ORIGIN` | `https://accounts.synthetos.com` |
| GitHub callback | `https://accounts.synthetos.com/auth/github/callback` |
| GitHub webhook | `https://accounts.synthetos.com/webhooks/github` |
| Webhook event | `github_app_authorization` (revocations) |

These identify the GitHub-to-accounts sign-in app, not a relying party's
`oauth_clients` registration or client secret. The accounts guard accepts this
app ID and refuses the forum app `5559540`. The owner retains the client secret,
webhook secret and PKCS#8 app private key outside repositories; the current
user-authorization adapter does not require that private key.

A separate staging GitHub App is still pending. Use separate staging credentials
and its configured callback; do not fill staging settings with the production
registration. Cloudflare bindings/routes, owner-approved beta IDs and live
sign-in/revocation verification remain A1-07 setup work. Recording this app does
not enable authentication or authorize deployment.

## Release gates still pending

A1-05 is independently accepted. Accounts provides the Chromium CI gate, D37
admission and confidential-RP introspection. Expanded mutation validation is tracked
in the root README. Remaining integration includes scheduled bounded retention,
product deletion delivery, signed RP notices and forumbot cache/write-path introspection tests.
A1-06 must keep identity outside machine/protocol/safety and never gate stop paths.
Nothing here authorizes pushing, deploying, provisioning or editing the run repo.
