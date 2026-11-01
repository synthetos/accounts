# Account management (A1-05)

`GET /account` (also `/`) renders the profile, linked identities and up to 100
newest active sessions across all products. It contains no script. Display values
are HTML-escaped. Session rows show product, creation/last-use time, coarse
browser/OS and country; raw user agents and IP addresses are not retained.

Every account form uses a synchronizer token bound to the accounts session ID,
action (including its target ID) and expiry. POST requires a valid accounts
session, exact HTTPS Origin, same-origin Sec-Fetch-Site when present and form
content type. Missing/duplicate fields, JSON bodies and cross-action tokens fail.
Mutations recheck user ownership and active session state in their D1 transaction;
a valid CSRF token is not a substitute for authorization.

## Session controls

- `/account/sessions/revoke` signs out one owned session, including another product.
- `/account/sessions/revoke-all` signs out every session owned by this account.

Both actions are audited. Only the accounts cookie is cleared when the current
session is revoked; no Clear-Site-Data header is emitted. Session validation in
products must use primary-backed checks. These operations do not send commands
to a machine or cancel an accepted operation; the never-gated stop/recovery paths
remain available under the machine safety rules.

## Step-up and linking

`POST /account/step-up` starts a ten-minute flow bound to both the existing
accounts session and an independent `__Host-acct_manage` nonce cookie. State and
nonce are stored hashed. The PKCE verifier is AES-GCM sealed with origin,
purpose, session ID and both hashes as authenticated data. The existing registered
GitHub callback dispatches using server-stored state, not a caller-selected user
or purpose. It consumes the flow once, verifies the current session/cookie, and
uses S256 plus `prompt=select_account` for the provider round trip.

[GitHub's account picker](https://github.blog/changelog/2024-06-07-account-picker-updates-for-oauth-and-github-app-sign-in/)
selects an account; it is not a promise of a fresh password or MFA challenge.
The returned numeric subject must match an identity already linked to this user.
Success audits the verification and sets `step_up_at`. A mismatch audits the
failure, revokes the originating session, clears its cookie and never creates a
new user or identity. Revocation and expiry are checked again after the network
round trip. Cancelling does not grant verification. Step-up validity is strictly
less than ten minutes, and a new verification attempt clears the old marker.

Account form HTML uses `Referrer-Policy: same-origin` and self-only form-action.
A verification/link POST returns a script-free page with an explicit “Continue
to GitHub” hyperlink; that response has no-referrer and self-only form-action.
This avoids a form redirect chain to GitHub without relaxing the account page's
CSP. Only login form HTML permits GitHub in form-action. Chromium tests exercise
the actual account POST/link and a no-referrer negative control with external
network blocked.

After step-up, `/account/identities/link` starts a second provider flow for the
new identity. Only the GitHub adapter is available now; Google is future work.
The callback requires the same active accounts session and still-fresh step-up.
It refuses identities owned by another user and audits that refusal. There are
no silent merges and no email-based linking. GitHub email remains discarded.

`/account/identities/unlink` requires fresh step-up and refuses the last identity,
including concurrent attempts. It revokes sessions authenticated through that
identity before removing it. New sessions record `sign_in_identity_id`, which
also propagates through code exchange. Legacy sessions with unknown provenance
are conservatively revoked on any unlink. All these writes share one D1 batch.

## Export and deletion boundary

The full export ZIP/R2 pipeline, deletion grace/cancel flow, product fan-out,
retry/finalization and tombstones are **A2-08**, not implemented here. The account
page explicitly says these features are unavailable and their buttons are disabled.
`POST /account/export` and `/account/delete` nevertheless enforce the complete
session/form/step-up gate; only then do they return 501 without mutating data.
A2-08 must replace that final refusal with the complete reviewed workflow.
The existing RPC deletion admission queues product jobs; it must not be wired to
an incomplete public deletion UX. Security audits survive deletion for one year;
GitHub posts remain on GitHub.

## Remaining release gates

A1-06 still owns run's device-bind-before-cookie handoff and AuthGate integration.
Before A1-07: browser regression in CI, idp/Worker mutation scope at the unchanged
90% threshold, D37 allowlist, scheduled retention and required product revocation
integration. No production resource, GitHub App, secret or deployment is created
by this implementation.
