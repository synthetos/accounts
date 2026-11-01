# Identity migrations

Apply the numbered SQL files through Wrangler's migration ledger, in order.
`0001` creates the eight RUN_PLAN §4.1 tables; `0002` adds indexes without
changing existing data or application queries. `0003` replaces only the audit
delete guard and adds retention indexes; existing records are preserved.

Local D1 validation (no Cloudflare credentials or deployed database needed):

```sh
corepack pnpm --dir ci/deploy-toolchain install --frozen-lockfile --ignore-scripts
corepack pnpm test:d1
```

`wrangler.local.json` has an intentionally synthetic database id, and the test
passes `--local` on every call with a temporary persistence directory. The
fixture is test-only and must never be included in production migrations.

Timestamp fields are integer Unix seconds. Token/code/state hashes use lowercase
SHA-256 hex. PKCE challenge and encrypted verifier fields are distinct. Session
and code validation, exact redirect URI checks, JSON-array entry validation,
PKCE verification, encryption of verifiers and provider-specific TTL policies
belong to A1-03/A1-04; constraints alone do not authenticate anyone.

Authorization codes and requests must be consumed with a conditional UPDATE
that checks unused state and expiry atomically; the tests demonstrate the shape,
including browser nonce binding. Do not use a read-then-write sequence.

Audit rows deliberately have no cascading user/session foreign keys. They
remain after account deletion with a pseudonymous `usr_<ULID>` reference.
The launch privacy text must disclose that security audit records survive account
deletion until their retention period expires; this is not anonymous data.
UPDATE is always blocked. DELETE is allowed only for rows older than 365 days,
using the database clock; the exact 365-day boundary remains protected.
The required bounded retention job is future work: prune with `at < now - 31536000`
using `security_audit_by_time`. No request handler may disable the guards.
There is currently no application mutation or pruning path, so this migration
enables the policy but does not schedule automatic deletion.

Account finalization must confirm every product deletion, remove completed
deletion-job rows, then remove the user. The restrictive FK intentionally prevents
deletion while any job remains, including completed jobs awaiting cleanup.
The finalizer must enforce completion; the FK alone does not check job status.

Session retention is 30 days after effective expiry. Since idle expiry is always
at or before absolute expiry, the pruning query can use `idle_expires_at < cutoff`
with `sessions_by_idle_expiry`; `sessions_by_expiry` remains for absolute expiry.
Retention jobs and their scheduling are not implemented by A1-02.

A1-04 must add a nullable RP OIDC `nonce` column in a forward migration before
issuing ID tokens from authorization-code exchange. Preserve and echo the RP's
nonce exactly; a stored hash alone cannot supply that claim. This is distinct
from the pre-auth browser cookie binding in `auth_requests.browser_nonce_hash`.
A1-03 must request no email scope, discard any email returned in GitHub's profile,
and test that sign-in leaves `identities.email IS NULL` and `email_verified = 0`.
Those endpoint tests require the future sign-in implementation.

Future schema changes use expand/contract: add nullable columns or compatible
tables first; deploy readers/writers; backfill with a reviewed job; remove old
fields only after the compatibility window and a separate review. Never edit a
numbered migration after it has been applied. Use a new forward migration.

Production D1 resources, environment bindings, migration application and
deployment remain part of A1-07. No resources have been created by this task.
