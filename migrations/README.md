# Identity migrations

Apply the numbered SQL files through Wrangler's migration ledger, in order.
`0001` creates the eight RUN_PLAN §4.1 tables; `0002` adds indexes without
changing existing data or application queries. Both are expand-only.

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
remain after account deletion. UPDATE and DELETE are blocked by triggers;
there is no application mutation or pruning path. The required one-year
retention job is future work and needs a separately reviewed, bounded
maintenance migration that manages those triggers. Do not disable them in
request handlers. Account finalization must remove completed deletion-job
rows before removing the user; outstanding jobs prevent premature deletion.

Future schema changes use expand/contract: add nullable columns or compatible
tables first; deploy readers/writers; backfill with a reviewed job; remove old
fields only after the compatibility window and a separate review. Never edit a
numbered migration after it has been applied. Use a new forward migration.

Production D1 resources, environment bindings, migration application and
deployment remain part of A1-07. No resources have been created by this task.
