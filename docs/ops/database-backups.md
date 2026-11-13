# Database backups and recovery

Owner decision: 2026-11-13, option C. Cloudflare backs itself up through private
scheduled Workers; no new backup key or nightly GitHub approval is needed.

## Provisioning and nightly operation

Each repository builds its backup Worker into the same twice-built, compared and
attested archive as its application Worker. Its existing deploy jobs provision
resources and deploy the backup Worker with that verified artifact: staging first,
then production with the owner's normal production approval. The application
Workers and their bindings are unchanged. Exact configuration gates refuse extra
bindings, routes, custom domains, workers.dev and preview URLs. The backup Workers
have only a cron handler and a fetch handler returning 404.

| Repo | Production / staging Worker | Source D1 | UTC cron |
| --- | --- | --- | --- |
| accounts | accounts-backup / accounts-backup-staging | identity / identity-staging | 07:45 production / 07:30 staging daily |
| run | run-backup / run-backup-staging | run-auth / run-auth-staging | 07:50 production / 07:35 staging daily |

The source databases are read-only **by code**, using SELECT (including schema
metadata queries). D1 bindings themselves do not enforce read-only access. Scratch
restores receive only the separate SCRATCH binding. Source and scratch IDs must
differ. No source writes are issued by the cron path. Future run-data support adds
one binding/database entry to `workers/backup/src/sources.ts` and regenerates the
reviewed templates. Provisioning, exact gates and the cron consume that same list;
no new credential or separate backup engine is needed.

Accounts provisions `synthetos-db-backups` idempotently during deploy, with no public
r2.dev access or custom domain. Existing public configuration fails closed. It
sets and reads back disjoint 30-day production and 7-day staging lifecycle rules;
it never deletes the bucket. Run verifies privacy before deploying. Deploy accounts
before run's first backup deployment. Existing CI credentials keep their existing
roles: `CLOUDFLARE_API_TOKEN` needs **Workers R2 Storage: Edit** and Worker deployment
permission; `CLOUDFLARE_D1_API_TOKEN` needs **D1: Edit** for scratch provisioning.
Those credentials stay in approved CI jobs and are never installed in the Workers.

The scheduled GitHub backup workflow was removed, including its secret-bearing
exception. There is no on-demand backup endpoint/workflow. Normal nights run under
Cloudflare cron without approval. Manual production **restore** remains a separate
protected workflow requiring approval, described below.

## Dump format, consistency and limits

Keys remain `<repo>/<database>/<YYYY-MM-DD>/<database>-<YYYY-MM-DDTHHMMZ>.sql.gz`,
with `<file>.sql.gz.sha256` beside each archive. Production uses `accounts/identity/`
and `run/run-auth/`; staging prefixes every path with `staging/`. Sidecars contain
`<hex>  <file name>\n`, two spaces, compatible with the unchanged Zeus pull script.
Existing keys are never overwritten, including conditional-put races. Both objects
are read back; their SHA-256 and the restored SQL bytes must match the original.

The dump reads tables, indexes and triggers from sqlite_master, excludes system
objects, and emits table definitions, rows, then indexes/triggers (so restoring
rows cannot replay trigger effects). Text and blobs are encoded as hex, preserving
quotes, newlines and NULs. Integers are converted to text inside SQLite so even
64-bit values never pass through a JavaScript number. Reals keep round-trip precision.
Gzip uses CompressionStream; checksums use crypto.subtle. The pure key, quoting and
checksum validation module and SQL parser are shared with the protected CI restore.

Below a conservative 4 MiB estimated encoded row budget, schema and all table reads
are in one D1 batch/transaction, giving one consistent view. Above that threshold,
reads page by rowid; the log explicitly says `paged-rowid-not-atomic`. Concurrent
writes can then produce a cross-page/cross-table inconsistent snapshot. A rowid-less
or fully shadowed-rowid large table fails closed. Schema changes detected during
planning/paging also fail the run. SQL output is capped at 16 MiB to stay inside
Worker memory; reaching it is a failed backup that needs review, not a truncated
success. Large text/blob restore values are bound rather than embedded in the
D1 statement, keeping statement text below its size limit.

The binding-based dump does not invoke the D1 export API's exclusive export step.
Read batches still consume database capacity and can delay other requests while
they execute. There is no measured production pause duration yet; monitor elapsed
milliseconds and D1 query latency on staging. Cloudflare's current limits include
a 50 MB query-result cap and finite Worker memory/runtime; the lower local budget
is intentional. See [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)
and [query-result limit](https://developers.cloudflare.com/changelog/post/2026-10-30-query-result-size-limit/).

## Monthly recovery proof and failure visibility

On UTC day 1 the cron restores the newest archive it just wrote and verified into
its own environment’s scratch database: production uses `restore-test-<repo>` and
staging uses `restore-test-<repo>-staging`. Each Worker binds only its own scratch. Import,
verification SELECTs and table removal execute in one D1 batch transaction. The
returned counts are compared with the dump afterward. Staging runs 15 minutes before
production; separate scratch databases keep the environments isolated. Empty
application tables are preserved and valid. The same SQL
parser handles this restore and protected CI recovery. Cleanup runs in finally,
including partial imports and count failures. Runner termination or an API outage
can prevent cleanup; verify the next successful monthly cleanup or recover through
an owner-reviewed CI operation. Scratch must not host unrelated data.

Each database emits one structured JSON log with database, object key, byte count,
rows per table, elapsedMs, consistency and restore result. Failure logs report only
the failed stage and throw a sanitized exception so Cloudflare marks the cron run
failed. No SQL, row values or original D1 exception is logged.

In Cloudflare dashboard → Workers & Pages → `accounts-backup` or `run-backup`
(select the staging Worker when applicable), open **Observability / Logs** and filter
scheduled invocations. Check the structured `status`, `restore` and `consistency`
fields, and the failed invocation/error metrics. In the Worker's **Triggers / Cron
Triggers** view confirm the cron is configured and inspect recent runs. An absence
of a successful log for a night is also a backup failure, even if no log was emitted
by a terminated invocation. Observability is enabled with full head sampling on
these dedicated Workers only; normal application logging is unchanged. See
[Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/).

## Owner-approved recovery

Stop application writes before restoring and keep them stopped until sign-in and
record checks pass. First record the current database ID and desired recovery
point. Use Actions → **database-restore** → Run workflow, **main**. This is the
checked-in, byte-pinned, manual-only workflow, not the nightly workflow. Its job
uses the protected **production** environment and the same pinned toolchain.
Type `RESTORE identity` in accounts or `RESTORE run-auth` in run. Review the selected
inputs and approve the production job. Never dispatch with a guess about the
recovery point.

### Recent damage: Time Travel

Choose `mode=time-travel`, the database, and `timestamp=YYYY-MM-DDTHH:MM:SSZ` in UTC;
leave `key` empty. D1 Time Travel retains 30 days on Workers Paid (7 days on Free),
so verify the account plan and available recovery point. The CI command is:

```sh
node tools/backups/restore-cli.mjs
# This validates the protected dispatch and resolves the selected database ID,
# then invokes the pinned executable with a private generated config:
ci/deploy-toolchain/node_modules/.bin/wrangler d1 time-travel restore BACKUP_DB --timestamp "$RESTORE_TIMESTAMP" --config "$RESTORE_CONFIG"
```

`BACKUP_DB` is bound to the selected production database in that generated config;
no checked-in placeholder ID is used. The wrapper suppresses child output.
See [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/).

### Older recovery or a lost database: SQL archive

Choose `mode=sql` and the exact production `.sql.gz` object key; leave timestamp
empty. The wrapper refuses staging, another repository or a path traversal key.
For an archive older than R2 retention, copy the preserved NAS archive **and its
sidecar**, unchanged, back to the same private R2 key through an owner-reviewed
CI recovery step with the existing R2 write credential. The NAS credential cannot
upload. Never attach SQL to an issue, public artifact or workflow log.

The manual checked-in workflow executes `node tools/backups/restore-cli.mjs`. In order it:

1. Downloads the selected archive and sidecar using pinned `wrangler r2 object get
   synthetos-db-backups/<key> --remote --file <private-path> --config <private-config>`.
2. Checks SHA-256, decompresses, checks expected tables, and performs the scratch
   restore/count check described above. An invalid archive never reaches production.
3. Resolves the production database by name, creating it only if it was lost. If
   it still has tables, exports and verifies a fresh safety backup first. If that
   current database is too damaged to export, this path fails closed: use Time
   Travel or a separately reviewed incident recovery change rather than bypassing
   the safety backup silently.
4. Empties the selected production database and invokes pinned
   `wrangler d1 execute BACKUP_DB --remote --yes --file <verified-sql> --config
   <private-config>`, then verifies every table count against the archive.

A failed production import can leave partial data. Keep writes stopped and retry
only after assessing the failure; the source archive and safety backup remain.
The Worker dump includes and restores `d1_migrations`, preserving the migration
ledger. The normal CI migration step therefore applies only newer migrations after
a restore. Only `sqlite_*` and `_cf_*` system objects are excluded.

If the database was recreated, its ID changed: run the existing CI provisioning
and deployment path to update bindings and redeploy. Do not reopen traffic while
bindings still point at the lost ID. Check sign-in and application behavior after
either recovery path. Production restoration is never scheduled automatically.

## Zeus cold storage

The installed script is committed verbatim in run at
`tools/backups/zeus-db-pull.sh`. Zeus (`192.168.1.221`) pulls nightly at **03:30
America/New_York** into `/mnt/storage/coldstorage/synthetos-db/`, preserving bucket
paths and skipping `staging/`. It never deletes or overwrites cold copies.
The log is `/mnt/storage/coldstorage/synthetos-db/pull.log`; rclone errors go to
`rclone-errors.log` beside it. No installation or schedule changes are needed.

The owner creates an R2 API token with **Object Read only**, **Apply to specific
buckets only**, selecting only `synthetos-db-backups`. Write its credentials as an
rclone config on zeus at `~/.config/synthetos-db-backups/rclone.conf` with remote
name **r2**, type `s3`, provider **Cloudflare**, region `auto`, and the endpoint from
R2. Keep the config private (mode 600); never commit or print its keys. This is an
S3 credential, not the CI Cloudflare REST token. See
[R2 token permissions](https://developers.cloudflare.com/r2/api/tokens/).

Until that config exists, the installed script logs “not configured” and exits
successfully. Once configured, it copies new objects, verifies each new archive
and records verified paths in `.verified`. Already verified files are retained
without rechecking on every pull. An overlapping pull is skipped under a lock.
Missing checksums or mismatches fail the pull; monitor its exit status and log.

Backups write each checksum as `<hex>  <file name>` (two spaces, terminating
newline) in `<file>.sql.gz.sha256` next to `<file>.sql.gz`, matching the installed
script. Bucket name and staging prefix remain unchanged. R2 expiry never deletes
the cold copy. An interrupted two-object upload may need a later pull once its
checksum arrives; investigate mismatches rather than replacing a cold copy.
Minute-granularity archive keys refuse same-minute retries rather than overwriting
an earlier archive; wait for the prior job to finish and the minute to change.
