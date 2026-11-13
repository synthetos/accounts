# Database backups and recovery

Owner decision: 2026-11-13. Nothing here requires a local Wrangler command.
The workflows must be merged to main before they can run. Production environment
reviewers approve production jobs; dispatching a workflow is not production approval.

## Storage and nightly operation

`database-backups.yml` runs nightly (accounts 07:15 UTC, run 07:45 UTC) and by
manual dispatch. Dispatch staging first with `restore_test=true`, approve its
protected environment, and inspect the summary. Then dispatch production and
approve that environment. Scheduled runs back up both environments; production
waits for the staging job to finish. A failed staging job does not suppress the
production backup. GitHub schedules may be delayed; use the summary timestamp.

Accounts owns idempotent provisioning of the private `synthetos-db-backups` R2
bucket. Run expects that bucket to exist. No public r2.dev access or custom domains
are allowed: an unexpected public setting fails closed. CI creates the bucket,
sets retention, and reads it back; it never deletes the bucket. Run accounts'
staging backup once before run's first backup. Existing environment credentials:
`CLOUDFLARE_API_TOKEN` needs **Workers R2 Storage: Edit** and
`CLOUDFLARE_D1_API_TOKEN` needs **D1: Edit**, with `CLOUDFLARE_ACCOUNT_ID` as a
variable. No additional CI key is generated or printed.

Production keys are `<repo>/<database>/<YYYY-MM-DD>/<database>-<YYYY-MM-DDTHHMMZ>.sql.gz`
and the same name plus `.sha256`. `accounts/identity/` and `run/run-auth/` expire
after 30 days. Staging uses `staging/accounts/identity-staging/` and
`staging/run/run-auth-staging/`, expiring after 7 days. Rules have disjoint prefixes.
Each workflow owns only its repository's databases. Add a future production
run-data database by adding one schema entry to `tools/backups/config.mjs` after
provisioning it; list all expected tables and any tables that must contain rows.
Do not add it before production resources exist.

The pinned deploy toolchain (Wrangler 4.149.0, frozen lockfile, scripts disabled)
exports SQL, gzip-compresses it and computes SHA-256. Both objects are downloaded
again; the checksum and exact SQL bytes must match. Empty or invalid exports fail.
Temporary SQL and credentials are never uploaded as Actions artifacts or printed.
Child command output is suppressed because an SQL error could contain private rows.
The job summary reports success/failure and the object key, not contents.

D1 export blocks other database requests for the duration of the export, including
writes. Cloudflare supplies no fixed duration guarantee. These small databases
should finish quickly at the quiet hour, but **there is no measured production
pause duration yet**. The summary records export-command elapsed milliseconds, including tool startup
and download. Measure it on staging before relying on a latency estimate. A command times out after five
minutes rather than waiting indefinitely. See [D1 import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/).

## Monthly proof of recovery

On UTC day 1 (or `restore_test=true`), the job restores the new backup it has just
uploaded and read back: the newest backup produced by that run. It creates
`restore-test-accounts` or `restore-test-run` only if absent. It compares every
exported application table and its exact row count with the scratch database.
`oauth_clients` must contain rows; session/rate-limit and new-user tables can
legitimately be empty. The source database is never the scratch target.

Scratch tables are emptied before import and in a `finally` block after success
or a partial/failed import. A failed verification or cleanup fails the workflow.
A runner termination or Cloudflare outage can prevent cleanup: rerun a protected
restore-test job when service returns, and verify its successful cleanup summary.
Do not use scratch databases for anything else. They may temporarily hold private
production data and have the same restricted account access as production D1.

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

The checked-in workflow executes `node tools/backups/restore-cli.mjs`. In order it:

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
If the database was recreated, its ID changed: run the existing CI provisioning
and deployment path to update bindings and redeploy. Do not reopen traffic while
bindings still point at the lost ID. Check sign-in and application behavior after
either recovery path. Production restoration is never scheduled automatically.

## NAS cold storage (run repository script)

Install `tools/backups/nas-pull.sh` from run on the Unraid NAS. Install rclone via
the Unraid plugin, or provide a local `rclone` wrapper invoking a pinned container
with the config and destination paths mounted at the same paths. Also provide
`sha256sum`, POSIX sh, awk and find. Schedule the script after nightly backups:

```sh
sh /boot/config/custom/nas-pull.sh /boot/config/custom/synthetos-backups-rclone.conf
```

The owner creates one R2 API token: **Object Read only**, **Apply to specific
buckets only**, selecting only `synthetos-db-backups`. This is an S3 credential,
not a Cloudflare REST API token. We never create keys. Put its Access Key ID and
Secret Access Key in the private rclone config on the NAS (mode 600, directory
accessible only to the owner), remote name `synthetos-backups`, type `s3`, provider
`Cloudflare`, region `auto`, endpoint copied from the R2 token page. Do not put the
config in git, shell history, logs or this runbook. See [R2 token permissions](https://developers.cloudflare.com/r2/api/tokens/).

The script copies only `accounts/` and `run/` to
`/mnt/user/mybackups/synthetos-db/`, preserving paths. It verifies every archive
against its sidecar, rejects malformed or missing pairs, and appends one timestamp
and OK/FAILED line to `pull.log`. It never syncs, deletes or overwrites NAS archives.
If R2 expires an object, the NAS copy remains indefinitely. A failure exits nonzero;
alert on that status in the NAS scheduler. An interrupted two-object upload can
cause a missing-pair failure; rerun after the CI upload finishes. A checksum mismatch
requires investigation, not automatic replacement of the old cold-storage copy.
Minute-granularity archive keys mean dispatches within the same minute must be
refused rather than overwriting an archive; wait for the prior job to finish and the minute to change before rerunning.
