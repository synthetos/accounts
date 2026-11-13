import { mkdtemp, rm, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { cloudflare, assertPrivate } from './api.mjs';
import { provisionBucket } from './bucket.mjs';
import { remote } from './remote.mjs';
import { backupDatabase } from './backup.mjs';
import { REPO, DATABASES } from './config.mjs';
export function requireCI(env) {
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REF !== 'refs/heads/main' || !['schedule', 'workflow_dispatch'].includes(env.GITHUB_EVENT_NAME)) throw new Error('Backups run only in the approved main-branch CI workflow');
  if (!['production', 'staging'].includes(env.BACKUP_ENV) || !env.RUNNER_TEMP || !env.GITHUB_STEP_SUMMARY) throw new Error('Missing CI backup scope');
}
export async function run(env = process.env) {
  requireCI(env);
  process.umask(0o077);
  const directory = await mkdtemp(join(env.RUNNER_TEMP, 'database-backup-'));
  const summary = text => appendFile(env.GITHUB_STEP_SUMMARY, `${text}\n`);
  try {
    const account = env.CLOUDFLARE_ACCOUNT_ID ?? '';
    const r2 = cloudflare(account, env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN: Workers R2 Storage: Edit');
    if (REPO === 'accounts') await provisionBucket(r2);
    else await assertPrivate(r2);
    const api = cloudflare(account, env.CLOUDFLARE_D1_API_TOKEN, 'CLOUDFLARE_D1_API_TOKEN: D1: Edit');
    const io = remote({ api, account, d1Token: env.CLOUDFLARE_D1_API_TOKEN, r2Token: env.CLOUDFLARE_API_TOKEN, directory });
    const now = new Date();
    const monthly = now.getUTCDate() === 1 || env.RESTORE_TEST === 'true';
    for (const schema of DATABASES) {
      const name = env.BACKUP_ENV === 'staging' ? schema.staging : schema.name;
      await summary(`Starting ${REPO}/${name}: export, gzip, upload and read-back${monthly ? ', scratch restore and cleanup' : ''}.`);
      const key = await backupDatabase(io, { repo: REPO, environment: env.BACKUP_ENV, schema, now, monthly, onExport: elapsed => summary(`Export command elapsed: ${elapsed} ms (includes tool startup and download).`) });
      await summary(`PASS: ${key}${monthly ? ' — restore verified and scratch emptied' : ''}.`);
    }
  } catch {
    await summary('FAILED: database backup or restore verification. No database contents or child output are logged. Check the environment tokens (D1: Edit; Workers R2 Storage: Edit), provisioning and the last stage above.');
    process.exitCode = 1;
  } finally { await rm(directory, { recursive: true, force: true }); }
}
if (process.argv[1]?.endsWith('/backups/cli.mjs')) {
  run().catch(() => { process.stderr.write('Backup CI setup failed.\n'); process.exitCode = 1; });
}
