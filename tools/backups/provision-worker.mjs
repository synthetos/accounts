import { SOURCES } from '../../workers/backup/src/sources.ts';
import { readFile, writeFile } from 'node:fs/promises';
import { cloudflare, databaseId, assertPrivate } from './api.mjs';
import { provisionBucket } from './bucket.mjs';
import { workerConfig, checkBackupConfig } from './worker-config.mjs';
import { REPO } from './config.mjs';
export async function provisionWorker(environment, account, d1, r2) {
  const template = workerConfig(environment, Object.fromEntries(SOURCES.map(s => [s.binding, 'SOURCE_DATABASE_ID'])), 'SCRATCH_DATABASE_ID');
  if (REPO === 'accounts') await provisionBucket(r2); else await assertPrivate(r2);
  const ids = {};
  for (const binding of template.d1_databases.filter(d => d.binding !== 'SCRATCH')) ids[binding.binding] = await databaseId(d1, binding.database_name);
  const scratchName = template.d1_databases.find(d => d.binding === 'SCRATCH').database_name;
  const scratch = await databaseId(d1, scratchName, true);
  return workerConfig(environment, ids, scratch, account);
}
async function main() {
  const environment = process.argv[2];
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_REF !== 'refs/heads/main' || process.env.GITHUB_EVENT_NAME !== 'push') throw new Error('Backup provisioning requires the gated main deploy');
  if (!['production', 'staging'].includes(environment)) throw new Error('Invalid deployment scope');
  const reviewed = JSON.parse(await readFile(`workers/backup/wrangler.${environment}.json`, 'utf8'));
  if (!checkBackupConfig(reviewed) || reviewed.vars.BACKUP_ENV !== environment) throw new Error('Unreviewed backup Worker configuration');
  const account = process.env.CLOUDFLARE_ACCOUNT_ID;
  const d1 = cloudflare(account, process.env.CLOUDFLARE_D1_API_TOKEN, 'CLOUDFLARE_D1_API_TOKEN: D1: Edit');
  const r2 = cloudflare(account, process.env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN: Workers R2 Storage: Edit');
  const config = await provisionWorker(environment, account, d1, r2);
  await writeFile(REPO === 'run' ? 'workers/backup/wrangler.deploy.json' : 'payload/backup-wrangler.json', JSON.stringify(config, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write('Private backup resources and exact deployment bindings ready.\n');
}
if (process.argv[1]?.endsWith('/backups/provision-worker.mjs')) main().catch(() => { process.stderr.write('Backup provisioning failed; check existing D1/R2 token permissions and reviewed resources.\n'); process.exitCode = 1; });
