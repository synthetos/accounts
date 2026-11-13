import { SOURCES } from '../../workers/backup/src/sources.ts';
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { cloudflare, databaseId, assertPrivate } from './api.mjs';
import { provisionBucket } from './bucket.mjs';
import { workerConfig, checkBackupConfig } from './worker-config.mjs';
import { REPO } from './config.mjs';
export async function provisionWorker(environment, account, d1, r2, lookup = d1 ?? r2) {
  const template = workerConfig(environment, Object.fromEntries(SOURCES.map(s => [s.binding, 'SOURCE_DATABASE_ID'])), 'SCRATCH_DATABASE_ID');
  const ids = {};
  for (const binding of template.d1_databases.filter(d => d.binding !== 'SCRATCH')) ids[binding.binding] = await databaseId(lookup, binding.database_name, false, true);
  if (Object.values(ids).every(id => id === null)) return null;
  if (!d1) throw new Error('Missing credential: CLOUDFLARE_D1_API_TOKEN: D1: Edit');
  if (Object.values(ids).some(id => id === null)) throw new Error('Some backup source databases are missing');
  if (REPO === 'accounts') await provisionBucket(r2); else await assertPrivate(r2);
  const scratchName = template.d1_databases.find(d => d.binding === 'SCRATCH').database_name;
  const scratch = await databaseId(d1, scratchName, true);
  return workerConfig(environment, ids, scratch, account);
}
export async function runProvision(environment, env = process.env, fetcher = fetch) {
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REF !== 'refs/heads/main' || env.GITHUB_EVENT_NAME !== 'push') throw new Error('Backup provisioning requires the gated main deploy');
  if (!['production', 'staging'].includes(environment)) throw new Error('Invalid deployment scope');
  const reviewed = JSON.parse(await readFile(new URL(`../../workers/backup/wrangler.${environment}.json`, import.meta.url), 'utf8'));
  if (!checkBackupConfig(reviewed) || reviewed.vars.BACKUP_ENV !== environment) throw new Error('Unreviewed backup Worker configuration');
  const account = env.CLOUDFLARE_ACCOUNT_ID;
  const d1 = env.CLOUDFLARE_D1_API_TOKEN ? cloudflare(account, env.CLOUDFLARE_D1_API_TOKEN, 'CLOUDFLARE_D1_API_TOKEN: D1: Edit', fetcher) : null;
  const r2 = cloudflare(account, env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN: Workers R2 Storage: Edit', fetcher);
  const lookup = d1 ?? cloudflare(account, env.CLOUDFLARE_API_TOKEN, 'CLOUDFLARE_API_TOKEN: D1: Read', fetcher);
  const config = await provisionWorker(environment, account, d1, r2, lookup);
  if (config === null) {
    const names = SOURCES.map(s => s.database + (environment === 'staging' ? '-staging' : '')).join(', ');
    const message = `Backups not deployed yet: ${names} does not exist in ${environment}. They start after the database is created.`;
    await appendFile(env.GITHUB_OUTPUT, 'ready=false\n');
    await appendFile(env.GITHUB_STEP_SUMMARY, message + '\n');
    process.stdout.write(message + '\n');
    return;
  }
  await writeFile(REPO === 'run' ? 'workers/backup/wrangler.deploy.json' : 'payload/backup-wrangler.json', JSON.stringify(config, null, 2) + '\n', { flag: 'wx' });
  await appendFile(env.GITHUB_OUTPUT, 'ready=true\n');
  process.stdout.write('Private backup resources and exact deployment bindings ready.\n');
}
if (process.argv[1]?.endsWith('/backups/provision-worker.mjs')) runProvision(process.argv[2]).catch(error => { process.stderr.write((/^(Missing credential:|Credential requires)/.test(error.message) ? error.message : 'Backup provisioning failed; check existing D1/R2 token permissions and reviewed resources.') + '\n'); process.exitCode = 1; });
