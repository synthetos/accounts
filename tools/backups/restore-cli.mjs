import { mkdtemp, rm, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { cloudflare, assertPrivate } from './api.mjs';
import { remote } from './remote.mjs';
import { restoreRequest, restoreProduction } from './restore.mjs';
import { REPO, DATABASES } from './config.mjs';
async function run() {
  const request = restoreRequest(process.env, REPO, DATABASES);
  if (!process.env.RUNNER_TEMP || !process.env.GITHUB_STEP_SUMMARY) throw new Error('Missing CI paths');
  process.umask(0o077);
  const directory = await mkdtemp(join(process.env.RUNNER_TEMP, 'database-restore-'));
  const summary = text => appendFile(process.env.GITHUB_STEP_SUMMARY, `${text}\n`);
  try {
    const account = process.env.CLOUDFLARE_ACCOUNT_ID;
    const r2Token = process.env.CLOUDFLARE_API_TOKEN, d1Token = process.env.CLOUDFLARE_D1_API_TOKEN;
    await assertPrivate(cloudflare(account, r2Token, 'CLOUDFLARE_API_TOKEN: Workers R2 Storage: Edit'));
    const api = cloudflare(account, d1Token, 'CLOUDFLARE_D1_API_TOKEN: D1: Edit');
    await summary(`Starting owner-approved ${request.mode} restore of ${request.schema.name}.`);
    await restoreProduction(remote({ api, account, d1Token, r2Token, directory }), REPO, request);
    await summary(`PASS: ${request.schema.name} restore completed. Check sign-in and bindings before reopening traffic.`);
  } catch {
    await summary('FAILED: manual restore. Keep traffic stopped; inspect recovery state before retrying. Database contents and child output are suppressed.');
    process.exitCode = 1;
  } finally { await rm(directory, { recursive: true, force: true }); }
}
run().catch(() => { process.stderr.write('Restore CI setup refused.\n'); process.exitCode = 1; });
