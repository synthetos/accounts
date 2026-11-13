// Only the pinned deploy toolchain runs with credentials. No child output is forwarded: SQL may be in errors.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { BUCKET, databaseId } from './api.mjs';
const exec = promisify(execFile);
export function remote({ api, account, d1Token, r2Token, directory, runner = exec, fetcher = fetch }) {
  const wrangler = resolve('ci/deploy-toolchain/node_modules/.bin/wrangler');
  const config = join(directory, 'wrangler.json');
  const command = async (args, token, database) => {
    await writeFile(config, JSON.stringify({ name: 'database-backup', compatibility_date: '2026-11-13', ...(database === undefined ? {} : { d1_databases: [{ binding: 'BACKUP_DB', database_name: database.name, database_id: database.id }] }) }), { mode: 0o600 });
    try {
      await runner(wrangler, [...args, '--config', config], { cwd: directory, timeout: 300_000, maxBuffer: 1024 * 1024, env: {
        PATH: process.env.PATH, HOME: process.env.HOME, XDG_CONFIG_HOME: directory, CI: 'true', WRANGLER_SEND_METRICS: 'false',
        CLOUDFLARE_ACCOUNT_ID: account, CLOUDFLARE_API_TOKEN: token,
      } });
    } catch { throw new Error('Pinned Wrangler command failed; child output suppressed to protect database contents'); }
  };
  return {
    exists: async key => {
      const response = await fetcher(`https://api.cloudflare.com/client/v4/accounts/${account}/r2/buckets/${BUCKET}/objects/${encodeURIComponent(key)}`, {
        headers: { authorization: `Bearer ${r2Token}` }, redirect: 'error', signal: AbortSignal.timeout(30_000),
      });
      await response.body?.cancel();
      if (response.status === 404) return false;
      if (!response.ok) throw new Error('Cannot check existing backup object');
      return true;
    },
    database: async (name, create = false) => ({ name, id: await databaseId(api, name, create) }),
    export: async database => {
      const path = join(directory, 'export.sql');
      await command(['d1', 'export', 'BACKUP_DB', '--remote', '--output', path], d1Token, database);
      return readFile(path);
    },
    import: async (database, sql) => {
      const path = join(directory, 'import.sql');
      await writeFile(path, sql, { mode: 0o600 });
      await command(['d1', 'execute', 'BACKUP_DB', '--remote', '--yes', '--file', path], d1Token, database);
    },
    query: async (database, sql) => {
      const response = await api(`d1/database/${database.id}/query`, 'POST', { sql });
      if (!Array.isArray(response.result) || response.result.some(r => r.success !== true || !Array.isArray(r.results))) throw new Error('Database verification query failed');
      return response.result.flatMap(r => r.results);
    },
    put: async (key, bytes) => {
      const path = join(directory, 'upload');
      await writeFile(path, bytes, { mode: 0o600 });
      await command(['r2', 'object', 'put', `${BUCKET}/${key}`, '--remote', '--file', path], r2Token);
    },
    get: async key => {
      const path = join(directory, 'download');
      await command(['r2', 'object', 'get', `${BUCKET}/${key}`, '--remote', '--file', path], r2Token);
      return readFile(path);
    },
    timeTravel: async (database, timestamp) => command(['d1', 'time-travel', 'restore', 'BACKUP_DB', '--timestamp', timestamp], d1Token, database),
  };
}
