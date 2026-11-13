import { SOURCES } from '../../workers/backup/src/sources.ts';
import { REPO } from './config.mjs';
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
export function workerConfig(environment, source, scratch, account) {
  if (!['staging', 'production'].includes(environment)) throw new Error('Invalid backup environment');
  const sourceIds = typeof source === 'string' ? { SOURCE: source } : source;
  for (const id of [...SOURCES.map(s => sourceIds[s.binding]), scratch]) if (!UUID.test(id) && id !== 'SOURCE_DATABASE_ID' && id !== 'SCRATCH_DATABASE_ID') throw new Error('Invalid D1 binding id');
  if (account !== undefined && !/^[0-9a-f]{32}$/.test(account)) throw new Error('Invalid account');
  if (SOURCES.some(s => sourceIds[s.binding] === scratch)) throw new Error('Source and scratch must differ');
  const suffix = environment === 'staging' ? '-staging' : '';
  return {
    name: `${REPO}-backup${suffix}`, main: REPO === 'run' ? 'index.mjs' : 'workers/backup/src/index.js', compatibility_date: '2026-10-01',
    ...(account === undefined ? {} : { account_id: account }), workers_dev: false, preview_urls: false, routes: [],
    observability: { enabled: true, head_sampling_rate: 1 }, triggers: { crons: [REPO === 'accounts' ? '45 7 * * *' : '50 7 * * *'] },
    vars: { BACKUP_ENV: environment },
    d1_databases: [...SOURCES.map(s => ({ binding: s.binding, database_name: s.database + suffix, database_id: sourceIds[s.binding] })), { binding: 'SCRATCH', database_name: `restore-test-${REPO}`, database_id: scratch }],
    r2_buckets: [{ binding: 'BACKUPS', bucket_name: 'synthetos-db-backups' }],
    find_additional_modules: true, rules: [{ type: 'ESModule', globs: [REPO === 'run' ? '**/*.mjs' : '**/*.js'] }],
  };
}
function ordered(value) { return Array.isArray(value) ? value.map(ordered) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, ordered(value[k])])) : value; }
export function checkBackupConfig(config, environment) {
  try {
    if (environment !== undefined && config.vars.BACKUP_ENV !== environment) return false;
    const ids = Object.fromEntries(config.d1_databases.filter(d => d.binding !== 'SCRATCH').map(d => [d.binding, d.database_id]));
    const expected = workerConfig(config.vars.BACKUP_ENV, ids, config.d1_databases.find(d => d.binding === 'SCRATCH').database_id, config.account_id);
    return JSON.stringify(ordered(config)) === JSON.stringify(ordered(expected));
  } catch { return false; }
}
