// Manual, owner-approved production recovery only. No scheduled caller imports this module.
import { expectedCounts, checkRestored } from './archive.mjs';
import { downloadVerified, restoreCheck, emptyDatabase, backupDatabase } from './backup.mjs';
export function restoreRequest(env, repo, schemas) {
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REF !== 'refs/heads/main' || env.GITHUB_EVENT_NAME !== 'workflow_dispatch' || env.BACKUP_ENV !== 'production') throw new Error('Restore requires the protected manual production workflow on main');
  const schema = schemas.find(item => item.name === env.RESTORE_DATABASE);
  if (!schema || env.RESTORE_CONFIRM !== `RESTORE ${schema.name}`) throw new Error('Explicit database confirmation required');
  if (env.RESTORE_MODE === 'time-travel') {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(env.RESTORE_TIMESTAMP ?? '') || !Number.isFinite(Date.parse(env.RESTORE_TIMESTAMP))) throw new Error('Invalid restore timestamp');
    return { schema, mode: 'time-travel', timestamp: env.RESTORE_TIMESTAMP };
  }
  const prefix = `${repo}/${schema.name}/`;
  const key = env.RESTORE_KEY ?? '';
  if (env.RESTORE_MODE !== 'sql' || !key.startsWith(prefix) || !/^\d{4}-\d{2}-\d{2}\/[a-z0-9-]+-\d{4}-\d{2}-\d{2}T\d{4}Z\.sql\.gz$/.test(key.slice(prefix.length))) throw new Error('Restore key must be an owned production archive');
  return { schema, mode: 'sql', key };
}
export async function restoreProduction(io, repo, request, now = new Date()) {
  if (request.mode === 'time-travel') {
    const database = await io.database(request.schema.name);
    await io.timeTravel(database, request.timestamp);
    return;
  }
  // Verify archive and scratch restore before changing production or creating a replacement.
  const sql = await downloadVerified(io, request.key);
  const counts = expectedCounts(sql, request.schema.tables, request.schema.nonempty);
  await restoreCheck(io, repo, { id: 'not-a-database' }, sql, counts);
  const database = await io.database(request.schema.name, true);
  // Preserve a populated current database before replacing it. A newly recreated DB is empty.
  const tables = await io.query(database, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'");
  if (tables.length) await backupDatabase(io, { repo, environment: 'production', schema: request.schema, now });
  await emptyDatabase(io, database);
  await io.import(database, sql);
  await checkRestored(query => io.query(database, query), counts);
}
