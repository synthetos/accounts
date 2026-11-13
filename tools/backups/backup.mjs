import { basename } from 'node:path';
import { archiveKey, pack, unpack, expectedCounts, checkRestored, quoteIdentifier } from './archive.mjs';
export const TABLES_SQL = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'";
export async function emptyDatabase(io, database) {
  const tables = await io.query(database, TABLES_SQL);
  if (tables.length > 0) await io.query(database, `PRAGMA defer_foreign_keys=ON; ${tables.map(t => `DROP TABLE ${quoteIdentifier(t.name)};`).join(' ')}`);
  if ((await io.query(database, TABLES_SQL)).length !== 0) throw new Error('Database cleanup failed');
}
export async function restoreCheck(io, repo, source, sql, counts) {
  if (!['accounts', 'run'].includes(repo)) throw new Error('Invalid restore-test scope');
  const scratch = await io.database(`restore-test-${repo}`, true);
  if (scratch.id === source.id) throw new Error('Scratch database is the source database');
  try {
    await emptyDatabase(io, scratch);
    await io.import(scratch, sql);
    await checkRestored(query => io.query(scratch, query), counts);
  } finally {
    // A partial import and a failed count check must both leave no private rows behind.
    await emptyDatabase(io, scratch);
  }
}
export async function downloadVerified(io, key) {
  const bytes = await io.get(key);
  const checksum = (await io.get(`${key}.sha256`)).toString('utf8');
  return unpack(bytes, checksum, basename(key));
}
export async function backupDatabase(io, { repo, environment, schema, now, monthly = false, onExport = async () => {} }) {
  const name = environment === 'staging' ? schema.staging : schema.name;
  const database = await io.database(name);
  const started = Date.now();
  const sql = await io.export(database);
  await onExport(Date.now() - started);
  const { bytes, hash } = pack(sql);
  // A SQL file containing only comments is not a successful export.
  const counts = expectedCounts(sql, schema.tables, schema.nonempty);
  if (Object.keys(counts).length === 0) throw new Error('Export contains no application tables');
  const key = archiveKey(repo, name, environment, now);
  // Jobs share a per-repo concurrency group; never replace an earlier minute's archive.
  if (await io.exists(key) || await io.exists(`${key}.sha256`)) throw new Error('Backup key already exists; retry in a later minute');
  await io.put(key, bytes);
  await io.put(`${key}.sha256`, Buffer.from(`${hash}  ${basename(key)}\n`));
  const downloaded = await downloadVerified(io, key);
  // The remote object and its checksum cannot both be replaced without detection.
  if (!downloaded.equals(sql)) throw new Error('Uploaded backup differs from the export');
  if (monthly) await restoreCheck(io, repo, database, downloaded, counts);
  return key;
}
