import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
export const MAX_SQL_BYTES = 512 * 1024 * 1024;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function archiveKey(repo, database, environment, date) {
  if (!['accounts', 'run'].includes(repo) || !/^[a-z][a-z0-9-]+$/.test(database) || !['staging', 'production'].includes(environment)) throw new Error('Invalid backup scope');
  const iso = date.toISOString();
  return `${environment === 'staging' ? 'staging/' : ''}${repo}/${database}/${iso.slice(0, 10)}/${database}-${iso.slice(0, 16).replaceAll(':', '')}Z.sql.gz`;
}
export function pack(sql) {
  if (sql.byteLength === 0 || sql.byteLength > MAX_SQL_BYTES || !sql.toString('utf8').trim()) throw new Error('Export is empty or exceeds the backup size limit');
  const bytes = gzipSync(sql, { level: 9 });
  return { bytes, hash: sha256(bytes) };
}
export function unpack(bytes, checksum, basename) {
  if (!/^[a-z0-9T.Z-]+\.sql\.gz$/.test(basename)) throw new Error('Invalid archive filename');
  const match = /^([0-9a-f]{64})  ([^\n]+)\n$/.exec(checksum);
  if (!match || match[2] !== basename || sha256(bytes) !== match[1]) throw new Error('Backup checksum mismatch');
  try { return gunzipSync(bytes, { maxOutputLength: MAX_SQL_BYTES }); }
  catch { throw new Error('Invalid compressed backup'); }
}
export function quoteIdentifier(value) {
  if (typeof value !== 'string' || value.includes('\0')) throw new Error('Invalid table name');
  return `"${value.replaceAll('"', '""')}"`;
}
export function expectedCounts(sql, tables, nonempty) {
  const db = new DatabaseSync(':memory:', { allowExtension: false });
  try {
    db.exec(sql.toString('utf8'));
    const counts = Object.fromEntries(db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'").all().map(row => [row.name, Number(db.prepare(`SELECT count(*) AS n FROM ${quoteIdentifier(row.name)}`).get().n)]));
    for (const table of tables) if (!(table in counts)) throw new Error('Expected table missing');
    for (const table of nonempty) if (!(counts[table] > 0)) throw new Error('Expected non-empty table is empty');
    return counts;
  } catch { throw new Error('Export schema or expected rows are missing or invalid'); }
  finally { db.close(); }
}
export async function checkRestored(query, counts) {
  const rows = await query("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'");
  if (JSON.stringify(rows.map(r => r.name).sort()) !== JSON.stringify(Object.keys(counts).sort())) throw new Error('Restored tables differ from the export');
  for (const [table, count] of Object.entries(counts)) {
    const result = await query(`SELECT count(*) AS n FROM ${quoteIdentifier(table)}`);
    if (result[0]?.n !== count) throw new Error('Restored row count differs from the export');
  }
}
