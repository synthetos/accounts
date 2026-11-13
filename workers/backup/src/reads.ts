import type { Database, Result } from './types.ts';
import { quoteIdentifier as ident } from './format.ts';
export const SCHEMA = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index','trigger') AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT IN ('d1_migrations','_d1_migrations') AND sql IS NOT NULL ORDER BY type,name";
export function rows(result: Result): Record<string, unknown>[] {
  if (!result.success || !Array.isArray(result.results)) throw new Error('D1 read failed');
  return result.results;
}
/** The live database capability exposes SELECT/metadata PRAGMA only. Restore never receives it. */
export function read(db: Database, sql: string): ReturnType<Database['prepare']> {
  if (!/^SELECT\b/i.test(sql)) throw new Error('Source database is read only');
  return db.prepare(sql);
}
export function literal(column: string): string {
  const c = ident(column);
  // No integer crosses the D1 JS number boundary; encode it inside SQLite.
  // Hex text also preserves embedded NULs and newlines (SQLite quote() truncates NUL text).
  return `CASE typeof(${c}) WHEN 'null' THEN 'NULL' WHEN 'integer' THEN CAST(${c} AS TEXT) WHEN 'real' THEN CASE WHEN ${c}>1.7976931348623157e308 THEN '9e999' WHEN ${c}< -1.7976931348623157e308 THEN '-9e999' ELSE printf('%!.17g',${c}) END WHEN 'blob' THEN 'X'''||hex(${c})||'''' WHEN 'text' THEN 'CAST(X'''||hex(${c})||''' AS TEXT)' ELSE NULL END`;
}
export async function columns(db: Database, table: string): Promise<string[]> {
  const result = rows(await read(db, `SELECT name FROM pragma_table_xinfo('${table.replaceAll("'", "''")}') WHERE hidden=0 ORDER BY cid`).all());
  if (!result.length || result.some(r => typeof r['name'] !== 'string')) throw new Error('Invalid table columns');
  return result.map(r => r['name'] as string);
}
