import { restoreStatement } from './statement.ts';
import type { Database } from './types.ts';
import { quoteIdentifier as ident } from './format.ts';
import { splitSql } from './sql.ts';
import { SCHEMA, rows } from './reads.ts';
export async function clearScratch(db: Database): Promise<void> {
  const tables = rows(await db.prepare(SCHEMA).all()).filter(r => r['type'] === 'table');
  if (tables.length) await db.batch([db.prepare('PRAGMA defer_foreign_keys=ON'), ...tables.map(t => db.prepare(`DROP TABLE IF EXISTS ${ident(String(t['name']))}`))]);
  if (rows(await db.prepare(SCHEMA).all()).length) throw new Error('Scratch cleanup failed');
}
export async function restoreScratch(db: Database, sql: string, counts: Record<string, number>): Promise<void> {
  try {
    await clearScratch(db);
    const statements = splitSql(sql), tables = Object.keys(counts).sort();
    // One D1 transaction includes restore, verification reads AND removal. Concurrent
    // staging/production invocations cannot observe or erase another restore halfway.
    const result = await db.batch([
      ...statements.map(statement => restoreStatement(db, statement)),
      db.prepare(SCHEMA),
      ...tables.map(table => db.prepare(`SELECT count(*) AS n FROM ${ident(table)}`)),
      ...tables.map(table => db.prepare(`DROP TABLE ${ident(table)}`)),
    ]);
    if (result.some(r => !r.success)) throw new Error('Scratch import failed');
    const restored = rows(result[statements.length]!).filter(r => r['type'] === 'table').map(t => String(t['name'])).sort();
    if (JSON.stringify(restored) !== JSON.stringify(tables)) throw new Error('Scratch tables differ');
    tables.forEach((table, i) => {
      if (rows(result[statements.length + 1 + i]!)[0]?.['n'] !== counts[table]) throw new Error('Scratch row counts differ');
    });
  } finally { await clearScratch(db); }
}
