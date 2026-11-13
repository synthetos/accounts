import type { Database, Statement } from './types.ts';
/** Keep large text/blob rows below D1's SQL-statement length limit. Values in a
 * generated INSERT are typed literals; binding integer text then CAST keeps 64 bits. */
export function restoreStatement(db: Database, sql: string): Statement {
  const insert = /^(INSERT INTO [\s\S]+ VALUES )\(([\s\S]*)\)$/.exec(sql);
  if (!insert) return db.prepare(sql);
  const values: unknown[] = [];
  const expressions = insert[2]!.split(',').map(value => {
    if (value === 'NULL') return 'NULL';
    const hex = /^(X'([0-9A-F]*)'|CAST\(X'([0-9A-F]*)' AS TEXT\))$/.exec(value);
    if (hex) {
      const bytes = (hex[2] ?? hex[3])!;
      values.push(Uint8Array.from(bytes.match(/../g) ?? [], b => Number.parseInt(b, 16)).buffer);
      return hex[3] === undefined ? '?' : 'CAST(? AS TEXT)';
    }
    if (!/^-?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value)) throw new Error('Unsupported dump literal');
    values.push(value);
    return /^-?\d+$/.test(value) ? 'CAST(? AS INTEGER)' : 'CAST(? AS REAL)';
  });
  return db.prepare(`${insert[1]}(${expressions.join(',')})`).bind(...values);
}
