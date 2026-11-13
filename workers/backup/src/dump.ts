import type { Database, Dump } from './types.ts';
import { quoteIdentifier as ident } from './format.ts';
import { SCHEMA, rows, read, columns, literal } from './reads.ts';
const MAX_SQL = 16 * 1024 * 1024;
export async function dumpDatabase(db: Database, batchBytes = 4 * 1024 * 1024): Promise<Dump> {
  const schema = rows(await read(db, SCHEMA).all());
  const tables = schema.filter(r => r['type'] === 'table');
  if (!tables.length || tables.some(t => typeof t['name'] !== 'string' || typeof t['sql'] !== 'string' || /^CREATE VIRTUAL/i.test(t['sql'] as string))) throw new Error('Missing or unsupported tables');
  const specs = await Promise.all(tables.map(async table => {
    const name = table['name'] as string, names = await columns(db, name);
    return { name, names, table, select: `SELECT ${names.map((c, i) => `${literal(c)} AS ${ident(`v${i}`)}`).join(',')} FROM ${ident(name)}` };
  }));
  const estimates = await db.batch(specs.map(s => read(db, `SELECT COALESCE(SUM(${s.names.map(c => `COALESCE(length(CAST(${ident(c)} AS BLOB)),0)*2+32`).join('+')}),0) AS bytes FROM ${ident(s.name)}`)));
  const paged = estimates.reduce((n, r) => n + Number(rows(r)[0]?.['bytes']), 0) > batchBytes;
  const counts: Record<string, number> = {};
  const statements = ['PRAGMA defer_foreign_keys=ON', ...tables.map(t => t['sql'] as string)];
  let size = statements.join('').length;
  const append = (spec: typeof specs[number], records: Record<string, unknown>[]): void => {
    counts[spec.name] = (counts[spec.name] ?? 0) + records.length;
    for (const record of records) {
      const values = spec.names.map((_, i) => record[`v${i}`]);
      if (values.some(v => typeof v !== 'string')) throw new Error('Unsupported SQL value');
      const statement = `INSERT INTO ${ident(spec.name)} (${spec.names.map(ident).join(',')}) VALUES (${values.join(',')})`;
      size += statement.length;
      if (size > MAX_SQL) throw new Error('Dump exceeds safe Worker memory budget');
      statements.push(statement);
    }
  };
  if (!paged) {
    // Metadata and every table are re-read in the same D1 batch/transaction.
    const result = await db.batch([read(db, SCHEMA), ...specs.map(s => read(db, s.select))]);
    if (JSON.stringify(rows(result[0]!)) !== JSON.stringify(schema)) throw new Error('Schema changed while planning dump');
    specs.forEach((s, i) => append(s, rows(result[i + 1]!)));
  } else {
    for (const spec of specs) {
      const rowid = ['_rowid_', 'rowid', 'oid'].find(n => !spec.names.some(c => c.toLowerCase() === n));
      if (!rowid || /WITHOUT\s+ROWID/i.test(spec.table['sql'] as string)) throw new Error('Large table cannot be paged by rowid');
      let after: string | undefined;
      for (;;) {
        const query = spec.select.replace('SELECT ', `SELECT CAST(${ident(rowid)} AS TEXT) AS __cursor, `) + (after === undefined ? '' : ` WHERE ${ident(rowid)}>CAST(? AS INTEGER)`) + ` ORDER BY ${ident(rowid)} LIMIT 128`;
        const statement = read(db, query);
        const page = rows(await (after === undefined ? statement : statement.bind(after)).all());
        append(spec, page);
        if (page.length < 128) break;
        after = String(page.at(-1)!['__cursor']);
      }
    }
    if (JSON.stringify(rows(await read(db, SCHEMA).all())) !== JSON.stringify(schema)) throw new Error('Schema changed during paged dump');
  }
  // Create indexes/triggers after INSERTs: triggers must not replay side effects during restore.
  statements.push(...schema.filter(r => r['type'] !== 'table').map(r => r['sql'] as string));
  return { sql: statements.join(';\n') + ';\n', counts, paged };
}
