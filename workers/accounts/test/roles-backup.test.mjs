import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { adminFixture } from './roles-fixture.mjs';
import { emptyDatabase } from '../../../tools/backups/backup.mjs';
import { dumpDatabase } from '../../backup/src/dump.ts';
import { restoreScratch } from '../../backup/src/restore.ts';

function adapter(db) {
  const prepare = (sql, args = []) => ({
    bind: (...values) => prepare(sql, values),
    all: async () => ({ success: true, results: db.prepare(sql).all(...args.map(v => v instanceof ArrayBuffer ? new Uint8Array(v) : v)) }),
  });
  return { prepare, batch: async statements => {
    db.exec('BEGIN');
    try { const result = []; for (const statement of statements) result.push(await statement.all()); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  } };
}

test('whole-database restore cleanup removes last-admin guards before deleting tables', async () => {
  const f = await adminFixture(); try {
    await emptyDatabase({ query: async (_database, sql) => sql.startsWith('SELECT') ? f.db.prepare(sql).all() : (f.db.exec('BEGIN; ' + sql + ' COMMIT;'), []) }, { id: 'scratch' });
    assert.equal(f.db.prepare("SELECT count(*) n FROM sqlite_schema WHERE type='table'").get().n, 0);
  } finally { f.close(); }
});

test('scheduled backup restores roles, audit and guard triggers and empties scratch without changing the live admin', async () => {
  const f = await adminFixture(); const target = new DatabaseSync(':memory:'); target.exec('PRAGMA foreign_keys=ON');
  try {
    const dump = await dumpDatabase(adapter(f.db));
    assert.equal(dump.counts.roles, 1); assert.equal(dump.counts.role_audit, 1);
    await restoreScratch(adapter(target), dump.sql, dump.counts);
    assert.equal(target.prepare("SELECT count(*) n FROM sqlite_schema WHERE type='table'").get().n, 0);
    assert.equal(f.db.prepare('SELECT role FROM roles').get().role, 'admin');
    assert.throws(() => f.db.exec('DELETE FROM roles'), /last_admin/);
  } finally { target.close(); f.close(); }
});
