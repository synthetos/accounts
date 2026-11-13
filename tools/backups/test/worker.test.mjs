import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { dumpDatabase } from '../../../workers/backup/src/dump.ts';
import { splitSql } from '../../../workers/backup/src/sql.ts';
import { backupScheduled } from '../../../workers/backup/src/scheduled.ts';
import { restoreScratch } from '../../../workers/backup/src/restore.ts';
import { upload, download } from '../../../workers/backup/src/archive.ts';
import { fixture } from './fixture.mjs';

function local() {
  const db = new DatabaseSync(':memory:');
  const wrap = (sql, args = []) => ({
    sql, bind: (...values) => wrap(sql, values),
    all: async () => ({ success: true, results: db.prepare(sql).all(...args.map(v => v instanceof ArrayBuffer ? new Uint8Array(v) : v)).map(row => ({ ...row })) }),
  });
  return { db, prepare: wrap, batch: async statements => {
    db.exec('BEGIN');
    try { const result = []; for (const s of statements) result.push(await s.all()); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  } };
}
function bucket() {
  const values = new Map();
  return { values, head: async key => values.has(key) ? {} : null,
    put: async (key, value, options) => { assert.equal(options.onlyIf.get('If-None-Match'), '*'); if (values.has(key)) return null; values.set(key, value); return {}; },
    get: async key => values.has(key) ? { arrayBuffer: async () => new Response(values.get(key)).arrayBuffer(), text: async () => new Response(values.get(key)).text() } : null,
  };
}
test('dump round trip preserves exact values, empty tables, indexes and trigger bodies', async () => {
  const source = local(), target = local();
  try {
    source.db.exec(fixture);
    const dump = await dumpDatabase(source);
    assert.equal(dump.paged, false);
    assert.deepEqual(dump.counts, { audit: 0, data: 2, empty_table: 0 });
    for (const statement of splitSql(dump.sql)) target.db.exec(statement);
    for (const query of ["SELECT id,hex(txt) txt,hex(b) b,CAST(n AS TEXT) n,printf('%!.17g',r) r,empty FROM data ORDER BY id", "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"]) assert.deepEqual(target.db.prepare(query).all(), source.db.prepare(query).all());
    target.db.exec("INSERT INTO data(id) VALUES(3)"); assert.equal(target.db.prepare('SELECT count(*) n FROM audit').get().n, 2);
  } finally { source.db.close(); target.db.close(); }
});
test('paged dumps use exact rowid cursors and explicitly mark their weaker consistency', async () => {
  const source = local();
  try { source.db.exec(fixture); for (let i = 3; i < 140; i++) source.db.exec(`INSERT INTO data(id) VALUES(${i})`); const dump = await dumpDatabase(source, 1); assert.equal(dump.paged, true); assert.equal(dump.counts.data, 139); }
  finally { source.db.close(); }
});
test('archive readback, collision and checksum mismatch', async () => {
  const r2 = bucket(), key = 'run/run-auth/2026-11-01/run-auth-2026-11-01T0715Z.sql.gz';
  await upload(r2, key, fixture); assert.equal(await download(r2, key), fixture);
  await assert.rejects(upload(r2, key, fixture), /exists/);
  r2.values.set(`${key}.sha256`, 'bad'); await assert.rejects(download(r2, key), /checksum/);
  const mismatch = bucket(); const original = mismatch.get; mismatch.get = async key => key.endsWith('.sha256') ? { text: async () => 'bad' } : original(key);
  await assert.rejects(upload(mismatch, key, fixture), /checksum/);
});
test('scratch is emptied on restore failure and monthly branch only runs on day one', async () => {
  const source = local(), scratch = local(); source.db.exec(fixture);
  try {
    const dump = await dumpDatabase(source);
    await assert.rejects(restoreScratch(scratch, dump.sql, { ...dump.counts, data: 900 }), /counts/);
    assert.equal(scratch.db.prepare("SELECT count(*) n FROM sqlite_master WHERE type='table'").get().n, 0);
    for (const day of [1, 2]) {
      const logs = []; let restores = 0;
      const target = { ...scratch, batch: async statements => { restores++; return scratch.batch(statements); } };
      await backupScheduled('run', 'production', [{ name: 'run-auth', database: source }], target, bucket(), new Date(`2026-11-0${day}T07:50:00Z`), r => logs.push(r));
      assert.equal(restores > 0, day === 1); assert.equal(logs.length, 1); assert.equal(logs[0].status, 'ok'); assert.ok(!JSON.stringify(logs).includes('quote'));
    }
  } finally { source.db.close(); scratch.db.close(); }
});
test('SQL splitter refuses incomplete tokens and preserves comments, strings and triggers', () => {
  for (const sql of ["CREATE TABLE x(a TEXT DEFAULT 'missing)", '/* missing', 'CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1;']) assert.throws(() => splitSql(sql));
  assert.equal(splitSql("-- header\nCREATE TABLE x(a TEXT DEFAULT ';'); /* ; */ INSERT INTO x VALUES('it''s;ok'); -- tail").length, 2);
});
import worker from '../../../workers/backup/src/index.ts';
test('Worker HTTP entry is inert; failure logs never include a D1 error or row value', async () => {
  assert.equal(worker.fetch().status, 404);
  const logs = [];
  const failed = { prepare: () => ({ all: async () => { throw new Error('secret row text'); } }) };
  await assert.rejects(backupScheduled('accounts', 'production', [{ name: 'identity', database: failed }], { prepare: () => { throw new Error('Scratch must not be reached'); } }, bucket(), new Date('2026-11-02T07:45:00Z'), r => logs.push(r)), error => !error.message.includes('secret row'));
  assert.equal(logs.length, 1); assert.equal(logs[0].stage, 'dump'); assert.ok(!JSON.stringify(logs).includes('secret row'));
});
