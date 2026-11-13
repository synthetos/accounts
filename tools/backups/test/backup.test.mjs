import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { archiveKey, pack, unpack, expectedCounts } from '../archive.mjs';
import { backupDatabase, restoreCheck } from '../backup.mjs';
import { cloudflare, databaseId } from '../api.mjs';
import { provisionBucket, LIFECYCLE } from '../bucket.mjs';
const sql = Buffer.from('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(1); CREATE TABLE sessions(id TEXT);');
const schema = { name: 'run-auth', staging: 'run-auth-staging', tables: ['items', 'sessions'], nonempty: ['items'] };
const now = new Date('2026-11-01T07:15:00Z');
function fake() {
  const objects = new Map(), db = new DatabaseSync(':memory:');
  const calls = [];
  const io = {
    database: async (name, create) => { calls.push(['database', name, create]); return { name, id: name }; },
    export: async () => sql,
    exists: async key => objects.has(key),
    put: async (key, bytes) => { objects.set(key, bytes); },
    get: async key => objects.get(key),
    query: async (database, query) => { assert.equal(database.name, 'restore-test-run'); calls.push(['query', query]); if (query.startsWith('SELECT')) return db.prepare(query).all(); db.exec(query); return []; },
    import: async (database, bytes) => { assert.equal(database.name, 'restore-test-run'); db.exec(bytes.toString()); },
  };
  return { io, objects, calls, db };
}
test('production and staging archives have isolated dated keys', () => {
  assert.equal(archiveKey('run', 'run-auth', 'production', now), 'run/run-auth/2026-11-01/run-auth-2026-11-01T0715Z.sql.gz');
  assert.match(archiveKey('accounts', 'identity-staging', 'staging', now), /^staging\/accounts\/identity-staging\//);
  assert.throws(() => archiveKey('run', '../escape', 'production', now));
});
test('empty exports, missing tables and empty mandatory tables are refused; empty sessions are legitimate', () => {
  for (const bytes of [Buffer.alloc(0), Buffer.from('   ')]) assert.throws(() => pack(bytes));
  assert.deepEqual(expectedCounts(sql, schema.tables, schema.nonempty), { items: 1, sessions: 0 });
  for (const bytes of [Buffer.from('-- empty'), Buffer.from('CREATE TABLE items(id INT);'), Buffer.from('bad SQL with private data')]) assert.throws(() => expectedCounts(bytes, schema.tables, schema.nonempty), /missing or invalid/);
});
test('checksum verification refuses damaged content and mismatched filenames before decompression', () => {
  const { bytes, hash } = pack(sql), name = 'run-auth-2026-11-01T0715Z.sql.gz';
  assert.deepEqual(unpack(bytes, `${hash}  ${name}\n`, name), sql);
  for (const checksum of [`${'0'.repeat(64)}  ${name}\n`, `${hash}  other.sql.gz\n`, `${hash}  ../${name}\n`]) assert.throws(() => unpack(bytes, checksum, name), /checksum/);
});
test('backup reads back both objects, restores all table counts and empties scratch', async () => {
  const { io, objects, db } = fake();
  try {
    const key = await backupDatabase(io, { repo: 'run', environment: 'production', schema, now, monthly: true });
    assert.equal(objects.size, 2); assert.ok(objects.has(`${key}.sha256`));
    assert.equal(db.prepare("SELECT count(*) n FROM sqlite_schema WHERE type='table'").get().n, 0);
  } finally { db.close(); }
});
test('upload corruption fails before scratch is opened', async () => {
  const { io, calls, db } = fake();
  io.get = async () => Buffer.from('corrupt');
  try { await assert.rejects(backupDatabase(io, { repo: 'run', environment: 'production', schema, now, monthly: true }), /checksum/); assert.equal(calls.length, 1); }
  finally { db.close(); }
});
test('partial import and wrong row count still empty scratch, and cannot target the source', async () => {
  for (const partial of [true, false]) {
    const { io, db } = fake();
    io.import = async () => { db.exec('CREATE TABLE items(id INT); CREATE TABLE sessions(id TEXT);'); if (partial) throw Error('import failed'); };
    try {
      await assert.rejects(restoreCheck(io, 'run', { id: 'source' }, sql, { items: 1, sessions: 0 }));
      assert.equal(db.prepare("SELECT count(*) n FROM sqlite_schema WHERE type='table'").get().n, 0);
      await assert.rejects(restoreCheck(io, 'run', { id: 'restore-test-run' }, sql, {}), /source/);
    } finally { db.close(); }
  }
});
test('bucket provisioning creates once, enforces privacy and reads back retention without deleting', async () => {
  for (const exists of [true, false]) {
    const calls = []; let lifecycle = { rules: [] };
    const api = async (path, method = 'GET', body) => {
      calls.push([path, method, body]);
      if (path.endsWith('/managed')) return { result: { enabled: false } };
      if (path.endsWith('/custom')) return { result: { domains: [] } };
      if (path.endsWith('/lifecycle')) { if (method === 'PUT') lifecycle = body; return { result: lifecycle }; }
      return exists || method === 'POST' ? { result: {} } : null;
    };
    await provisionBucket(api);
    assert.equal(calls.filter(c => c[1] === 'POST').length, exists ? 0 : 1);
    assert.ok(calls.every(c => c[1] !== 'DELETE'));
    assert.deepEqual(lifecycle, LIFECYCLE);
    assert.deepEqual(lifecycle.rules.map(r => [r.conditions.prefix, r.deleteObjectsTransition.condition.maxAge]), [['accounts/', 2592000], ['run/', 2592000], ['staging/', 604800]]);
    calls.length = 0; await provisionBucket(api); assert.ok(calls.every(c => c[1] !== 'PUT'));
  }
  for (const publicBucket of [true, false]) await assert.rejects(provisionBucket(async path => ({ result: path.endsWith('/managed') ? { enabled: publicBucket } : { domains: ['custom'] } })), /private/);
});
test('D1 lookup paginates, creates only if missing, and refuses ambiguous names', async () => {
  const id = '11111111-2222-4333-8444-555555555555';
  const api = async path => ({ result: path.endsWith('page=2') ? [{ name: 'run-auth', uuid: id }] : [], result_info: { total_pages: 2 } });
  assert.equal(await databaseId(api, 'run-auth'), id);
  await assert.rejects(databaseId(async () => ({ result: [{ name: 'run-auth', uuid: id }, { name: 'run-auth', uuid: id }] }), 'run-auth'), /Ambiguous/);
  let created = 0;
  assert.equal(await databaseId(async (path, method, body) => { if (method === 'POST') { created++; assert.deepEqual(body, { name: 'restore-test-run' }); return { result: { uuid: id } }; } return { result: [] }; }, 'restore-test-run', true), id);
  assert.equal(created, 1);
});
test('API denial hides response content and names the credential permission', async () => {
  for (const status of [401, 403, 500]) {
    const api = cloudflare('a'.repeat(32), 'private-token', 'D1: Edit', async () => new Response('private rows', { status }));
    await assert.rejects(api('d1/database'), error => !error.message.includes('private') && (status === 500 || error.message.includes('D1: Edit')));
  }
});
import { restoreRequest, restoreProduction } from '../restore.mjs';
test('manual production restore refuses unapproved scope, cross-repo keys and missing confirmation', () => {
  const env = { GITHUB_ACTIONS: 'true', GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'workflow_dispatch', BACKUP_ENV: 'production', RESTORE_DATABASE: 'run-auth', RESTORE_CONFIRM: 'RESTORE run-auth', RESTORE_MODE: 'sql', RESTORE_KEY: 'run/run-auth/2026-11-01/run-auth-2026-11-01T0715Z.sql.gz' };
  assert.equal(restoreRequest(env, 'run', [schema]).mode, 'sql');
  for (const patch of [{ GITHUB_EVENT_NAME: 'schedule' }, { RESTORE_CONFIRM: '' }, { RESTORE_KEY: 'staging/' + env.RESTORE_KEY }, { RESTORE_KEY: '../identity.sql.gz' }, { RESTORE_DATABASE: 'identity' }]) assert.throws(() => restoreRequest({ ...env, ...patch }, 'run', [schema]));
  assert.equal(restoreRequest({ ...env, RESTORE_MODE: 'time-travel', RESTORE_TIMESTAMP: '2026-11-01T07:15:00Z' }, 'run', [schema]).mode, 'time-travel');
});
test('manual SQL restore with a bad archive never looks up or changes production', async () => {
  const { io, calls, db } = fake(); io.get = async () => Buffer.from('bad');
  try { await assert.rejects(restoreProduction(io, 'run', { mode: 'sql', key: 'bad', schema })); assert.deepEqual(calls, []); }
  finally { db.close(); }
});

test('a same-minute retry never replaces a prior archive or checksum', async () => {
  const { io, db, objects } = fake();
  try {
    const key = await backupDatabase(io, { repo: 'run', environment: 'production', schema, now });
    const before = objects.get(key);
    await assert.rejects(backupDatabase(io, { repo: 'run', environment: 'production', schema, now }), /already exists/);
    assert.equal(objects.get(key), before);
  } finally { db.close(); }
});
test('manual SQL recovery verifies scratch, saves existing production first, then verifies restored rows', async () => {
  for (const existing of [false, true]) {
    const scratch = new DatabaseSync(':memory:'), production = new DatabaseSync(':memory:');
    const key = 'run/run-auth/2026-10-01/run-auth-2026-10-01T0715Z.sql.gz';
    const { bytes, hash } = pack(sql), objects = new Map([[key, bytes], [`${key}.sha256`, Buffer.from(`${hash}  run-auth-2026-10-01T0715Z.sql.gz\n`)]]);
    if (existing) production.exec('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(2); CREATE TABLE sessions(id TEXT);');
    const io = {
      database: async name => ({ name, id: name }), exists: async key => objects.has(key),
      get: async key => objects.get(key), put: async (key, value) => { objects.set(key, value); },
      export: async () => Buffer.from('CREATE TABLE items(id INTEGER PRIMARY KEY); INSERT INTO items VALUES(2); CREATE TABLE sessions(id TEXT);'),
      query: async (database, query) => { const db = database.name === 'restore-test-run' ? scratch : production; if (query.startsWith('SELECT')) return db.prepare(query).all(); db.exec(query); return []; },
      import: async (database, bytes) => (database.name === 'restore-test-run' ? scratch : production).exec(bytes.toString()),
    };
    try {
      await restoreProduction(io, 'run', { mode: 'sql', key, schema }, now);
      assert.equal(production.prepare('SELECT id FROM items').get().id, 1);
      assert.equal(objects.size, existing ? 4 : 2);
      assert.equal(scratch.prepare("SELECT count(*) n FROM sqlite_schema WHERE type='table'").get().n, 0);
    } finally { scratch.close(); production.close(); }
  }
});
