import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';
import { fixture } from '../tools/backups/test/fixture.mjs';
import { upload, download } from '../workers/backup/src/archive.ts';
import { dumpDatabase } from '../workers/backup/src/dump.ts';
import { splitSql } from '../workers/backup/src/sql.ts';
import { restoreStatement } from '../workers/backup/src/statement.ts';
import { restoreScratch } from '../workers/backup/src/restore.ts';
// Resolve the runtime from the pinned Wrangler package, not an undeclared root dependency.
const loadPinnedWranglerDependency = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
const { Miniflare, convertV4MiniflareOptions } = loadPinnedWranglerDependency('miniflare');
test('local D1 preserves quotes, newlines, NUL text, blob, 64-bit integers, reals, empty tables, indexes and triggers', { timeout: 60_000 }, async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: 'export default {fetch(){return new Response(null,{status:404})}}', compatibilityDate: '2026-10-01', d1Databases: { SOURCE: 'source', SCRATCH: 'scratch' }, r2Buckets: { BACKUPS: 'backups' } }));
  try {
    const source = await mf.getD1Database('SOURCE'), scratch = await mf.getD1Database('SCRATCH');
    await source.batch(splitSql(fixture).map(sql => source.prepare(sql)));
    await source.prepare('INSERT INTO data(id,txt,b,n,r) VALUES(4,?,?,CAST(? AS INTEGER),9e999)').bind('z'.repeat(60_000), new Uint8Array(60_000).buffer, '9007199254740993').run();
    const dump = await dumpDatabase(source);
    await scratch.batch(splitSql(dump.sql).map(sql => restoreStatement(scratch, sql)));
    for (const query of ["SELECT id,hex(txt) txt,hex(b) b,CAST(n AS TEXT) n,printf('%!.17g',r) r,empty FROM data ORDER BY id", "SELECT type,name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' ORDER BY name"]) assert.deepEqual((await scratch.prepare(query).all()).results, (await source.prepare(query).all()).results);
    await scratch.prepare('INSERT INTO data(id) VALUES(3)').run();
    assert.equal((await scratch.prepare('SELECT count(*) n FROM audit').first()).n, 4);
    const bucket = await mf.getR2Bucket('BACKUPS');
    const key = 'accounts/identity/2026-11-01/identity-2026-11-01T0745Z.sql.gz';
    await upload(bucket, key, dump.sql);
    assert.equal(await download(bucket, key), dump.sql);
    await assert.rejects(upload(bucket, key, dump.sql), /exists/);
    await Promise.all([restoreScratch(scratch, dump.sql, dump.counts), restoreScratch(scratch, dump.sql, dump.counts)]);
    assert.deepEqual((await scratch.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'").all()).results, []);
  } finally { await mf.dispose(); }
});

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
test('restored migration ledger makes the real Wrangler migration command a no-op', { timeout: 90_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'backup-ledger-'));
  const migrations = resolve('migrations');
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: 'export default {fetch(){return new Response(null,{status:404})}}', compatibilityDate: '2026-10-01', d1Databases: { SOURCE: 'ledger-source' } }));
  const config = join(root, 'wrangler.json');
  writeFileSync(config, JSON.stringify({ name: 'backup-ledger-test', compatibility_date: '2026-10-01', d1_databases: [{ binding: 'DB', database_name: 'restored', database_id: '11111111-2222-4333-8444-555555555555', migrations_dir: migrations }] }));
  function cli(args) {
    const result = spawnSync(process.execPath, [resolve('ci/deploy-toolchain/node_modules/wrangler/bin/wrangler.js'), 'd1', ...args, 'restored', '--local', '--config', config, '--persist-to', join(root, 'state')], { encoding: 'utf8', timeout: 25_000, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: join(root, 'wrangler.log') } });
    assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
    return result.stdout;
  }
  try {
    const source = await mf.getD1Database('SOURCE');
    await source.prepare("CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)").run();
    const names = readdirSync(migrations).filter(name => name.endsWith('.sql')).sort();
    for (const name of names) {
      await source.batch([...splitSql(readFileSync(join(migrations, name), 'utf8')).map(sql => source.prepare(sql)), source.prepare('INSERT INTO d1_migrations(name) VALUES(?)').bind(name)]);
    }
    const dump = await dumpDatabase(source);
    assert.equal(dump.counts.d1_migrations, names.length);
    const sql = join(root, 'restore.sql'); writeFileSync(sql, dump.sql);
    cli(['execute', '--file', sql]);
    const ledgerQuery = ['execute', '--command', 'SELECT id,name,applied_at FROM d1_migrations ORDER BY id', '--json'];
    const before = JSON.parse(cli(ledgerQuery))[0].results;
    assert.deepEqual(before, (await source.prepare('SELECT id,name,applied_at FROM d1_migrations ORDER BY id').all()).results);
    assert.match(cli(['migrations', 'apply']), /No migrations to apply/i);
    assert.deepEqual(JSON.parse(cli(ledgerQuery))[0].results, before);
  } finally { await mf.dispose(); rmSync(root, { recursive: true, force: true }); }
});
