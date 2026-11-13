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
