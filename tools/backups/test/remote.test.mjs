import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { remote } from '../remote.mjs';
test('only the pinned Wrangler runs, with isolated config, separated credentials and suppressed child output', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'backup-remote-test-'));
  const calls = [];
  try {
    const io = remote({ api: async () => ({ result: [{ success: true, results: [{ n: 1 }] }] }), account: 'a'.repeat(32), d1Token: 'd1-secret', r2Token: 'r2-secret', directory, runner: async (binary, args, options) => {
      assert.equal(binary, resolve('ci/deploy-toolchain/node_modules/.bin/wrangler'));
      assert.equal(options.env.CLOUDFLARE_API_TOKEN, args[0] === 'd1' ? 'd1-secret' : 'r2-secret');
      assert.equal(options.env.WRANGLER_SEND_METRICS, 'false');
      const config = JSON.parse(await readFile(args.at(-1), 'utf8')); assert.equal(config.build, undefined);
      calls.push(args);
      if (args.includes('--output')) await writeFile(args[args.indexOf('--output') + 1], 'CREATE TABLE x(id INT);');
      if (args[2] === 'get') await writeFile(args[args.indexOf('--file') + 1], 'downloaded');
    } });
    const database = { id: 'id', name: 'run-auth' };
    assert.match((await io.export(database)).toString(), /CREATE TABLE/);
    await io.import(database, Buffer.from('sql'));
    await io.put('run/example.sql.gz', Buffer.from('gzip'));
    assert.equal((await io.get('run/example.sql.gz')).toString(), 'downloaded');
    assert.deepEqual(await io.query(database, 'SELECT count(*) n FROM x'), [{ n: 1 }]);
    await io.timeTravel(database, '2026-11-01T07:15:00Z');
    assert.equal(calls.length, 5);
    assert.ok(calls[1].includes('--yes'));
    const failing = remote({ directory, runner: async () => { throw Error('private rows and d1-secret'); } });
    await assert.rejects(failing.export(database), error => !error.message.includes('private rows') && !error.message.includes('d1-secret'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
test('existing-object check distinguishes absence from access failure without reading private bytes', async () => {
  for (const status of [200, 404, 403]) {
    const io = remote({ directory: '/unused', account: 'a'.repeat(32), r2Token: 'secret', fetcher: async (url, options) => {
      assert.match(url, /objects\/run%2Fbackup/); assert.equal(options.redirect, 'error');
      return new Response('private bytes', { status });
    } });
    if (status === 403) await assert.rejects(io.exists('run/backup'), /Cannot check/);
    else assert.equal(await io.exists('run/backup'), status === 200);
  }
});
