import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

test('built Worker completes stubbed GitHub login against workerd D1 and rejects a callback replay', { timeout: 60_000 }, async () => {
  execFileSync(process.execPath, ['tools/build.mjs']);
  const require = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
  // Use the Miniflare version already pinned by the isolated Wrangler test toolchain.
  const { Miniflare, convertV4MiniflareOptions, Response: RuntimeResponse } = require('miniflare');
  const origin = 'https://accounts.example.test';
  const { unstable_splitSqlQuery } = require('wrangler');
  let challenge; let calls = 0; const requests = [];
  const entry = resolve('dist/workers/accounts/src/index.js');
  const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]);
  const modules = [entry, ...files(resolve('dist')).filter((p) => p.endsWith('.js') && p !== entry)].map((path) => ({ type: 'ESModule', path }));
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules, modulesRoot: resolve('dist'),
    compatibilityDate: '2026-10-01', d1Databases: ['IDENTITY'],
    bindings: { AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
      GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-secret',
      OAUTH_STATE_KEY: Buffer.alloc(32, 1).toString('base64url'), FORM_KEY: Buffer.alloc(32, 2).toString('base64url'),
      RATE_KEY: Buffer.alloc(32, 3).toString('base64url'), GITHUB_WEBHOOK_SECRET: 'fixture-webhook-secret-long-enough' },
    outboundService: async (request) => {
      calls++; requests.push(request.url);
      if (request.url === 'https://github.com/login/oauth/access_token') {
        const body = new URLSearchParams(await request.text());
        assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'), challenge);
        return RuntimeResponse.json({ token_type: 'bearer', access_token: 'ghu_local_only' });
      }
      assert.equal(request.url, 'https://api.github.com/user');
      assert.equal(request.headers.get('Authorization'), 'Bearer ghu_local_only');
      return RuntimeResponse.json({ id: 23456, login: 'local-test', name: 'Local Test', avatar_url: null, email: 'discard@example.test' });
    },
  }));
  try {
    const db = await mf.getD1Database('IDENTITY');
    for (const file of readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort()) {
      await db.batch(unstable_splitSqlQuery(readFileSync(`migrations/${file}`, 'utf8')).map((sql) => db.prepare(sql)));
    }
    const get = await mf.dispatchFetch(`${origin}/login`, { redirect: 'manual' }); assert.equal(get.status, 200);
    const form = await get.text(); const csrf = form.match(/name="csrf" value="([^"]+)"/)[1];
    const start = await mf.dispatchFetch(`${origin}/login`, { method: 'POST', redirect: 'manual',
      headers: { Cookie: get.headers.get('Set-Cookie').split(';')[0], Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf, return_to: '/' }).toString() });
    assert.equal(start.status, 303);
    const github = new URL(start.headers.get('Location')); challenge = github.searchParams.get('code_challenge');
    const callback = `${origin}/auth/github/callback?state=${github.searchParams.get('state')}&code=local-code`;
    const headers = { Cookie: start.headers.get('Set-Cookie').split(';')[0] };
    const done = await mf.dispatchFetch(callback, { headers, redirect: 'manual' }); assert.equal(done.status, 303, JSON.stringify({ calls, requests, body: await done.text() }));
    const sid = done.headers.getSetCookie().find((s) => s.startsWith('__Host-acct_sid=')); assert.ok(sid);
    const account = await mf.dispatchFetch(origin, { headers: { Cookie: sid.split(';')[0] }, redirect: 'manual' });
    assert.equal(account.status, 200); assert.match(await account.text(), /Local Test/);
    assert.equal((await mf.dispatchFetch(callback, { headers, redirect: 'manual' })).status, 400);
    assert.equal(calls, 2);
    assert.equal((await db.prepare('SELECT email FROM identities').first()).email, null);
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM sessions').first()).n, 1);
  } finally { await mf.dispose(); }
});
