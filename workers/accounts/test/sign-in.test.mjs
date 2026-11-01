import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { GitHubProvider } from '../../../packages/idp/src/index.ts';
import { createApp } from '../src/app.ts';
import { Store, ACCOUNT_IDLE, ACCOUNT_ABSOLUTE } from '../src/store.ts';
import { key, seal } from '../src/security.ts';

import { fixture, origin, sha, cookie, rawToken, refreshToken } from './fixture.mjs';
const worker = createApp();

test('GitHub sign-in uses S256, persists only hashes and selected profile fields, and refreshes login', async () => {
  const f = fixture();
  // Let node:sqlite's runtime warning finish before capturing application logs.
  await new Promise((resolve) => setImmediate(resolve));
  const logs = []; const oldLog = console.log; const oldError = console.error; const oldWarn = console.warn;
  console.log = console.error = console.warn = (...args) => logs.push(args);
  try {
    const flow = await f.start(); assert.equal(flow.response.status, 303);
    assert.equal(flow.authorization.origin, 'https://github.com');
    assert.equal(flow.authorization.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(flow.authorization.searchParams.has('scope'), false);
    const record = f.db.prepare('SELECT * FROM auth_requests').get();
    assert.equal(record.state_hash, sha(flow.state)); assert.notEqual(record.browser_nonce_hash, flow.cookie.split('=')[1]);
    const done = await f.callback(flow); assert.equal(done.status, 303); assert.equal(done.headers.get('Location'), '/');
    const sid = cookie(done, '__Host-acct_sid'); assert.ok(sid);
    const stored = f.db.prepare('SELECT * FROM sessions').get();
    assert.equal(stored.token_hash, sha(sid.split('=')[1]));
    assert.equal(stored.idle_expires_at - f.now, ACCOUNT_IDLE); assert.equal(stored.abs_expires_at - f.now, ACCOUNT_ABSOLUTE);
    assert.match(done.headers.getSetCookie()[0], /Secure; HttpOnly; SameSite=Lax; Max-Age=2592000/);
    assert.ok(done.headers.getSetCookie().some((s) => s.includes('__Host-acct_oauth=;')));
    const identity = f.db.prepare('SELECT * FROM identities').get(); assert.equal(identity.email, null); assert.equal(identity.email_verified, 0);
    assert.equal(identity.provider_subject, '12345'); assert.match(identity.user_id, /^usr_[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(f.exchangeCalls, 1); assert.equal(f.profileCalls, 1);
    const account = await f.call('/', { headers: { Cookie: sid } }); assert.equal(account.status, 200);
    assert.match(await account.text(), /Fixture User/); assert.equal(account.headers.get('Access-Control-Allow-Origin'), null);
    assert.equal(account.headers.get('Cross-Origin-Opener-Policy'), 'same-origin');
    assert.equal(account.headers.get('Referrer-Policy'), 'same-origin'); assert.equal(account.headers.get('Cache-Control'), 'no-store');
    f.profile = { id: 12345, login: 'renamed', name: '<script>alert(1)</script>', avatar_url: 'https://evil.test/tracking', email: 'still-discard@example.test' };
    f.now++;
    const second = await f.callback(await f.start()); assert.equal(second.status, 303);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 1);
    assert.equal(f.db.prepare('SELECT login FROM identities').get().login, 'renamed');
    assert.equal(f.db.prepare('SELECT email FROM identities').get().email, null);
    const html = await (await f.call('/', { headers: { Cookie: cookie(second, '__Host-acct_sid') } })).text();
    assert.match(html, /&lt;script&gt;/); assert.doesNotMatch(html, /<script>/);
    const rows = ['users','identities','sessions','auth_requests','security_audit','login_rate_limits'].map((table) => f.db.prepare(`SELECT * FROM ${table}`).all());
    const saved = JSON.stringify(rows) + JSON.stringify(logs) + html + JSON.stringify([...done.headers]);
    for (const secret of [rawToken, refreshToken, 'must-discard@example.test', '192.0.2.1', 'fixture-code', f.env.GITHUB_CLIENT_SECRET]) assert.ok(!saved.includes(secret), secret);
    assert.deepEqual(logs, []); assert.ok(f.primaryReads > 0);
  } finally { console.log = oldLog; console.error = oldError; console.warn = oldWarn; f.close(); }
});

test('callback rejects missing, mismatched, duplicate, expired and replayed state/cookies before exchanging', async () => {
  const f = fixture();
  try {
    const flow = await f.start();
    assert.equal((await f.callback({ ...flow, cookie: undefined })).status, 400);
    assert.equal((await f.callback({ ...flow, cookie: `__Host-acct_oauth=${Buffer.alloc(32, 9).toString('base64url')}` })).status, 400);
    assert.equal((await f.callback(flow, { state: Buffer.alloc(32, 8).toString('base64url') })).status, 400);
    assert.equal((await f.callback({ ...flow, cookie: `${flow.cookie}; ${flow.cookie}` })).status, 403);
    assert.equal((await f.call(`/auth/github/callback?state=${flow.state}&state=other&code=fixture-code`, { headers: { Cookie: flow.cookie } })).status, 400);
    assert.equal(f.exchangeCalls, 0);
    const results = await Promise.all([f.callback(flow), f.callback(flow)]);
    assert.deepEqual(results.map((r) => r.status).sort(), [303, 400]); assert.equal(f.exchangeCalls, 1);
    const expired = await f.start(); f.now += 600;
    assert.equal((await f.callback(expired)).status, 400); assert.equal(f.exchangeCalls, 1);
  } finally { f.close(); }
});

test('PKCE mismatch and upstream failure never mint sessions or echo provider secrets', async () => {
  const f = fixture();
  try {
    const flow = await f.start(); const record = f.db.prepare('SELECT * FROM auth_requests').get();
    const encrypted = await seal('x'.repeat(43), await key(f.env.OAUTH_STATE_KEY, 'AES-GCM'), `${origin}|${record.state_hash}|${record.browser_nonce_hash}`);
    f.db.prepare('UPDATE auth_requests SET pkce_verifier_enc=?').run(encrypted);
    const response = await f.callback(flow); assert.equal(response.status, 502); assert.equal(await response.text(), 'sign_in_unavailable');
    assert.equal(f.profileCalls, 0); assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
    assert.equal((await f.callback(flow)).status, 400);
    f.failure = true; assert.equal((await f.callback(await f.start())).status, 502);
  } finally { f.close(); }
});

test('login form requires exact Origin, nonce-bound synchronizer token and validated return path', async () => {
  const f = fixture();
  try {
    for (const value of ['//evil.test', '/\\evil.test', '//2130706433/', '/%2f%2fevil.test', '/<script>', '/\n']) {
      assert.equal((await f.call(`/login?return_to=${encodeURIComponent(value)}`)).status, 400);
    }
    const form = await f.form('/account');
    for (const headers of [{ Origin: 'https://other.example.test' }, { Origin: '' }, { Origin: 'null' }, { 'Sec-Fetch-Site': 'same-site' },
      { Cookie: '' }, { 'Content-Type': 'application/json' }]) assert.equal((await f.start(form, headers)).response.status, 403);
    assert.equal((await f.start({ ...form, csrf: 'bad' })).response.status, 403);
    assert.equal((await f.start({ ...form, returnTo: '/' })).response.status, 403);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM auth_requests').get().n, 0);
    assert.equal((await f.start(form)).response.status, 303);
  } finally { f.close(); }
});

test('login starts are limited atomically per hashed edge IP and the window resets', async () => {
  const f = fixture();
  try {
    for (let i = 0; i < 10; i++) assert.equal((await f.start()).response.status, 303);
    assert.equal((await f.start()).response.status, 429);
    f.now += 600; assert.equal((await f.start()).response.status, 303);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM login_rate_limits').get().n, 1);
  } finally { f.close(); }
});

test('only the login form permits GitHub form navigation and preserves the POST Origin', async () => {
  const f = fixture();
  try {
    const form = await f.form();
    assert.match(form.response.headers.get('Content-Security-Policy'), /form-action 'self' https:\/\/github\.com$/);
    assert.equal(form.response.headers.get('Referrer-Policy'), 'same-origin');
    const flow = await f.start(form);
    const callback = await f.callback(flow); assert.equal(callback.status, 303);
    for (const response of [flow.response, callback, await f.call('/missing'),
      await f.call('/login?return_to=//evil.test')]) {
      assert.match(response.headers.get('Content-Security-Policy'), /form-action 'self'$/);
      assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
    }
  } finally { f.close(); }
});

test('browser-bound cancellation consumes the flow, clears only pre-auth cookie and offers a retry', async () => {
  const f = fixture();
  try {
    const flow = await f.start();
    const path = `/auth/github/callback?state=${flow.state}&error=access_denied`;
    const unbound = await f.call(path); assert.equal(unbound.status, 400); assert.equal(unbound.headers.get('Set-Cookie'), null);
    assert.equal(f.db.prepare('SELECT used_at FROM auth_requests').get().used_at, null);
    const response = await f.call(path, { headers: { Cookie: flow.cookie } });
    assert.equal(response.status, 400); assert.match(response.headers.get('Content-Type'), /text\/html/);
    assert.match(await response.text(), /Sign-in was cancelled.*href="\/login">Try again/s);
    assert.deepEqual(response.headers.getSetCookie(), ['__Host-acct_oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0']);
    assert.equal(f.db.prepare('SELECT used_at FROM auth_requests').get().used_at, f.now);
    assert.equal((await f.callback(flow)).status, 400);
    assert.equal(f.exchangeCalls, 0); assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
    assert.match(response.headers.get('Content-Security-Policy'), /form-action 'self'$/);
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
  } finally { f.close(); }
});

test('rate-limit cleanup is bounded and removes only expired windows, including the exact boundary', async () => {
  const f = fixture();
  try {
    const insert = f.db.prepare('INSERT INTO login_rate_limits(bucket_hash,window_start,attempts) VALUES (?,?,1)');
    for (let i = 0; i < 101; i++) insert.run(`old-${i}`, f.now - 600);
    insert.run('active', f.now - 599);
    const store = new Store(f.env.IDENTITY);
    await store.rateLimit('fresh', f.now);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM login_rate_limits WHERE window_start<=?').get(f.now - 600).n, 1);
    assert.ok(f.db.prepare("SELECT bucket_hash FROM login_rate_limits WHERE bucket_hash='active'").get());
    await store.rateLimit('fresh', f.now);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM login_rate_limits WHERE window_start<=?').get(f.now - 600).n, 0);
    assert.equal(f.db.prepare("SELECT attempts FROM login_rate_limits WHERE bucket_hash='fresh'").get().attempts, 2);
  } finally { f.close(); }
});

test('session idle/absolute expiry, revocation and account status take effect on primary reads', async () => {
  const f = fixture();
  try {
    const done = await f.callback(await f.start()); const sid = cookie(done, '__Host-acct_sid'); const hash = sha(sid.split('=')[1]);
    const store = new Store(f.env.IDENTITY); const before = f.db.prepare('SELECT * FROM sessions').get();
    assert.ok(await store.validate(hash, f.now + 299)); assert.equal(f.db.prepare('SELECT last_seen_at FROM sessions').get().last_seen_at, f.now);
    assert.ok(await store.validate(hash, f.now + 300)); assert.equal(f.db.prepare('SELECT last_seen_at FROM sessions').get().last_seen_at, f.now + 300);
    assert.equal(await store.validate(hash, f.now + 300 + ACCOUNT_IDLE), null);
    assert.equal(await store.validate(hash, before.abs_expires_at), null);
    f.db.prepare("UPDATE users SET status='locked'").run(); assert.equal(await store.validate(hash, f.now), null);
    f.db.prepare("UPDATE users SET status='active'").run();
    f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test'").run(f.now); assert.equal(await store.validate(hash, f.now), null);
  } finally { f.close(); }
});

test('verified revocation webhooks reject replays and close the in-flight callback race', async () => {
  const f = fixture();
  try {
    const signedIn = await f.callback(await f.start()); const sid = cookie(signedIn, '__Host-acct_sid');
    const inFlight = await f.start();
    assert.equal((await f.webhook('bad', undefined, { 'X-Hub-Signature-256': `sha256=${'0'.repeat(64)}` })).status, 403);
    assert.equal(f.db.prepare('SELECT revoked_at FROM sessions').get().revoked_at, null);
    assert.equal((await f.webhook()).status, 204);
    assert.equal((await f.call('/', { headers: { Cookie: sid } })).status, 303);
    assert.equal((await f.webhook()).status, 409);
    assert.equal((await f.callback(inFlight)).status, 403);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1);
    f.now++; const newSession = await f.callback(await f.start()); assert.equal(newSession.status, 303);
    // A second real revocation may have identical payload bytes and a new delivery ID.
    assert.equal((await f.webhook('second-revocation')).status, 204);
    assert.equal((await f.call('/', { headers: { Cookie: cookie(newSession, '__Host-acct_sid') } })).status, 303);
  } finally { f.close(); }
});

test('disabled or incomplete configuration stays closed and invocation logging stays disabled', async () => {
  const f = fixture();
  try {
    assert.equal((await worker.fetch(new Request(`${origin}/login`))).status, 503);
    for (const patch of [{ IDENTITY: undefined }, { OAUTH_STATE_KEY: '' }, { GITHUB_APP_ID: '5559540' }, { GITHUB_WEBHOOK_SECRET: 'short' }]) {
      assert.equal((await f.app.fetch(new Request(`${origin}/login`), { ...f.env, ...patch })).status, 503);
    }
    for (const name of ['wrangler.json', 'wrangler.local.json']) {
      const config = JSON.parse(readFileSync(`workers/accounts/${name}`, 'utf8'));
      assert.equal(config.observability.enabled, false);
      for (const value of Object.values(config.env ?? {})) assert.equal(value.observability.enabled, false);
    }
  } finally { f.close(); }
});

test('encrypted verifier tampering fails before GitHub, and locked accounts cannot obtain new sessions', async () => {
  const f = fixture();
  try {
    const flow = await f.start();
    f.db.prepare("UPDATE auth_requests SET pkce_verifier_enc='tampered'").run();
    assert.notEqual((await f.callback(flow)).status, 303); assert.equal(f.exchangeCalls, 0);
    const signedIn = await f.callback(await f.start()); assert.equal(signedIn.status, 303);
    f.db.prepare("UPDATE users SET status='locked'").run();
    assert.equal((await f.callback(await f.start())).status, 403);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1);
  } finally { f.close(); }
});

test('GitHub adapter refuses redirects, malformed profiles and upstream errors without leaking credentials', async () => {
  const options = { clientId: 'id', clientSecret: 'secret', redirectUri: `${origin}/auth/github/callback` };
  for (const response of [new Response(null, { status: 302, headers: { Location: 'https://evil.test' } }),
    Response.json({ error: 'bad', access_token: rawToken }), Response.json({ token_type: 'mac', access_token: rawToken }),
    new Response(rawToken), Response.json({ token_type: 'bearer', access_token: 'bad\nvalue' }), new Response('x'.repeat(65_537))]) {
    let count = 0;
    const provider = new GitHubProvider({ ...options, fetch: async (_url, init) => { count++; assert.equal(init.redirect, 'manual'); return response; } });
    await assert.rejects(provider.exchange('code', 'verifier'), { message: 'provider_unavailable' });
    assert.equal(count, 1);
  }
  for (const profile of [null, [], { id: '123', login: 'user', name: null }, { id: Number.MAX_SAFE_INTEGER + 1, login: 'user', name: null },
    { id: 123, login: 'bad<script>', name: null }, { id: 123, login: 'user', name: {} }]) {
    const provider = new GitHubProvider({ ...options, fetch: async () => Response.json(profile) });
    await assert.rejects(provider.profile(rawToken), { message: 'provider_unavailable' });
  }
});
