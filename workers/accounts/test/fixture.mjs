import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { createApp } from '../src/app.ts';
import { GitHubProvider } from '../../../packages/idp/src/index.ts';

const origin = 'https://accounts.example.test';
const rawToken = 'ghu_fixture_secret_token';
const refreshToken = 'ghr_fixture_secret_refresh';
const sha = (value) => createHash('sha256').update(value).digest('hex');
const cookie = (response, name) => response.headers.getSetCookie().find((s) => s.startsWith(`${name}=`))?.split(';')[0];

function fixture() {
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync('migrations').filter((s) => s.endsWith('.sql')).sort()) db.exec(readFileSync(`migrations/${name}`, 'utf8'));
  let primaryReads = 0;
  const adapter = {
    prepare(sql) {
      const statement = db.prepare(sql); let values = [];
      return { bind(...bound) { values = bound; return this; },
        async first() { return statement.get(...values) ?? null; },
        async run() { return this.execute(); },
        execute() { return { meta: { changes: Number(statement.run(...values).changes) } }; },
      };
    },
    async batch(statements) {
      db.exec('BEGIN');
      try { const results = statements.map((s) => s.execute()); db.exec('COMMIT'); return results; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    },
  };
  const identity = { withSession(mode) { assert.equal(mode, 'first-primary'); primaryReads++; return adapter; } };
  const env = { AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
    GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-client-secret',
    OAUTH_STATE_KEY: Buffer.alloc(32, 1).toString('base64url'), FORM_KEY: Buffer.alloc(32, 2).toString('base64url'),
    RATE_KEY: Buffer.alloc(32, 3).toString('base64url'), GITHUB_WEBHOOK_SECRET: 'fixture-webhook-secret-long-enough', IDENTITY: identity };
  let now = 2_000_000_000; let expectedChallenge; let exchangeCalls = 0; let profileCalls = 0; let failure = false;
  let profile = { id: 12345, login: 'fixture-user', name: 'Fixture User', avatar_url: 'https://avatars.githubusercontent.com/u/12345', email: 'must-discard@example.test' };
  const outbound = [];
  const provider = new GitHubProvider({ clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET,
    redirectUri: `${origin}/auth/github/callback`, fetch: async (url, options) => {
      outbound.push({ url, options });
      assert.equal(options.redirect, 'manual'); assert.ok(options.signal instanceof AbortSignal);
      if (url === 'https://github.com/login/oauth/access_token') {
        exchangeCalls++;
        const body = new URLSearchParams(options.body);
        assert.equal(body.get('client_secret'), env.GITHUB_CLIENT_SECRET);
        assert.equal(body.get('redirect_uri'), `${origin}/auth/github/callback`);
        const challenge = createHash('sha256').update(body.get('code_verifier')).digest('base64url');
        if (failure || body.get('code') !== 'fixture-code' || challenge !== expectedChallenge) {
          return Response.json({ error: 'bad_verification_code', error_description: `${rawToken} DO NOT ECHO` }, { status: 400 });
        }
        return Response.json({ token_type: 'bearer', access_token: rawToken, refresh_token: refreshToken });
      }
      assert.equal(url, 'https://api.github.com/user'); profileCalls++;
      assert.equal(options.headers.Authorization, `Bearer ${rawToken}`);
      return Response.json(profile);
    } });
  const app = createApp({ provider, now: () => now });
  const call = (path, init = {}) => app.fetch(new Request(`${origin}${path}`, init), env);
  async function form(returnTo = '/') {
    const response = await call(`/login?return_to=${encodeURIComponent(returnTo)}`); assert.equal(response.status, 200);
    const html = await response.text();
    return { cookie: cookie(response, '__Host-acct_oauth'), csrf: html.match(/name="csrf" value="([^"]+)"/)[1], returnTo, response };
  }
  async function start(input = undefined, headerPatch = {}) {
    const f = input ?? await form();
    const response = await call('/login', { method: 'POST', headers: { Cookie: f.cookie, Origin: origin,
      'Sec-Fetch-Site': 'same-origin', 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '192.0.2.1', ...headerPatch },
    body: new URLSearchParams({ csrf: f.csrf, return_to: f.returnTo }) });
    if (response.status !== 303) return { response };
    const authorization = new URL(response.headers.get('Location'));
    expectedChallenge = authorization.searchParams.get('code_challenge');
    return { response, authorization, state: authorization.searchParams.get('state'), cookie: cookie(response, '__Host-acct_oauth') };
  }
  const callback = (flow, patch = {}) => call(`/auth/github/callback?${new URLSearchParams({ state: flow.state, code: 'fixture-code', ...patch })}`, { headers: flow.cookie ? { Cookie: flow.cookie } : {} });
  function webhook(delivery = 'delivery-1', body = JSON.stringify({ action: 'revoked', sender: { id: profile.id } }), headers = {}) {
    const signature = createHmac('sha256', env.GITHUB_WEBHOOK_SECRET).update(body).digest('hex');
    return call('/webhooks/github', { method: 'POST', body, headers: { 'Content-Type': 'application/json',
      'X-Hub-Signature-256': `sha256=${signature}`, 'X-GitHub-Event': 'github_app_authorization', 'X-GitHub-Delivery': delivery, ...headers } });
  }
  return { db, env, app, call, form, start, callback, webhook, outbound, close: () => db.close(),
    get now() { return now; }, set now(value) { now = value; }, set profile(value) { profile = value; },
    set failure(value) { failure = value; }, get primaryReads() { return primaryReads; },
    get exchangeCalls() { return exchangeCalls; }, get profileCalls() { return profileCalls; } };
}

export { fixture, origin, sha, cookie, rawToken, refreshToken };
