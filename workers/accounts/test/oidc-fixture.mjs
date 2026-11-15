import assert from 'node:assert/strict';
import { fixture, sha } from './fixture.mjs';
import { Store } from '../src/store.ts';
import { runRpc } from '../src/rpc.ts';
import { randomToken, createPkce } from '../../../packages/auth-core/src/index.ts';

const runRedirect = 'https://run.example.test/auth/callback';
const forumRedirect = 'https://forum.example.test/auth/callback';
async function setup() {
  const f = fixture();
  f.env.GITHUB_ALLOWED_IDS = '[]'; f.env.OPEN_SIGNUP = 'true';
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
  f.env.ID_TOKEN_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', keys.privateKey));
  f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding',?)").run(JSON.stringify([runRedirect]));
  f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES ('forum-synthetos','Forum','confidential',?,?)")
    .run(JSON.stringify([forumRedirect]), sha('forum-secret'));
  f.accountToken = randomToken();
  await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS, true).signIn('github', { subject: '12345', login: 'alice', displayName: 'Alice', avatarUrl: null }, sha(f.accountToken), f.now, f.now);
  f.accountCookie = `__Host-acct_sid=${f.accountToken}`;
  f.rpc = () => runRpc(f.env, f.now);
  f.params = async (client = 'run') => {
    const pkce = await createPkce();
    return { pkce, params: new URLSearchParams({ response_type: 'code', scope: 'openid', client_id: client,
      redirect_uri: client === 'run' ? runRedirect : forumRedirect, state: randomToken(), nonce: randomToken(), code_challenge: pkce.challenge, code_challenge_method: 'S256' }) };
  };
  f.authorize = async (client = 'run') => {
    const flow = await f.params(client);
    const response = await f.call(`/authorize?${flow.params}`, { headers: { Cookie: f.accountCookie } });
    assert.equal(response.status, 303, await response.clone().text());
    return { ...flow, response, code: new URL(response.headers.get('Location')).searchParams.get('code') };
  };
  f.exchange = (flow, context = {}) => f.rpc().exchangeCode(flow.code, flow.pkce.verifier, { redirectUri: runRedirect, deviceRecordId: 'device_fixture', ...context });
  f.forumExchange = (flow, patch = {}, header = {}) => f.call('/token', { method: 'POST', headers: {
    'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${btoa('forum-synthetos:forum-secret')}`, ...header },
  body: new URLSearchParams({ grant_type: 'authorization_code', code: flow.code, code_verifier: flow.pkce.verifier, redirect_uri: forumRedirect, ...patch }) });
  return f;
}

export { setup, runRedirect, forumRedirect };
