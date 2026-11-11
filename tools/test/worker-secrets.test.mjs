import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { PLANS, randomKey, setMissingSecrets, signingJwk } from '../worker-secrets.mjs';

const env = { CLOUDFLARE_API_TOKEN: 't', CLOUDFLARE_ACCOUNT_ID: 'acc', GITHUB_CLIENT_SECRET: 'client-secret' };
const stub = (existing, { listStatus = 200, putStatus = 200 } = {}) => {
  const puts = [];
  const fn = async (url, init = {}) => {
    if ((init.method ?? 'GET') === 'GET') return Response.json({ success: listStatus === 200, result: existing.map((name) => ({ name })) }, { status: listStatus });
    puts.push({ url, ...JSON.parse(init.body) });
    return Response.json({ success: putStatus === 200 }, { status: putStatus });
  };
  return { fn, puts };
};

test('generated keys are 32 random bytes in base64url, and the signing key is a private P-256 JWK', () => {
  const k = randomKey();
  assert.match(k, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(randomKey(), k);
  const jwk = JSON.parse(signingJwk());
  assert.equal(jwk.kty, 'EC');
  assert.equal(jwk.crv, 'P-256');
  assert.equal(typeof jwk.d, 'string');
});

test('only missing secrets are set; existing ones are left alone so sessions survive a rerun', async () => {
  const { fn, puts } = stub(['FORM_KEY', 'RATE_KEY']);
  const r = await setMissingSecrets('accounts-staging', env, fn);
  assert.deepEqual(r.kept, ['FORM_KEY', 'RATE_KEY']);
  assert.deepEqual(r.set.sort(), ['GITHUB_CLIENT_SECRET', 'GITHUB_WEBHOOK_SECRET', 'ID_TOKEN_PRIVATE_JWK', 'OAUTH_STATE_KEY']);
  assert.deepEqual(r.problems, []);
  assert.ok(puts.every((p) => p.url === 'https://api.cloudflare.com/client/v4/accounts/acc/workers/scripts/accounts-staging/secrets' && p.type === 'secret_text'));
  assert.equal(puts.find((p) => p.name === 'GITHUB_CLIENT_SECRET').text, 'client-secret');
  assert.equal(new Set(puts.map((p) => p.text)).size, puts.length);
});

test('a missing outside value, an unknown Worker, missing credentials, and API refusals are reported, by name only', async () => {
  const noClient = await setMissingSecrets('accounts-staging', { ...env, GITHUB_CLIENT_SECRET: '' }, stub([]).fn);
  assert.match(noClient.problems.join(), /GITHUB_CLIENT_SECRET is missing/);
  assert.equal(noClient.set.length, 5);
  assert.match((await setMissingSecrets('nope', env, stub([]).fn)).problems.join(), /no secret plan/);
  assert.match((await setMissingSecrets('accounts-staging', {}, stub([]).fn)).problems.join(), /CLOUDFLARE_API_TOKEN is not set/);
  assert.match((await setMissingSecrets('accounts-staging', env, stub([], { listStatus: 404 }).fn)).problems.join(), /could not list the secrets of accounts-staging/);
  const refused = await setMissingSecrets('accounts-staging', env, stub([], { putStatus: 403 }).fn);
  assert.equal(refused.set.length, 0);
  assert.ok(refused.problems.every((p) => !p.includes('client-secret')));
});

test('the plan covers every secret the accounts Worker requires', () => {
  const app = ['app.ts', 'oidc.ts'].map((f) => readFileSync(`workers/accounts/src/${f}`, 'utf8')).join('\n');
  for (const name of Object.keys(PLANS['accounts-staging'])) assert.match(app, new RegExp(`env\\.${name}\\b`));
});

test('the staging-secrets workflow is manual, staging-only, and gives the token only to the one step', () => {
  const wf = JSON.parse(readFileSync('.github/workflows/staging-secrets.yml', 'utf8'));
  assert.deepEqual(Object.keys(wf.on), ['workflow_dispatch']);
  const job = wf.jobs['set-staging-secrets'];
  assert.equal(job.environment, 'staging');
  const withToken = job.steps.filter((s) => JSON.stringify(s).includes('CLOUDFLARE_API_TOKEN'));
  assert.equal(withToken.length, 1);
  assert.equal(withToken[0].run, 'node tools/worker-secrets.mjs accounts-staging');
  assert.doesNotMatch(JSON.stringify(wf), /production/);
});
