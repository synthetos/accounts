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

test('run-staging gets only its two generated sign-in keys', async () => {
  const { fn, puts } = stub([]);
  const r = await setMissingSecrets('run-staging', { CLOUDFLARE_API_TOKEN: 't', CLOUDFLARE_ACCOUNT_ID: 'acc' }, fn);
  assert.deepEqual(r.set, ['RUN_STATE_KEY', 'RUN_RATE_KEY']);
  assert.ok(puts.every((p) => p.url.endsWith('/workers/scripts/run-staging/secrets') && /^[A-Za-z0-9_-]{43}$/.test(p.text)));
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
  assert.equal(withToken[0].run, 'node tools/worker-secrets.mjs "$WORKER"');
  assert.equal(withToken[0].env.WORKER, '${{ inputs.worker }}');
  assert.deepEqual(wf.on.workflow_dispatch.inputs.worker.options, Object.keys(PLANS).filter(name => name.endsWith('-staging')));
  assert.equal(wf.on.workflow_dispatch.inputs.worker.type, 'choice');
  assert.equal(withToken[0].env.GITHUB_CLIENT_SECRET, '${{ secrets.APP_CLIENT_SECRET }}');
  assert.doesNotMatch(JSON.stringify(wf), /production/);
});

test('production uses only supplied production values, keeps existing secrets, and never generates a fallback', async () => {
  for (const script of ['accounts', 'run']) {
    const values = Object.fromEntries(Object.keys(PLANS[script]).map(name => [name, `production-${name}`]));
    const { fn, puts } = stub([]);
    const result = await setMissingSecrets(script, { ...env, ...values }, fn);
    assert.deepEqual(result.problems, []);
    assert.equal(puts.length, Object.keys(values).length);
    for (const put of puts) { assert.equal(put.text, values[put.name]); assert.ok(put.url.endsWith(`/workers/scripts/${script}/secrets`)); }
    const missing = stub([]);
    const refused = await setMissingSecrets(script, { CLOUDFLARE_API_TOKEN: 't', CLOUDFLARE_ACCOUNT_ID: 'acc' }, missing.fn);
    assert.equal(refused.problems.length, Object.keys(values).length); assert.equal(missing.puts.length, 0);
    const kept = stub(Object.keys(values));
    assert.deepEqual((await setMissingSecrets(script, env, kept.fn)).problems, []); assert.equal(kept.puts.length, 0);
  }
});
test('production-secrets is manual, main-only, production protected, with scoped environment secrets and no output of values', () => {
  const wf = JSON.parse(readFileSync('.github/workflows/production-secrets.yml', 'utf8'));
  assert.deepEqual(Object.keys(wf.on), ['workflow_dispatch']);
  assert.deepEqual(wf.on.workflow_dispatch.inputs.worker.options, ['accounts', 'run']);
  const job = wf.jobs['set-production-secrets'];
  assert.equal(job.environment, 'production'); assert.equal(job.if, "github.ref == 'refs/heads/main'");
  assert.deepEqual(job.permissions, { contents: 'read' });
  assert.equal(job.steps.length, 4);
  for (const step of job.steps.slice(0, 2)) { assert.match(step.uses, /@[0-9a-f]{40}$/); assert.doesNotMatch(JSON.stringify(step), /secrets/); }
  for (const [index, script] of ['accounts', 'run'].entries()) {
    const step = job.steps[index + 2];
    assert.equal(step.if, `inputs.worker == '${script}'`);
    assert.equal(step.run, 'node tools/worker-secrets.mjs "$WORKER"');
    assert.deepEqual(Object.keys(step.env).sort(), ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'WORKER', ...Object.keys(PLANS[script])].sort());
    for (const key of Object.keys(PLANS[script])) assert.match(step.env[key], /^\$\{\{ secrets\.[A-Z_]+ \}\}$/);
  }
  assert.doesNotMatch(JSON.stringify(wf), /staging|echo|printenv/);
});
