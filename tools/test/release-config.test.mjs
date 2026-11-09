// A1-07 release configuration: the deploy preflight, the per-environment run relying-party registration,
// and the deploy jobs that run them before any migration or deploy.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { DATABASE_NAMES, HOSTS, preflightFindings } from '../deploy-preflight.mjs';

const committed = () => JSON.parse(readFileSync('workers/accounts/wrangler.json', 'utf8'));
const STAGING_DB = '66666666-7777-4888-9999-aaaaaaaaaaaa';
const PRODUCTION_DB = '11111111-2222-4333-8444-555555555555';

function filled() {
  const config = committed();
  config.d1_databases[0].database_id = PRODUCTION_DB;
  config.env.staging.d1_databases[0].database_id = STAGING_DB;
  config.env.staging.vars.GITHUB_APP_ID = '7000001';
  config.env.staging.vars.GITHUB_CLIENT_ID = 'Iv23liSTAGINGclient1';
  return config;
}

test('the committed configuration is refused until the owner fills in what only the owner can create', () => {
  const staging = preflightFindings(committed(), 'staging');
  assert.ok(staging.some((f) => f.includes('identity-staging')), staging.join('\n'));
  assert.ok(staging.some((f) => f.includes('GITHUB_APP_ID')));
  assert.ok(staging.some((f) => f.includes('GITHUB_CLIENT_ID')));
  const production = preflightFindings(committed(), 'production');
  assert.deepEqual(production.map((f) => f.includes('database_id')), [true]);
});

test('filled in, both environments pass, each with its own host, database and origin', () => {
  for (const env of ['staging', 'production']) assert.deepEqual(preflightFindings(filled(), env), [], env);
  const config = filled();
  assert.equal(config.vars.ACCOUNT_ORIGIN, `https://${HOSTS.production}`);
  assert.equal(config.env.staging.vars.ACCOUNT_ORIGIN, `https://${HOSTS.staging}`);
  assert.equal(config.env.staging.d1_databases[0].database_name, DATABASE_NAMES.staging);
});

test('D37: the allowlist is the owner\'s numeric GitHub id only, and an empty or malformed one is refused', () => {
  const config = filled();
  assert.equal(config.vars.GITHUB_ALLOWED_IDS, '["231731"]');
  assert.equal(config.env.staging.vars.GITHUB_ALLOWED_IDS, '["231731"]');
  for (const bad of ['[]', '["ril3y"]', '[231731]', 'not json', '["0123"]']) {
    const c = filled();
    c.env.staging.vars.GITHUB_ALLOWED_IDS = bad;
    assert.ok(preflightFindings(c, 'staging').some((f) => f.includes('GITHUB_ALLOWED_IDS')), bad);
  }
});

test('staging never reuses the production app; the forum app and a wrong host are refused', () => {
  const a = filled();
  a.env.staging.vars.GITHUB_APP_ID = '5562809';
  a.env.staging.vars.GITHUB_CLIENT_ID = a.vars.GITHUB_CLIENT_ID;
  const findings = preflightFindings(a, 'staging');
  assert.ok(findings.some((f) => f.includes('separate staging app')));
  assert.ok(findings.some((f) => f.includes('client id') || f.includes('GITHUB_CLIENT_ID')));
  const b = filled();
  b.vars.GITHUB_APP_ID = '5559540';
  assert.ok(preflightFindings(b, 'production').some((f) => f.includes('GITHUB_APP_ID')));
  const c = filled();
  c.env.staging.routes = [{ pattern: 'accounts.synthetos.com', custom_domain: true }];
  c.env.staging.workers_dev = true;
  assert.ok(preflightFindings(c, 'staging').some((f) => f.includes('routes')));
  assert.ok(preflightFindings(c, 'staging').some((f) => f.includes('workers_dev')));
});

function identityDb() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of readdirSync('migrations').filter((n) => n.endsWith('.sql')).sort()) db.exec(readFileSync(`migrations/${name}`, 'utf8'));
  return db;
}

test('each environment registers exactly one run binding client with its own exact callback, idempotently', () => {
  for (const [env, host] of [['staging', 'staging.run.synthetos.com'], ['production', 'run.synthetos.com']]) {
    const db = identityDb();
    const sql = readFileSync(`clients/${env}.sql`, 'utf8');
    db.exec(sql);
    db.exec(sql);
    const rows = db.prepare("SELECT id,kind,redirect_uris_json,secret_hash FROM oauth_clients WHERE id='run'").all();
    assert.deepEqual(rows.map((r) => ({ ...r })), [{ id: 'run', kind: 'binding', redirect_uris_json: `["https://${host}/auth/callback"]`, secret_hash: null }]);
    assert.doesNotMatch(sql, env === 'staging' ? /"https:\/\/run\.synthetos\.com/ : /staging/);
  }
});

test('the deploy jobs run the preflight before migrations, and register the client after them, before the deploy', () => {
  const { jobs } = JSON.parse(readFileSync('.github/workflows/ci.yml', 'utf8'));
  for (const [name, env] of [['deploy-staging', 'staging'], ['deploy-production', 'production']]) {
    const runs = jobs[name].steps.map((s) => s.run ?? '');
    const at = (needle) => runs.findIndex((r) => r.includes(needle));
    const preflight = at(`node tools/deploy-preflight.mjs payload/wrangler.json ${env}`);
    const migrate = at('d1 migrations apply IDENTITY --remote --config payload/wrangler.json');
    const register = at(`--file payload/clients/${env}.sql`);
    const deploy = at('wrangler deploy --no-bundle --config payload/wrangler.json');
    assert.ok(preflight > 0 && preflight < migrate && migrate < register && register < deploy, name);
  }
  assert.match(readFileSync('tools/build.mjs', 'utf8'), /cpSync\('clients'/);
});
