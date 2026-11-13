import { test } from 'node:test';
import assert from 'node:assert/strict';
import { provisionWorker } from '../provision-worker.mjs';
import { workerConfig, checkBackupConfig } from '../worker-config.mjs';
import { REPO } from '../config.mjs';
import { LIFECYCLE } from '../bucket.mjs';
test('provisions only scratch, preserves source, and pins every private binding', async () => {
  const source = '11111111-2222-4333-8444-555555555555', scratch = '66666666-7777-4888-9999-aaaaaaaaaaaa';
  const calls = [];
  const r2 = async path => ({ result: path.endsWith('/managed') ? { enabled: false } : path.endsWith('/custom') ? { domains: [] } : path.endsWith('/lifecycle') ? LIFECYCLE : {} });
  const d1 = async (path, method = 'GET', body) => {
    calls.push([path, method, body]);
    if (method === 'POST') { assert.equal(body.name, `restore-test-${REPO}`); return { result: { uuid: scratch } }; }
    return { result: [{ name: REPO === 'run' ? 'run-auth' : 'identity', uuid: source }] };
  };
  const config = await provisionWorker('production', 'a'.repeat(32), d1, r2);
  assert.ok(checkBackupConfig(config));
  assert.deepEqual(config.d1_databases.map(d => d.database_id), [source, scratch]);
  assert.equal(calls.filter(c => c[1] === 'POST').length, 1);
  assert.throws(() => workerConfig('production', source, source), /differ/);
  await assert.rejects(provisionWorker('production', 'a'.repeat(32), async () => ({ result: [] }), r2), /missing/);
});

test('environment-specific scratch bindings and cron offsets are exact', () => {
  for (const environment of ['staging', 'production']) {
    const suffix = environment === 'staging' ? '-staging' : '';
    const config = workerConfig(environment, 'SOURCE_DATABASE_ID', 'SCRATCH_DATABASE_ID');
    assert.equal(config.d1_databases[1].database_name, `restore-test-${REPO}${suffix}`);
    assert.deepEqual(config.triggers.crons, [`${(REPO === 'accounts' ? 45 : 50) - (environment === 'staging' ? 15 : 0)} 7 * * *`]);
    const wrong = structuredClone(config);
    wrong.d1_databases[1].database_name = `restore-test-${REPO}${suffix ? '' : '-staging'}`;
    assert.equal(checkBackupConfig(wrong), false);
    assert.equal(checkBackupConfig({ ...config, triggers: { crons: ['0 0 * * *'] } }), false);
  }
});
