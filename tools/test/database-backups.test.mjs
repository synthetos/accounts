import '../backups/test/provision-worker.test.mjs';
import '../backups/test/worker.test.mjs';
import '../backups/test/backup.test.mjs';
import '../backups/test/remote.test.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { reviewedBackupWorkflow } from '../backups/workflow-policy.mjs';
test('manual restore workflow is independently byte-pinned and cannot acquire a scheduled trigger', () => {
  const source = readFileSync(new URL('../../.github/workflows/database-restore.yml', import.meta.url), 'utf8');
  assert.ok(reviewedBackupWorkflow('database-restore.yml', source));
  for (const [before, after] of [['workflow_dispatch', 'schedule'], ["refs/heads/main", "refs/heads/topic"], ['"environment": "production"', '"environment": "staging"'], ['node tools/backups/restore-cli.mjs', 'echo unsafe']]) assert.equal(reviewedBackupWorkflow('database-restore.yml', source.replace(before, after)), false);
});

import { existsSync } from 'node:fs';
import { workerConfig, checkBackupConfig } from '../backups/worker-config.mjs';
test('private backup Worker exact bindings pass, all extra bindings or public routes fail', () => {
  assert.equal(existsSync('.github/workflows/database-backups.yml'), false);
  for (const environment of ['staging', 'production']) {
    const config = JSON.parse(readFileSync(`workers/backup/wrangler.${environment}.json`, 'utf8'));
    assert.ok(checkBackupConfig(config));
    const wrongScratch = structuredClone(config);
    wrongScratch.d1_databases.find(d => d.binding === 'SCRATCH').database_name = environment === 'staging' ? 'restore-test-accounts' : 'restore-test-accounts-staging';
    assert.equal(checkBackupConfig(wrongScratch), false);
    for (const patch of [{ workers_dev: true }, { preview_urls: true }, { routes: [{ pattern: 'backup.test', custom_domain: true }] }, { route: 'backup.test' }, { services: [] }, { kv_namespaces: [] }, { build: { command: 'false' } }, { d1_databases: [...config.d1_databases, config.d1_databases[0]] }, { r2_buckets: [{ binding: 'BACKUPS', bucket_name: 'other' }] }]) assert.equal(checkBackupConfig({ ...config, ...patch }), false);
    assert.equal(workerConfig(environment, '11111111-2222-4333-8444-555555555555', '66666666-7777-4888-9999-aaaaaaaaaaaa').workers_dev, false);
  }
});
test('backup deploy uses the normal protected attested jobs, never scheduled GitHub credentials', () => {
  const jobs = JSON.parse(readFileSync('.github/workflows/ci.yml', 'utf8')).jobs;
  for (const environment of ['staging', 'production']) {
    const job = jobs[`deploy-${environment}`];
    const provision = job.steps.findIndex(s => s.run === `node tools/backups/provision-worker.mjs ${environment}`);
    const deploy = job.steps.findIndex(s => s.run === 'ci/deploy-toolchain/node_modules/.bin/wrangler deploy --no-bundle --config payload/backup-wrangler.json');
    assert.ok(provision > job.steps.findIndex(s => s.name === 'Extract verified artifact'));
    assert.equal(deploy, provision + 1); assert.equal(job.environment, environment);
    assert.ok(job.needs.includes('attest')); assert.match(job.if, /refs\/heads\/main/);
  }
});
