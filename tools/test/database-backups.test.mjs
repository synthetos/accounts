import '../backups/test/backup.test.mjs';
import '../backups/test/remote.test.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { reviewedBackupWorkflow } from '../backups/workflow-policy.mjs';
test('only the byte-pinned nightly/dispatch protected main-branch backup workflow is reviewed', () => {
  const source = readFileSync(new URL('../../.github/workflows/database-backups.yml', import.meta.url), 'utf8');
  assert.ok(reviewedBackupWorkflow('database-backups.yml', source));
  for (const [before, after] of [['refs/heads/main', 'refs/heads/topic'], ['"environment": "production"', '"environment": "staging"'], ['"schedule"', '"pull_request_target"'], ['"workflow_dispatch"', '"push"'], ['node tools/backups/cli.mjs', 'echo unsafe'], ['CLOUDFLARE_D1_API_TOKEN', 'OTHER_SECRET'], ['"persist-credentials": false', '"persist-credentials": true'], ['"contents": "read"', '"contents": "write"']]) {
    assert.ok(source.includes(before)); assert.equal(reviewedBackupWorkflow('database-backups.yml', source.replace(before, after)), false);
  }
  assert.equal(reviewedBackupWorkflow('other.yml', source), false);
});

test('manual restore workflow is independently byte-pinned and cannot acquire a scheduled trigger', () => {
  const source = readFileSync(new URL('../../.github/workflows/database-restore.yml', import.meta.url), 'utf8');
  assert.ok(reviewedBackupWorkflow('database-restore.yml', source));
  for (const [before, after] of [['workflow_dispatch', 'schedule'], ["refs/heads/main", "refs/heads/topic"], ['"environment": "production"', '"environment": "staging"'], ['node tools/backups/restore-cli.mjs', 'echo unsafe']]) assert.equal(reviewedBackupWorkflow('database-restore.yml', source.replace(before, after)), false);
});
