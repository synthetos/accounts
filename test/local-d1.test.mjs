import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

test('Wrangler local D1 applies migrations and enforces identity uniqueness and audit retention', { timeout: 90_000 }, () => {
  const root = mkdtempSync(join(tmpdir(), 'accounts-d1-'));
  const wrangler = resolve('ci/deploy-toolchain/node_modules/wrangler/bin/wrangler.js');
  function cli(args) {
    return spawnSync(process.execPath, [wrangler, 'd1', ...args, 'identity', '--local',
      '--config', resolve('workers/accounts/wrangler.local.json'), '--persist-to', join(root, 'state')], {
      encoding: 'utf8', timeout: 25_000,
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: join(root, 'wrangler.log') },
    });
  }
  const pass = (result) => assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  try {
    pass(cli(['migrations', 'apply']));
    pass(cli(['migrations', 'apply'])); // ledger makes repeated application a no-op
    pass(cli(['execute', '--file', resolve('test/fixtures/identity.sql')]));
    const duplicate = cli(['execute', '--command', `INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at)
      VALUES ('duplicate','usr_01ARZ3NDEKTSV4RRFFQ69G5FAW','github','100000001','duplicate',1000)`]);
    assert.notEqual(duplicate.status, 0);
    assert.match(duplicate.stdout + duplicate.stderr, /UNIQUE constraint failed/);
    pass(cli(['execute', '--command', `INSERT INTO security_audit(id,at,event) VALUES
      ('recent',CAST(strftime('%s','now') AS INTEGER),'test'), ('old',1,'test')`]));
    for (const command of ["DELETE FROM security_audit WHERE id='recent'", "UPDATE security_audit SET at=0 WHERE id='old'"]) {
      const denied = cli(['execute', '--command', command]);
      assert.notEqual(denied.status, 0);
      assert.match(denied.stdout + denied.stderr, /append-only/);
    }
    pass(cli(['execute', '--command', "DELETE FROM security_audit WHERE at < CAST(strftime('%s','now') AS INTEGER) - 31536000"]));
    const retained = cli(['execute', '--command', 'SELECT id FROM security_audit ORDER BY id', '--json']);
    pass(retained);
    assert.deepEqual(JSON.parse(retained.stdout)[0].results, [{ id: 'recent' }]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
