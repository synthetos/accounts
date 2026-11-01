import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parsePnpmReport, noRuntimeDependencies } from '../licence/reports.ts';
import { checkReports } from '../licence/policy.ts';

test('licence gate allows an empty production report only with no declared runtime dependencies', () => {
  assert.deepEqual(parsePnpmReport('No licenses in packages found\n', true), {});
  assert.throws(() => parsePnpmReport('No licenses in packages found', false));
  assert.throws(() => parsePnpmReport('Some unrelated pnpm error', true));
  assert.throws(() => checkReports({}, {}), /no installed packages/);
  const root = mkdtempSync(join(tmpdir(), 'accounts-licence-'));
  try {
    writeFileSync(join(root, 'package.json'), '{}');
    mkdirSync(join(root, 'packages/core'), { recursive: true });
    const manifest = join(root, 'packages/core/package.json');
    writeFileSync(manifest, '{}');
    assert.equal(noRuntimeDependencies(root), true);
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      writeFileSync(manifest, JSON.stringify({ [field]: { unexpected: '1.0.0' } }));
      assert.equal(noRuntimeDependencies(root), false);
    }
    const gpl = { 'GPL-3.0-only': [{ name: 'unsafe-package', versions: ['1.0.0'] }] };
    assert.equal(checkReports({}, gpl).violations.length, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
