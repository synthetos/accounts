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
    const inventory = JSON.stringify([{ path: root }, { path: join(root, 'packages/core') }]);
    writeFileSync(manifest, '{}');
    assert.equal(noRuntimeDependencies(root, inventory), true);
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      writeFileSync(manifest, JSON.stringify({ [field]: { unexpected: '1.0.0' } }));
      assert.equal(noRuntimeDependencies(root, inventory), false);
    }
    const gpl = { 'GPL-3.0-only': [{ name: 'unsafe-package', versions: ['1.0.0'] }] };
    assert.equal(checkReports({}, gpl).violations.length, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('empty licence reports fail closed for runtime dependencies in newly added workspaces', () => {
  const root = mkdtempSync(join(tmpdir(), 'accounts-workspaces-'));
  try {
    writeFileSync(join(root, 'package.json'), '{}');
    const paths = ['packages/core', 'workers/accounts', 'apps/new-client'].map((name) => join(root, name));
    for (const path of paths) {
      mkdirSync(path, { recursive: true });
      writeFileSync(join(path, 'package.json'), '{}');
    }
    const inventory = JSON.stringify(paths.map((path) => ({ path })));
    assert.equal(noRuntimeDependencies(root, inventory), true);
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      writeFileSync(join(paths[2], 'package.json'), JSON.stringify({ [field]: { unexpected: '1.0.0' } }));
      assert.throws(() => parsePnpmReport('No licenses in packages found', noRuntimeDependencies(root, inventory)));
    }
    writeFileSync(join(paths[2], 'package.json'), '{}');
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { rootDependency: '1.0.0' } }));
    assert.equal(noRuntimeDependencies(root, inventory), false);
    for (const bad of ['not-json', '{}', '[]', '[null]', '[{}]', '[{"path":"relative/path"}]']) {
      assert.throws(() => noRuntimeDependencies(root, bad));
    }
    writeFileSync(join(root, 'package.json'), '{}');
    assert.throws(() => noRuntimeDependencies(root, JSON.stringify([{ path: join(root, 'missing') }])));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
