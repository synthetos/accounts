import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { manifest, compare } from '../artifact.mjs';

test('artifact comparison rejects changed bytes, extra files, missing files and symlinks', () => {
  const root = mkdtempSync(join(tmpdir(), 'accounts-build-'));
  const a = join(root, 'a'), b = join(root, 'b');
  try {
    mkdirSync(a); mkdirSync(b);
    writeFileSync(join(a, 'worker.js'), 'export default {};');
    writeFileSync(join(b, 'worker.js'), 'export default {};');
    compare(a, b);
    writeFileSync(join(b, 'worker.js'), 'export default {}; // injected timestamp');
    assert.throws(() => compare(a, b), /Builds differ/);
    writeFileSync(join(b, 'worker.js'), 'export default {};');
    writeFileSync(join(b, 'extra.js'), 'extra');
    assert.throws(() => compare(a, b), /Builds differ/);
    rmSync(join(b, 'extra.js')); rmSync(join(b, 'worker.js'));
    assert.throws(() => compare(a, b), /Builds differ/);
    symlinkSync(join(a, 'worker.js'), join(b, 'worker.js'));
    assert.throws(() => manifest(b), /symlinks/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
