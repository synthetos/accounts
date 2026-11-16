import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runMutation } from '../mutation/run.mjs';
import { contextHash } from '../mutation/context.mjs';
import { summarize, issueBody } from '../mutation/summary.mjs';

function fixture(t) {
  const base = 'node_modules/.cache'; mkdirSync(base, { recursive: true });
  const cwd = mkdtempSync(join(base, 'mutation-test-'));
  execFileSync('git', ['init', '-q', cwd]);
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const put = (name, text) => { const path = join(cwd, name); mkdirSync(join(path, '..'), { recursive: true }); writeFileSync(path, text); };
  put('packages/auth-core/test/a.test.mjs', 'test'); put('packages/auth-core/src/a.ts', 'source');
  const calls = [];
  const report = statuses => ({ files: Object.fromEntries(['packages/auth-core', 'packages/idp', 'workers/accounts'].map(name => [name + '/src/a.ts', { mutants: statuses.map(status => ({ status, location: { start: { line: 1, column: 0 } }, mutatorName: 'BooleanLiteral', replacement: 'false' })) }])) });
  const execute = (_node, args) => { calls.push(args); put('reports/release-mutation.json', JSON.stringify(report(['Killed']))); put('reports/stryker-incremental.json', '{}'); return { status: 0 }; };
  const options = { cwd, execute, env: { GITHUB_OUTPUT: join(cwd, 'reports/github-output') } };
  return { cwd, put, calls, report, options };
}

test('cold quick run is full, warm quick reuses, explicit full ignores cached report', t => {
  const f = fixture(t);
  assert.equal(runMutation('quick', f.options), 0); assert.ok(f.calls[0].includes('--force'));
  assert.equal(runMutation('quick', f.options), 0); assert.ok(!f.calls[1].includes('--force'));
  assert.equal(runMutation('full', f.options), 0); assert.ok(f.calls[2].includes('--force'));
  assert.ok(f.calls.every(args => args.includes('--incremental')));
});
test('mutated source edits are delegated to Stryker’s diff rather than discarding the report', t => {
  const f = fixture(t); runMutation('quick', f.options);
  f.put('packages/auth-core/src/a.ts', 'changed'); runMutation('quick', f.options);
  assert.ok(!f.calls[1].includes('--force'));
});
for (const file of ['packages/auth-core/test/a.test.mjs', 'workers/accounts/test/helper.mjs', 'pnpm-lock.yaml', 'stryker.config.json', 'workers/accounts/src/types.d.ts', 'packages/idp/package.json']) {
  test(`changing ${file} invalidates all cached results with the command runner`, t => {
    const f = fixture(t); runMutation('quick', f.options); f.put(file, 'changed');
    runMutation('quick', f.options); assert.ok(f.calls[1].includes('--force'));
  });
}
test('removed tracked tests also invalidate the cache', t => {
  const f = fixture(t); execFileSync('git', ['add', '.'], { cwd: f.cwd });
  const before = contextHash(f.cwd); rmSync(join(f.cwd, 'packages/auth-core/test/a.test.mjs'));
  assert.notEqual(contextHash(f.cwd), before);
});
test('adding a migration after a warm quick run forces a full run', t => {
  const f = fixture(t); runMutation('quick', f.options); runMutation('quick', f.options);
  assert.ok(!f.calls[1].includes('--force'));
  f.put('migrations/0009_example.sql', 'CREATE TABLE example (id TEXT PRIMARY KEY);');
  runMutation('quick', f.options);
  assert.ok(f.calls[2].includes('--force'));
});
for (const action of ['change', 'delete']) {
  test(`${action} of a tracked migration invalidates warm results`, t => {
    const f = fixture(t); const file = 'migrations/0009_example.sql';
    f.put(file, 'CREATE TABLE example (id TEXT PRIMARY KEY);');
    execFileSync('git', ['add', file], { cwd: f.cwd });
    runMutation('quick', f.options); runMutation('quick', f.options);
    assert.ok(!f.calls[1].includes('--force'));
    if (action === 'change') f.put(file, 'CREATE TABLE example (id INTEGER PRIMARY KEY);');
    else rmSync(join(f.cwd, file));
    runMutation('quick', f.options);
    assert.ok(f.calls[2].includes('--force'));
  });
}
for (const file of ['tools/backups/backup.mjs', 'tools/backups/archive.mjs', 'future-test-inputs/schema.json']) {
  test(`changing repository input ${file} invalidates warm results`, t => {
    const f = fixture(t); f.put(file, 'before'); runMutation('quick', f.options);
    f.put(file, 'after'); runMutation('quick', f.options);
    assert.ok(f.calls[1].includes('--force'));
  });
}
for (const file of ['node_modules/example/index.js', 'packages/auth-core/dist/index.js', 'reports/generated.json', '.git/description']) {
  test(`generated or repository metadata ${file} does not invalidate warm results`, t => {
    const f = fixture(t); f.put(file, 'before');
    if (!file.startsWith('.git/')) execFileSync('git', ['add', '-f', file], { cwd: f.cwd });
    runMutation('quick', f.options); f.put(file, 'after'); runMutation('quick', f.options);
    assert.ok(!f.calls[1].includes('--force'));
  });
}
test('missing context forces a full run even with a report', t => {
  const f = fixture(t); f.put('reports/stryker-incremental.json', '{}'); runMutation('quick', f.options);
  assert.ok(f.calls[0].includes('--force'));
});
test('below-floor complete run stays failed but refreshes reusable results and exposes issue output', t => {
  const f = fixture(t);
  f.options.execute = () => { f.put('reports/release-mutation.json', JSON.stringify(f.report(['Survived']))); f.put('reports/stryker-incremental.json', '{}'); return { status: 1 }; };
  assert.equal(runMutation('full', f.options), 1);
  assert.match(readFileSync(join(f.cwd, 'reports/github-output'), 'utf8'), /below=true\ncacheable=true/);
  assert.match(readFileSync(join(f.cwd, 'reports/mutation-issue.md'), 'utf8'), /BooleanLiteral/);
});
test('failed runner cannot reuse a stale release report or publish a reusable context', t => {
  const f = fixture(t); runMutation('quick', f.options);
  assert.throws(() => runMutation('quick', { ...f.options, execute: () => ({ status: 1 }) }), /fresh report/);
  assert.equal(existsSync(join(f.cwd, 'reports/mutation-context.txt')), false);
});
test('unresolved mutants cannot be cached as complete', t => {
  const f = fixture(t); f.options.execute = () => { f.put('reports/release-mutation.json', JSON.stringify(f.report(['RuntimeError']))); return { status: 1 }; };
  assert.throws(() => runMutation('quick', f.options), /Unresolved/);
  assert.equal(existsSync(join(f.cwd, 'reports/mutation-context.txt')), false);
});
test('score summary preserves the unrounded 90 floor and all survivor details', t => {
  const f = fixture(t);
  assert.equal(summarize(f.report([...Array(9).fill('Killed'), 'NoCoverage'])).below, false);
  const summary = summarize(f.report([...Array(8).fill('Killed'), 'Survived', 'NoCoverage']));
  assert.equal(summary.below, true); assert.equal(summary.survivors.length, 6);
  const body = issueBody(summary, 'https://github.com/example/repo/actions/runs/1');
  assert.match(body, /80\.00/); assert.match(body, /"replacement":"false"/); assert.match(body, /"line":1/);
});
test('oversized issue lists link to full report rather than exceeding GitHub limits', t => {
  const f = fixture(t); const summary = summarize(f.report(Array(1000).fill('Survived')));
  const body = issueBody(summary, 'https://github.com/example/repo/actions/runs/1');
  assert.ok(body.length < 60000); assert.match(body, /List truncated/);
});
