import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const read = file => JSON.parse(readFileSync(file, 'utf8'));
const ci = read('.github/workflows/ci.yml'), weekly = read('.github/workflows/mutation.yml');
const cacheFiles = 'reports/stryker-incremental.json\nreports/mutation-context.txt';

for (const [name, job] of [['push', ci.jobs.verify], ['weekly', weekly.jobs.mutation]]) {
  test(`${name} restores before mutation and saves only completed main results afterward`, () => {
    const restore = job.steps.findIndex(s => s.uses?.startsWith('actions/cache/restore@'));
    const run = job.steps.findIndex(s => s.id === 'mutation');
    const save = job.steps.findIndex(s => s.uses?.startsWith('actions/cache/save@'));
    assert.ok(restore < run && run < save);
    assert.equal(job.steps[restore].with.path, cacheFiles); assert.equal(job.steps[save].with.path, cacheFiles);
    assert.equal(job.steps[save].with.key, job.steps[restore].with.key);
    assert.match(job.steps[restore].with.key, /github.ref_name.*github.run_id.*github.run_attempt/);
    assert.match(job.steps[restore].with['restore-keys'], /github.ref_name.*\n.*-main-/);
    assert.equal(job.steps[save].if, "!cancelled() && github.ref == 'refs/heads/main' && steps.mutation.outputs.cacheable == 'true'");
    assert.deepEqual(job.permissions, { contents: 'read' });
    assert.doesNotMatch(JSON.stringify(job), /secrets\b|github.token|CLOUDFLARE/);
  });
}
test('push uses quick mode while the local lead gate remains full and the floor stays 90', () => {
  const pkg = read('package.json'), config = read('stryker.config.json');
  assert.equal(ci.jobs.verify.steps.find(s => s.id === 'mutation').run, 'pnpm mutation:quick');
  assert.equal(pkg.scripts.mutation, 'node tools/mutation/run.mjs full');
  assert.equal(pkg.scripts['mutation:quick'], 'node tools/mutation/run.mjs quick');
  assert.match(pkg.scripts.check, /pnpm mutation &&/); assert.match(pkg.scripts['check:quick'], /pnpm mutation:quick &&/);
  assert.equal(config.thresholds.break, 90); assert.equal(config.incrementalFile, 'reports/stryker-incremental.json');
});
test('Sunday night New York full run is dispatchable and cannot deploy', () => {
  assert.deepEqual(weekly.on.schedule, [{ cron: '37 23 * * 0', timezone: 'America/New_York' }]);
  assert.deepEqual(weekly.on.workflow_dispatch.inputs.full, { description: 'Force all mutants (ignore cached results)', type: 'boolean', default: true, required: true });
  assert.equal(weekly.jobs.mutation.if, "github.ref == 'refs/heads/main'");
  const run = weekly.jobs.mutation.steps.find(s => s.id === 'mutation');
  assert.equal(run.env.MUTATION_FULL, "${{ github.event_name == 'schedule' || inputs.full }}");
  assert.match(run.run, /then\n  pnpm mutation\nelse\n  pnpm mutation:quick/);
  assert.equal(weekly.jobs.mutation.steps.find(s => s.uses?.startsWith('actions/cache/restore@')).if, "github.event_name == 'workflow_dispatch' && !inputs.full");
  assert.deepEqual(Object.keys(weekly.jobs).sort(), ['mutation', 'report']);
});
test('weekly failure retains the report and runs a serialized, isolated issue reporter', () => {
  const upload = weekly.jobs.mutation.steps.find(s => s.uses?.startsWith('actions/upload-artifact@'));
  assert.equal(upload.if, '!cancelled()'); assert.match(upload.with.path, /release-mutation.json/); assert.match(upload.with.path, /mutation-issue.md/);
  const reporter = weekly.jobs.report;
  assert.equal(reporter.if, "!cancelled() && github.ref == 'refs/heads/main' && needs.mutation.outputs.below == 'true'");
  assert.deepEqual(reporter.permissions, { contents: 'read', issues: 'write' });
  assert.deepEqual(reporter.concurrency, { group: 'accounts-mutation-score-issue', 'cancel-in-progress': false });
  assert.equal(reporter.steps.at(-1).run, 'node tools/mutation/issue.mjs');
  assert.deepEqual(reporter.steps.at(-1).env, { GH_TOKEN: '${{ github.token }}' });
  assert.doesNotMatch(JSON.stringify(reporter), /pnpm|secrets\b/);
});
test('new workflow pins actions and never hides failed steps or interpolates shell input', () => {
  assert.deepEqual(weekly.permissions, { contents: 'read' });
  for (const job of Object.values(weekly.jobs)) for (const step of job.steps) {
    if (step.uses) assert.match(step.uses, /^[\w/-]+@[0-9a-f]{40}$/);
    if (step.run) assert.doesNotMatch(step.run, /\$\{\{/);
    if (step.uses?.startsWith('actions/checkout@')) assert.equal(step.with['persist-credentials'], false);
    assert.equal(step['continue-on-error'], undefined);
  }
});
