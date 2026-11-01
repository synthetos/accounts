import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../../workers/accounts/src/index.ts';

test('auth-core declares no dependency of any kind', () => {
  const manifest = JSON.parse(readFileSync('packages/auth-core/package.json', 'utf8'));
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    assert.deepEqual(Object.keys(manifest[field] ?? {}), []);
  }
});

test('foundation Worker exposes no login endpoint or cacheable authenticated content', async () => {
  const response = await worker.fetch(new Request('https://accounts.test/auth/login'));
  assert.equal(response.status, 503);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('Set-Cookie'), null);
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
  assert.match(response.headers.get('Permissions-Policy'), /serial=\(\)/);
});

test('workflow keeps Cloudflare secrets in gated deploy jobs and pins every action', () => {
  // JSON is a YAML subset: parsing exactly this subset avoids a permissive custom YAML parser.
  const workflow = JSON.parse(readFileSync('.github/workflows/ci.yml', 'utf8'));
  assert.deepEqual(Object.keys(workflow.on).sort(), ['pull_request', 'push']);
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  assert.equal(workflow.jobs.verify.if, undefined);
  for (const [name, job] of Object.entries(workflow.jobs)) {
    const deploy = name === 'deploy-staging' || name === 'deploy-production';
    if (!deploy) {
      assert.doesNotMatch(JSON.stringify(job), /secrets\b|CLOUDFLARE_API_TOKEN/);
      assert.equal(job.environment, undefined);
    } else {
      assert.equal(job.if, "github.event_name == 'push' && github.ref == 'refs/heads/main' && vars.ACCOUNTS_DEPLOY_ENABLED == 'true'");
      for (const gate of ['verify', 'build', 'e2e', 'attest']) assert.ok(job.needs.includes(gate));
      assert.equal(job.environment, name.slice('deploy-'.length));
      assert.ok(job.steps.some((s) => s.run?.includes('--source-digest "$GITHUB_SHA"')));
      assert.ok(job.steps.some((s) => s.run?.includes('--no-bundle --config payload/wrangler.json')));
    }
    for (const step of job.steps) {
      if (step.uses) assert.match(step.uses, /^[\w/-]+@[0-9a-f]{40}$/);
      if (step.run) assert.doesNotMatch(step.run, /\$\{\{/);
      assert.equal(step['continue-on-error'], undefined);
    }
    if (name !== 'attest') assert.deepEqual(job.permissions, { contents: 'read' });
  }
  assert.equal(workflow.jobs.attest.steps.some((s) => s.run || s.uses?.startsWith('actions/checkout')), false);
  const buildText = JSON.stringify(workflow.jobs.build);
  assert.match(buildText, /ci\/build-toolchain install --frozen-lockfile --ignore-scripts/);
  assert.match(buildText, /artifact.mjs compare a\/dist b\/dist/);
  assert.ok(workflow.jobs.verify.steps.some((s) => s.run === 'pnpm mutation'));
  const mutation = JSON.parse(readFileSync('stryker.config.json', 'utf8'));
  assert.equal(mutation.thresholds.break, 90);
});
