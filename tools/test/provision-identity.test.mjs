import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { provisionDatabase } from '../provision-identity.mjs';
const account = 'a'.repeat(32), id = '11111111-2222-4333-8444-555555555555';
test('lookup spans pages, reuses identity, or creates exactly identity once', async () => {
  for (const exists of [true, false]) {
    const calls = [];
    const fetcher = async (url, init) => {
      calls.push([url, init]);
      assert.equal(init.headers.authorization, 'Bearer private-token');
      assert.equal(init.redirect, 'error');
      return Response.json({ success: true, result: init.method === 'POST' ? { uuid: id } : exists && url.endsWith('page=2') ? [{ name: 'identity', uuid: id }] : [], result_info: { total_pages: 2 } });
    };
    assert.equal(await provisionDatabase(account, 'private-token', fetcher), id);
    assert.equal(calls.length, exists ? 2 : 3);
    if (!exists) assert.deepEqual(JSON.parse(calls[2][1].body), { name: 'identity' });
  }
});
test('refuses missing credentials, denial, bad pagination/id and duplicate names without leaking response text', async () => {
  await assert.rejects(provisionDatabase('bad', 't'), /ACCOUNT_ID/);
  await assert.rejects(provisionDatabase(account, ''), /D1: Edit/);
  for (const status of [401, 403, 500]) await assert.rejects(provisionDatabase(account, 't', async () => new Response('private-token', { status })), /D1/);
  for (const body of [{ success: false }, { success: true, result: {} }, { success: true, result: [], result_info: { total_pages: -1 } }, { success: true, result: [{ name: 'identity', uuid: 'bad' }] }, { success: true, result: [{ name: 'identity', uuid: id }, { name: 'identity', uuid: id }] }]) await assert.rejects(provisionDatabase(account, 't', async () => Response.json(body)));
});
test('provisioning is main-only, manual, production protected and uses only the D1 token on its one API step', () => {
  const wf = JSON.parse(readFileSync('.github/workflows/production-provision.yml', 'utf8'));
  assert.deepEqual(Object.keys(wf.on), ['workflow_dispatch']);
  const job = wf.jobs.provision;
  assert.equal(job.environment, 'production'); assert.equal(job.if, "github.ref == 'refs/heads/main'");
  assert.deepEqual(job.permissions, { contents: 'read' });
  assert.equal(job.concurrency['cancel-in-progress'], false);
  assert.equal(job.steps.length, 3);
  for (const step of job.steps.slice(0, 2)) { assert.match(step.uses, /@[0-9a-f]{40}$/); assert.doesNotMatch(JSON.stringify(step), /secrets/); }
  assert.equal(job.steps[0].with['persist-credentials'], false);
  assert.deepEqual(job.steps[2].env, { CLOUDFLARE_D1_API_TOKEN: '${{ secrets.CLOUDFLARE_D1_API_TOKEN }}', CLOUDFLARE_ACCOUNT_ID: '${{ vars.CLOUDFLARE_ACCOUNT_ID }}' });
  assert.equal(job.steps[2].run, 'node tools/provision-identity.mjs');
});
