import { test } from 'node:test';
import assert from 'node:assert/strict';
import { updateIssue } from '../mutation/issue.mjs';

for (const state of ['open', 'closed']) {
  test(`updates the existing ${state} score issue instead of creating duplicates`, async () => {
    const calls = [];
    const fetcher = async (url, options) => { calls.push({ url, ...options }); return { ok: true, json: async () => options.method === 'GET' ? [{ title: 'Mutation score below 90', number: 7, state }] : {} }; };
    await updateIssue({ repository: 'owner/accounts', token: 'test-only', body: 'survivors', fetcher });
    assert.equal(calls.length, 2); assert.equal(calls[1].method, 'PATCH'); assert.match(calls[1].url, /issues\/7$/);
    assert.deepEqual(JSON.parse(calls[1].body), { body: 'survivors', state: 'open' });
  });
}
test('paginates all issues and creates a single issue with the exact title when absent', async () => {
  const calls = [];
  const fetcher = async (url, options) => { calls.push({ url, ...options }); return { ok: true, json: async () => url.endsWith('page=1') ? Array(100).fill({ title: 'other' }) : [] }; };
  await updateIssue({ repository: 'owner/accounts', token: 'test-only', body: 'list', fetcher });
  assert.equal(calls.length, 3); assert.match(calls[1].url, /page=2$/);
  assert.equal(calls[2].method, 'POST'); assert.deepEqual(JSON.parse(calls[2].body), { title: 'Mutation score below 90', body: 'list' });
});
test('API rejection fails visibly without printing credentials or response bodies', async () => {
  await assert.rejects(updateIssue({ repository: 'owner/accounts', token: 'test-only', body: 'list', fetcher: async () => ({ ok: false, status: 403 }) }), /^Error: Issue API failed \(403\)$/);
});
