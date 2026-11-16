import { test } from 'node:test';
import assert from 'node:assert/strict';
import { githubPerson } from '../src/github-person.ts';

const profile = { id: 123, login: 'someone', type: 'User', name: 'Some One' };
const lookup = (patch) => githubPerson('someone', async () => Response.json({ ...profile, ...patch }));

test('GitHub lookup requests the versioned public JSON API', async () => {
  let headers;
  await githubPerson('someone', async (_url, options) => { headers = options.headers; return Response.json(profile); });
  assert.deepEqual(headers, { Accept: 'application/vnd.github+json', 'User-Agent': 'Synthetos-Accounts', 'X-GitHub-Api-Version': '2022-11-28' });
});

test('GitHub lookup returns the canonical profile without an avatar or extra fields', async () => {
  assert.deepEqual(await lookup({}), { subject: '123', login: 'someone', displayName: 'Some One', avatarUrl: null });
});

for (const [label, patch] of [
  ['zero ID', { id: 0 }], ['negative ID', { id: -1 }], ['fractional ID', { id: 1.5 }],
  ['unsafe ID', { id: Number.MAX_SAFE_INTEGER + 1 }], ['non-string login', { login: 123 }],
  ['prefixed login garbage', { login: '!someone' }], ['suffixed login garbage', { login: 'someone!' }],
  ['empty login', { login: '' }], ['overlong login', { login: 'a'.repeat(40) }],
]) {
  test(`GitHub lookup rejects ${label}`, async () => {
    await assert.rejects(lookup(patch), { status: 502, message: 'Invalid GitHub profile.' });
  });
}

for (const [label, name, expected] of [
  ['missing', undefined, 'someone'], ['null', null, 'someone'], ['numeric', 12, 'someone'],
  ['empty', '', ''], ['maximum length', 'n'.repeat(256), 'n'.repeat(256)],
  ['overlong', 'n'.repeat(257), 'someone'],
]) {
  test(`GitHub display name handles a ${label} name`, async () => {
    assert.equal((await lookup({ name })).displayName, expected);
  });
}
