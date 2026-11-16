import { test } from 'node:test';
import assert from 'node:assert/strict';
import { admission } from '../src/admission.ts';
import { fixture } from './fixture.mjs';
import { adminFixture } from './roles-fixture.mjs';

for (const [label, allowed] of [
  ['missing list', undefined], ['oversized list', ' '.repeat(100_001)], ['malformed JSON', '{'],
  ['non-array JSON', '{}'], ['duplicate IDs', '["12345","12345"]'], ['numeric IDs', '[12345]'],
  ['zero ID', '["0"]'], ['noncanonical ID', '["012345"]'], ['unsafe ID', '["9007199254740992"]'],
  ['too many IDs', JSON.stringify(Array.from({ length: 1001 }, (_, i) => String(i + 1)))],
]) {
  test(`admission fails closed with service_unavailable for ${label}`, async () => {
    const f = fixture(); try {
      await assert.rejects(admission(f.env.IDENTITY.withSession('first-primary'), allowed, true, 'github', '12345', f.now),
        { status: 503, message: 'service_unavailable' });
    } finally { f.close(); }
  });
}

for (const [allowed, open, expected] of [['["12345"]', false, 'admin'], ['[]', true, 'member']]) {
  test(`first admission chooses ${expected}`, async () => {
    const f = fixture(); try {
      assert.equal(await admission(f.env.IDENTITY.withSession('first-primary'), allowed, open, 'github', '12345', f.now), expected);
    } finally { f.close(); }
  });
}

test('non-GitHub identities cannot bootstrap from a matching allowlist ID', async () => {
  const f = fixture(); try {
    await assert.rejects(admission(f.env.IDENTITY.withSession('first-primary'), '["12345"]', true, 'other', '12345', f.now),
      { status: 403, message: 'Access requires a role. Contact an administrator.' });
  } finally { f.close(); }
});

test('existing roles only bypass bootstrap checks for the GitHub identity', async () => {
  const f = await adminFixture(); try {
    const user = f.db.prepare('SELECT user_id FROM roles').get().user_id;
    f.db.prepare("INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at) VALUES ('idn_other',?,'other','12345','other',?)").run(user, f.now);
    await assert.rejects(admission(f.env.IDENTITY.withSession('first-primary'), '[]', true, 'other', '12345', f.now),
      { status: 403, message: 'Access requires a role. Contact an administrator.' });
  } finally { f.close(); }
});

test('open signup records its distinct bootstrap reason', async () => {
  const f = fixture(); try {
    f.env.GITHUB_ALLOWED_IDS = '[]'; f.env.OPEN_SIGNUP = 'true';
    await f.callback(await f.start());
    assert.equal(f.db.prepare('SELECT reason FROM role_audit').get().reason, 'Open signup');
  } finally { f.close(); }
});
