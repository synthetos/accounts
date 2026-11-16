import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adminFixture } from './roles-fixture.mjs';
import { setup } from './oidc-fixture.mjs';

test('provisioning two people creates distinct immutable identity records', async () => {
  const f = await adminFixture(); try {
    for (const subject of ['45678', '56789']) {
      await f.roles.change(f.hash, subject, 'member', 'New person', f.now,
        { subject, login: `person-${subject}`, displayName: `Person ${subject}`, avatarUrl: null });
    }
    assert.deepEqual(f.db.prepare("SELECT provider_subject FROM identities WHERE provider_subject != '12345' ORDER BY provider_subject").all()
      .map(row => row.provider_subject), ['45678', '56789']);
  } finally { f.close(); }
});

test('RPC revokeAll revokes another run session as well as the calling session', async () => {
  const f = await setup(); try {
    const first = await f.exchange(await f.authorize());
    const second = await f.exchange(await f.authorize());
    await f.rpc().revokeAll(first.sessionToken);
    assert.equal(await f.rpc().validateSession(second.sessionToken), null);
  } finally { f.close(); }
});
