import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, sha, cookie } from './fixture.mjs';
import { adminFixture } from './roles-fixture.mjs';
import { setup } from './oidc-fixture.mjs';
import { Store } from '../src/store.ts';
import { capabilities } from '../src/roles.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';

const profile = { subject: '45678', login: 'new-person', displayName: 'New Person', avatarUrl: null };

test('allowlist seeds an admin exactly once and role changes remain authoritative', async () => {
  const f = await adminFixture(); try {
    assert.equal(f.db.prepare('SELECT role FROM roles').get().role, 'admin');
    assert.equal(f.db.prepare('SELECT reason FROM role_audit').get().reason, 'Allowlist bootstrap');
    assert.equal((await f.add('admin')).status, 303);
    assert.equal((await f.change('12345', 'tester')).status, 303);
    assert.equal((await f.callback(await f.start())).status, 303);
    assert.equal(f.db.prepare("SELECT role FROM roles JOIN identities USING(user_id) WHERE provider_subject='12345'").get().role, 'tester');
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 3);
  } finally { f.close(); }
});

test('open signup defaults off, only exact true enables member admission, with one audit on repeated sign-in', async () => {
  for (const value of [undefined, 'false', 'TRUE', '1', 'true']) {
    const f = fixture(); try {
      f.env.GITHUB_ALLOWED_IDS = '[]'; f.env.OPEN_SIGNUP = value;
      assert.equal((await f.callback(await f.start())).status, value === 'true' ? 303 : 403);
      if (value !== 'true') { assert.equal(f.db.prepare('SELECT count(*) n FROM users').get().n, 0); continue; }
      assert.equal(f.db.prepare('SELECT role FROM roles').get().role, 'member');
      assert.equal((await f.callback(await f.start())).status, 303);
      assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 1);
    } finally { f.close(); }
  }
});

test('an admin provisioned person can sign in outside the bootstrap list', async () => {
  const f = await adminFixture(); try {
    assert.equal((await f.add()).status, 303);
    f.profile = { id: 45678, login: 'renamed-person', name: 'New name', avatar_url: null };
    const response = await f.callback(await f.start()); assert.equal(response.status, 303);
    assert.ok(cookie(response, '__Host-acct_sid'));
    const users = f.db.prepare('SELECT count(*) n FROM users').get().n; assert.equal(users, 2);
    assert.equal(f.db.prepare("SELECT login FROM identities WHERE provider_subject='45678'").get().login, 'renamed-person');
  } finally { f.close(); }
});

test('removal revokes every client and cannot be bypassed by allowlist or open signup; explicit regrant works', async () => {
  const f = await adminFixture(); try {
    await f.add(); const token = randomToken();
    const store = new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS);
    await store.signIn('github', profile, sha(token), f.now, f.now);
    const session = await store.validate(sha(token), f.now); assert.ok(session);
    f.db.exec("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding','[]')");
    f.db.prepare(`INSERT INTO sessions(token_hash,id,user_id,client,device_record_id,created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at)
      VALUES (?,'ses_other',?,'run','device',?,?,?,?,?)`).run(sha(randomToken()), session.user_id, f.now, f.now, f.now+500, f.now+500, f.now);
    assert.equal((await f.change('45678', 'remove')).status, 303);
    assert.equal(await store.validate(sha(token), f.now), null);
    assert.equal(f.db.prepare('SELECT count(*) n FROM sessions WHERE user_id=? AND revoked_at IS NULL').get(session.user_id).n, 0);
    for (const allowed of ['[]', '["45678"]']) await assert.rejects(new Store(f.env.IDENTITY, allowed, true)
      .signIn('github', profile, sha(randomToken()), f.now, f.now), /Access requires a role/);
    assert.equal((await f.change('45678', 'member')).status, 303);
    assert.equal(await store.validate(sha(token), f.now), null);
    await store.signIn('github', profile, sha(randomToken()), f.now, f.now);
  } finally { f.close(); }
});

test('the last admin cannot be removed, demoted, locked or deleted and failed changes leave no audit', async () => {
  const f = await adminFixture(); try {
    for (const role of ['member','tester','moderator','remove']) {
      const response = await f.change('12345', role); assert.equal(response.status, 409);
      assert.match(await response.text(), /last administrator/);
    }
    assert.throws(() => f.db.exec("UPDATE users SET status='locked'"), /last_admin/);
    assert.throws(() => f.db.exec('DELETE FROM users'), /last_admin/);
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 1);
    assert.equal(f.db.prepare('SELECT role FROM roles').get().role, 'admin');
  } finally { f.close(); }
});

test('two admins cannot demote each other or themselves past the last admin', async () => {
  const f = await adminFixture(); try {
    await f.add('admin'); const token = randomToken();
    await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github', profile, sha(token), f.now, f.now);
    await f.roles.change(f.hash, '12345', 'member', 'Handing over', f.now);
    await assert.rejects(f.roles.change(sha(token), '45678', null, 'Leaving', f.now), /last administrator/);
    await assert.rejects(f.roles.change(f.hash, '45678', 'member', 'Stale admin session', f.now), /No change made/);
    assert.equal(f.db.prepare("SELECT count(*) n FROM roles WHERE role='admin'").get().n, 1);
  } finally { f.close(); }
});

test('roles and audit are one transaction and audit is immutable', async () => {
  const f = await adminFixture(); try {
    await f.add();
    f.db.exec("CREATE TRIGGER test_audit_failure BEFORE INSERT ON role_audit BEGIN SELECT RAISE(ABORT,'test_failure'); END");
    assert.equal((await f.change('45678', 'admin')).status, 503);
    assert.equal(f.db.prepare("SELECT role FROM roles JOIN identities USING(user_id) WHERE provider_subject='45678'").get().role, 'tester');
    assert.throws(() => f.db.exec("UPDATE role_audit SET reason='edited'"), /append-only/);
    assert.throws(() => f.db.exec('DELETE FROM role_audit'), /append-only/);
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 2);
  } finally { f.close(); }
});

test('RPC returns current role and shared capabilities, including changes after issuance and immediate removal', async () => {
  const f = await setup(); try {
    const result = await f.exchange(await f.authorize());
    assert.equal(result.session.role, 'member'); assert.deepEqual(result.session.capabilities, []);
    for (const role of ['tester','moderator','admin','tester']) {
      // Seed a second admin before testing demotion of this account.
      if (role === 'admin') {
        const candidate = 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAX';
        f.db.prepare('INSERT INTO users(id,display_name,created_at) VALUES (?,\'Other Admin\',?)').run(candidate, f.now);
        f.db.prepare("INSERT INTO roles(user_id,role,granted_at) VALUES (?,'admin',?)").run(candidate, f.now);
      }
      f.db.prepare('UPDATE roles SET role=? WHERE user_id=?').run(role, result.session.sub);
      const session = await f.rpc().validateSession(result.sessionToken);
      assert.equal(session.role, role); assert.deepEqual(session.capabilities, ['run.connect']);
    }
    f.db.prepare('DELETE FROM roles WHERE user_id=?').run(result.session.sub);
    assert.equal(await f.rpc().validateSession(result.sessionToken), null);
    assert.equal(await new Store(f.env.IDENTITY).validate(sha(f.accountToken), f.now), null);
  } finally { f.close(); }
});

test('capability arrays cannot mutate the shared map', () => {
  capabilities('admin').pop(); assert.deepEqual(capabilities('admin'), ['run.connect']);
  assert.deepEqual(capabilities('member'), []);
});

test('removing a role while an authorization code is outstanding prevents redemption', async () => {
  const f = await setup(); try {
    const flow = await f.authorize(); f.db.exec('DELETE FROM roles');
    await assert.rejects(f.exchange(flow), /invalid_grant/);
    assert.equal(f.db.prepare("SELECT count(*) n FROM sessions WHERE client='run'").get().n, 0);
  } finally { f.close(); }
});

test('an existing role admits its user independently of missing or changed bootstrap configuration', async () => {
  const f = await adminFixture(); try {
    for (const allowed of [undefined, 'not-json', '[]']) {
      f.env.GITHUB_ALLOWED_IDS = allowed;
      assert.equal((await f.callback(await f.start())).status, 303);
    }
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 1);
  } finally { f.close(); }
});
