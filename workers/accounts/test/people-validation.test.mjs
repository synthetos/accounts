import { test } from 'node:test';
import assert from 'node:assert/strict';
import { people } from '../src/people.ts';
import { key } from '../src/security.ts';
import { adminFixture } from './roles-fixture.mjs';
import { origin } from './fixture.mjs';

const request = (f, path = '/admin/people', init = {}) => new Request(origin + path, { ...init, headers: { Cookie: f.sid, ...init.headers } });
const formKey = f => key(f.env.FORM_KEY, 'HMAC');

for (const missing of ['IDENTITY', 'ACCOUNT_ORIGIN']) {
  test(`people refuses missing ${missing} configuration explicitly`, async () => {
    const f = await adminFixture(); try {
      await assert.rejects(people(request(f), { ...f.env, [missing]: undefined }, f.now, await formKey(f)),
        { status: 503, message: 'service_unavailable' });
    } finally { f.close(); }
  });
}

test('people refuses an unknown session with Access denied', async () => {
  const f = await adminFixture(); try {
    f.sid = '__Host-acct_sid=' + Buffer.alloc(32, 5).toString('base64url');
    await assert.rejects(people(request(f), f.env, f.now, await formKey(f)), { status: 403, message: 'Access denied.' });
  } finally { f.close(); }
});

test('admin GET returns a form-enabled HTML response', async () => {
  const f = await adminFixture(); try {
    const result = await people(request(f), f.env, f.now, await formKey(f));
    assert.deepEqual({ status: result.status, html: result.html, form: result.form }, { status: 200, html: true, form: true });
  } finally { f.close(); }
});

test('unsupported admin paths return a useful not-found response', async () => {
  const f = await adminFixture(); try {
    assert.deepEqual(await people(request(f, '/admin/people/unknown'), f.env, f.now, await formKey(f)), { status: 404, body: 'Not found.' });
  } finally { f.close(); }
});

test('unsupported root methods do not render the administration page', async () => {
  const f = await adminFixture(); try {
    assert.deepEqual(await people(request(f, '/admin/people', { method: 'PUT' }), f.env, f.now, await formKey(f)), { status: 404, body: 'Not found.' });
  } finally { f.close(); }
});

test('search trims surrounding whitespace after removing a leading at-sign', async () => {
  const f = await adminFixture(); try {
    const response = await f.admin('/admin/people?q=' + encodeURIComponent('@fixture-user  '));
    assert.match(await response.text(), /type="search" name="q" maxlength="40" value="fixture-user"/);
  } finally { f.close(); }
});

test('search accepts the maximum 39-character GitHub username', async () => {
  const f = await adminFixture(); try {
    assert.equal((await f.admin('/admin/people?q=' + 'a'.repeat(39))).status, 200);
  } finally { f.close(); }
});

for (const search of ['a'.repeat(40), '!alice', 'alice!', 'alice@']) {
  test(`search refuses ${JSON.stringify(search)}`, async () => {
    const f = await adminFixture(); try {
      assert.equal((await f.admin('/admin/people?q=' + encodeURIComponent(search))).status, 400);
    } finally { f.close(); }
  });
}

test('people refuses duplicate form fields', async () => {
  const f = await adminFixture(); try {
    const body = new URLSearchParams({ csrf: await f.csrf(), login: 'new-person', role: 'tester', reason: 'Test' });
    body.append('role', 'admin');
    const response = await f.admin('/admin/people/add', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    assert.equal(response.status, 400);
  } finally { f.close(); }
});

test('a maximum length reason is accepted and stored intact', async () => {
  const f = await adminFixture(); try {
    await f.post('add', { login: 'new-person', role: 'tester', reason: 'x'.repeat(500) });
    assert.equal(f.db.prepare("SELECT reason FROM role_audit WHERE github_id='45678'").get()?.reason, 'x'.repeat(500));
  } finally { f.close(); }
});

test('a trailing at-sign is not treated as a username prefix', async () => {
  const f = await adminFixture(); try {
    assert.equal((await f.post('add', { login: 'person@', role: 'tester', reason: 'Test' })).status, 400);
  } finally { f.close(); }
});

for (const target of ['012345', '+12345', ' 12345', '12345 ', '12345!', '9007199254740992']) {
  test(`role changes reject a noncanonical or unsafe ID ${JSON.stringify(target)}`, async () => {
    const f = await adminFixture(); try {
      assert.equal((await f.change(target, 'member')).status, 400);
    } finally { f.close(); }
  });
}

test('a successful addition redirects to the people page', async () => {
  const f = await adminFixture(); try {
    assert.equal((await f.add()).headers.get('Location'), '/admin/people');
  } finally { f.close(); }
});

test('add-person lookups are rate limited per administrator session', async () => {
  const f = await adminFixture(); try {
    const id = f.db.prepare('SELECT id FROM sessions WHERE token_hash=?').get(f.hash).id;
    f.db.prepare('INSERT INTO login_rate_limits(bucket_hash,window_start,attempts) VALUES (?,?,10)').run(`people:${id}`, f.now);
    assert.equal((await f.add()).status, 429);
  } finally { f.close(); }
});
