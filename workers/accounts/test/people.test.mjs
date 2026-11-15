import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adminFixture } from './roles-fixture.mjs';
import { Store } from '../src/store.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';
import { sha } from './fixture.mjs';
import { githubPerson } from '../src/github-person.ts';

const profile = { subject: '45678', login: 'new-person', displayName: 'New Person', avatarUrl: null };

test('admins add by GitHub login, search by login/id, change roles with reasons, and see audit', async () => {
  const f = await adminFixture(); try {
    assert.equal((await f.add()).status, 303); assert.deepEqual(f.lookupCalls, ['new-person']);
    for (const query of ['@NEW-person', '45678']) {
      const page = await f.admin('/admin/people?q=' + encodeURIComponent(query)); assert.equal(page.status, 200);
      const html = await page.text(); assert.match(html, /@new-person/); assert.match(html, /Testing machine access/);
      assert.doesNotMatch(html, /Fixture User/);
    }
    assert.equal((await f.change('45678', 'moderator', 'Help with moderation')).status, 303);
    const page = await f.admin(); const html = await page.text(); assert.match(html, /Help with moderation/);
    assert.match(html, /tester → moderator/);
    assert.equal((await f.roles.audit(''))[0].reason, 'Help with moderation'); assert.match(html, /People &amp; access/);
    assert.equal(page.headers.get('Referrer-Policy'), 'same-origin');
    assert.equal(page.headers.get('Cache-Control'), 'no-store');
    assert.match(page.headers.get('Content-Security-Policy'), /style-src 'self'; form-action 'self'$/);
    const css = await f.admin('/assets/accounts.css'); assert.equal(css.status, 200);
    assert.match(await css.text(), /prefers-color-scheme:dark/);
  } finally { f.close(); }
});

test('moderator is read-only; member, tester and anonymous visitors get 403', async () => {
  for (const role of ['moderator', 'member', 'tester']) {
    const f = await adminFixture(); try {
      await f.add(role); const token = randomToken();
      await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github', profile, sha(token), f.now, f.now);
      const adminCsrf = await f.csrf(); f.sid = '__Host-acct_sid=' + token;
      const response = await f.admin(); assert.equal(response.status, role === 'moderator' ? 200 : 403);
      if (role === 'moderator') { const html = await response.text(); assert.match(html, /Read-only/); assert.doesNotMatch(html, /method="post"/); }
      const write = await f.admin('/admin/people/change', { method: 'POST', body: new URLSearchParams({ csrf: adminCsrf, github_id: '12345', role: 'member', reason: 'Attempt' }) });
      assert.equal(write.status, 403);
      f.sid = ''; assert.equal((await f.admin()).status, 403);
    } finally { f.close(); }
  }
});

test('people mutations enforce exact origin, content type, fetch metadata and session-bound CSRF before lookup', async () => {
  const f = await adminFixture(); try {
    for (const headers of [{ Origin: '' }, { Origin: 'null' }, { Origin: 'https://run.example.test' },
      { 'Sec-Fetch-Site': 'same-site' }, { 'Content-Type': 'application/json' }]) {
      assert.equal((await f.post('add', { login: 'new-person', role: 'tester', reason: 'Test' }, headers)).status, 403);
    }
    for (const csrf of ['bad', '']) assert.ok([400,403].includes((await f.post('add', { login: 'new-person', role: 'tester', reason: 'Test', csrf })).status));
    const expired = await f.csrf(); f.now += 600;
    assert.equal((await f.post('add', { login: 'new-person', role: 'tester', reason: 'Test', csrf: expired })).status, 403);
    assert.deepEqual(f.lookupCalls, []);
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 1);
  } finally { f.close(); }
});

test('invalid roles, reasons, targets, fields and usernames are refused; no-op changes add no audit', async () => {
  const f = await adminFixture(); try {
    for (const fields of [{ role: 'owner' }, { role: 'remove' }, { reason: '   ' }, { reason: 'x'.repeat(501) },
      { reason: 'line\nbreak' }, { login: '../user' }, { login: 'https://evil.test' }, { extra: 'bad' }]) {
      assert.equal((await f.post('add', { login: 'new-person', role: 'tester', reason: 'Test', ...fields })).status, 400);
    }
    assert.equal((await f.change('invalid', 'member')).status, 400);
    assert.equal((await f.change('12345', 'admin')).status, 409);
    assert.equal(f.db.prepare('SELECT count(*) n FROM role_audit').get().n, 1);
    assert.equal((await f.admin('/admin/people?q=a&q=b')).status, 400);
    assert.equal((await f.admin('/admin/people/change')).status, 404);
  } finally { f.close(); }
});

test('people and audit escape stored names and reasons', async () => {
  const f = await adminFixture(); try {
    await f.add(); f.db.exec("UPDATE users SET display_name='<script>alert(1)</script>'");
    await f.change('45678', 'member', '<img src=x onerror=alert(1)>');
    const html = await (await f.admin()).text();
    assert.match(html, /&lt;script&gt;/); assert.match(html, /&lt;img/); assert.doesNotMatch(html, /<script>|<img/);
  } finally { f.close(); }
});

test('GitHub person lookup uses a fixed public API and validates immutable numeric id and user type', async () => {
  let seen;
  const person = await githubPerson('someone', async (url, options) => {
    seen = { url, options }; return Response.json({ id: 123, login: 'someone', type: 'User', name: 'Someone' });
  });
  assert.equal(person.subject, '123'); assert.equal(seen.url, 'https://api.github.com/users/someone');
  assert.equal(seen.options.redirect, 'manual'); assert.equal(seen.options.headers.Authorization, undefined);
  for (const data of [null, {}, { id: '123', login: 'someone', type: 'User' },
    { id: 123, login: 'someone', type: 'Organization' }, { id: 123, login: '<script>', type: 'User' }]) {
    await assert.rejects(githubPerson('someone', async () => Response.json(data)), /Invalid GitHub profile/);
  }
  await assert.rejects(githubPerson('missing', async () => new Response(null, { status: 404 })), /not found/);
  await assert.rejects(githubPerson('someone', async () => new Response(null, { status: 302 })), /unavailable/);
});
