import assert from 'node:assert/strict';
import { fixture, cookie, sha, origin } from './fixture.mjs';
import { createApp } from '../src/app.ts';
import { RoleStore } from '../src/role-store.ts';

export async function adminFixture() {
  const f = fixture();
  const signed = await f.callback(await f.start());
  assert.equal(signed.status, 303);
  f.sid = cookie(signed, '__Host-acct_sid'); f.hash = sha(f.sid.split('=')[1]);
  f.roles = new RoleStore(f.env.IDENTITY);
  f.lookupCalls = [];
  const app = createApp({ now: () => f.now, lookupPerson: async login => {
    f.lookupCalls.push(login);
    return { subject: '45678', login: 'new-person', displayName: 'New Person', avatarUrl: null };
  } });
  f.admin = (path = '/admin/people', init = {}) => app.fetch(new Request(origin + path, {
    ...init, headers: { Cookie: f.sid, ...init.headers },
  }), f.env);
  f.csrf = async () => (await (await f.admin()).text()).match(/name="csrf" value="([^"]+)"/)[1];
  f.post = async (action, fields, headers = {}) => f.admin(`/admin/people/${action}`, {
    method: 'POST', headers: { Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams({ csrf: await f.csrf(), ...fields }),
  });
  f.add = (role = 'tester') => f.post('add', { login: '@new-person', role, reason: 'Testing machine access' });
  f.change = (id, role, reason = 'Access review') => f.post('change', { github_id: id, role, reason });
  return f;
}
