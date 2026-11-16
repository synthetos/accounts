import { test } from 'node:test';
import assert from 'node:assert/strict';
import { peoplePage } from '../src/people-page.ts';

const person = { id: 'usr_example', githubId: '123', login: 'alice', name: 'Alice', role: 'tester' };
const event = { actor: 'admin', login: 'alice', githubId: '123', oldRole: 'member', newRole: 'tester', reason: 'Bench access', at: 1_700_000_000 };
const page = (csrf = 'form-token') => peoplePage([person], [event], '', csrf);
const options = (html) => [...html.matchAll(/<option value="([^"]+)"( selected)?>([^<]*)<\/option>/g)]
  .map(([, value, selected, label]) => ({ value, selected: !!selected, label }));
const roles = ['member', 'tester', 'moderator', 'admin'];

for (const selected of [...roles, null]) {
  test(`role editor selects only ${selected ?? 'no role'}`, () => {
    const html = peoplePage([{ ...person, role: selected }], [], '', 'csrf');
    const editor = html.match(/<select name="role" aria-label="Role for @alice">([\s\S]*?)<\/select>/)?.[1] ?? '';
    assert.deepEqual(options(editor), [
      ...roles.map(value => ({ value, label: value, selected: value === selected })),
      { value: 'remove', label: 'Remove access', selected: false },
    ]);
  });
}

test('new-person form defaults to member with the complete role choices', () => {
  const add = page().match(/<form method="post" action="\/admin\/people\/add"[\s\S]*?<\/form>/)?.[0] ?? '';
  assert.deepEqual(options(add), roles.map(value => ({ value, label: value, selected: value === 'member' })));
});

test('role selects contain only option elements without stray text', () => {
  const selects = [...page().matchAll(/<select\b[^>]*>([\s\S]*?)<\/select>/g)];
  assert.deepEqual(selects.map(([, body]) => body.replace(/<option\b[^>]*>[^<]*<\/option>/g, '')), ['', '']);
});

test('multi-person and multi-event table bodies contain only rows', () => {
  const html = peoplePage([person, { ...person, githubId: '456', login: 'bob' }],
    [event, { ...event, login: 'bob', githubId: '456' }], '', null);
  const bodies = [...html.matchAll(/<tbody>([\s\S]*?)<\/tbody>/g)];
  assert.deepEqual(bodies.map(([, body]) => body.replace(/<tr>[\s\S]*?<\/tr>/g, '')), ['', '']);
});

test('admins can submit a reasoned role change for the immutable GitHub ID', () => {
  assert.match(page(), /<form method="post" action="\/admin\/people\/change" class="role-form">\s*<input type="hidden" name="csrf" value="form-token"><input type="hidden" name="github_id" value="123">[\s\S]*?<input name="reason" required maxlength="500" placeholder="Why is access changing\?"><\/label>\s*<button type="submit">Save<\/button><\/form>/);
});

test('admins can submit a new-person lookup with CSRF and a reason', () => {
  assert.match(page(), /<form method="post" action="\/admin\/people\/add" class="add-form"><input type="hidden" name="csrf" value="form-token">[\s\S]*?<input name="login" required maxlength="40"[\s\S]*?<input name="reason" required maxlength="500"[\s\S]*?<button type="submit">Add person<\/button><\/form>/);
});

test('moderators have no mutation forms or change-access column', () => {
  assert.doesNotMatch(page(null), /method="post"|name="csrf"|name="role"|name="reason"|Change access|Add a person/);
});

for (const [csrf, expected] of [[null, 'Read-only access. Administrators manage roles.'], ['token', 'Manage who can sign in and connect to machines.']]) {
  test(`page explains ${csrf === null ? 'read-only' : 'admin'} access`, () => {
    assert.ok(page(csrf).includes(`<p>${expected}</p>`));
  });
}

test('administrator table names its action column', () => {
  assert.match(page(), /<th scope="col">Change access<\/th>/);
});

for (const [csrf, columns] of [[null, 3], ['token', 4]]) {
  test(`empty people table spans ${columns} columns`, () => {
    assert.ok(peoplePage([], [], '', csrf).includes(`<tbody><tr><td colspan="${columns}">No people found.</td></tr></tbody>`));
  });
}

test('an empty role audit explains that no changes were recorded', () => {
  assert.match(peoplePage([], [], '', null), /<tbody><tr><td colspan="5">No changes recorded\.<\/td><\/tr><\/tbody>/);
});

test('a populated audit omits the empty-audit message', () => {
  assert.doesNotMatch(page(), /No changes recorded/);
});

test('a populated people table omits the empty-people message', () => {
  assert.doesNotMatch(page(), /No people found/);
});

for (const [role, expected] of [[null, 'No access'], ['tester', 'tester']]) {
  test(`person badge renders ${expected}`, () => {
    assert.ok(peoplePage([{ ...person, role }], [], '', null).includes(`<span class="badge">${expected}</span>`));
  });
}

test('audit timestamps are formatted as UTC seconds with readable date and time', () => {
  assert.match(page(), /<td>2023-11-14 22:13:20 UTC<\/td>/);
});

for (const [oldRole, newRole, expected] of [[null, 'member', 'No access → member'], ['tester', null, 'tester → No access']]) {
  test(`audit describes ${expected}`, () => {
    assert.ok(peoplePage([], [{ ...event, oldRole, newRole }], '', null).includes(`<td>${expected}</td>`));
  });
}

for (const [actor, expected] of [[null, 'System'], ['boss<', '@boss&lt;']]) {
  test(`audit attributes a ${actor === null ? 'system' : 'human'} change`, () => {
    assert.ok(peoplePage([], [{ ...event, actor }], '', null).includes(`<td>${expected}</td><td>Bench access</td>`));
  });
}

for (const search of ['', 'alice']) {
  test(`audit caption describes ${search ? 'filtered' : 'all'} changes`, () => {
    assert.ok(peoplePage([], [], search, null).includes(`<caption>Latest 100 changes${search ? ' for this search' : ''}. Times are in UTC.</caption>`));
  });
}

test('search and CSRF values stay escaped inside their input attributes', () => {
  const html = peoplePage([], [], '\"><script>', '\"><script>');
  assert.deepEqual([...html.matchAll(/name="(q|csrf)"[^>]*value="([^"]*)"/g)].map(([, name, value]) => [name, value]),
    [['csrf', '&quot;&gt;&lt;script&gt;'], ['q', '&quot;&gt;&lt;script&gt;']]);
});
