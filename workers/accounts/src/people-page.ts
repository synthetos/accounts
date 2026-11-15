import { escapeHtml as e } from './security.ts';
import { ROLES, type Role } from './roles.ts';
import type { Person, RoleAudit } from './role-store.ts';

function choices(selected: Role | null): string {
  return ROLES.map(role => `<option value="${role}"${role === selected ? ' selected' : ''}>${role}</option>`).join('');
}
function fields(csrf: string): string { return `<input type="hidden" name="csrf" value="${e(csrf)}">`; }
function personRow(person: Person, csrf: string | null): string {
  const label = e(person.login);
  const action = csrf === null ? '' : `<td><form method="post" action="/admin/people/change" class="role-form">
    ${fields(csrf)}<input type="hidden" name="github_id" value="${e(person.githubId)}">
    <label>Role for @${label}<select name="role" aria-label="Role for @${label}">${choices(person.role)}<option value="remove">Remove access</option></select></label>
    <label>Reason for @${label}<input name="reason" required maxlength="500" placeholder="Why is access changing?"></label>
    <button type="submit">Save</button></form></td>`;
  return `<tr><th scope="row">@${label}<span class="secondary">${e(person.name)}</span></th><td>${e(person.githubId)}</td>
    <td><span class="badge">${person.role ?? 'No access'}</span></td>${action}</tr>`;
}
function auditRow(entry: RoleAudit): string {
  return `<tr><td>${new Date(entry.at * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')}</td>
    <th scope="row">@${e(entry.login)}<span class="secondary">${e(entry.githubId)}</span></th>
    <td>${entry.oldRole ?? 'No access'} → ${entry.newRole ?? 'No access'}</td>
    <td>${entry.actor === null ? 'System' : '@' + e(entry.actor)}</td><td>${e(entry.reason)}</td></tr>`;
}
export function peoplePage(people: Person[], audit: RoleAudit[], search: string, csrf: string | null): string {
  const add = csrf === null ? '' : `<section><h3>Add a person</h3><p>Look up their GitHub username and grant access to Synthetos.</p>
    <form method="post" action="/admin/people/add" class="add-form">${fields(csrf)}
    <label>GitHub username<input name="login" required maxlength="40" placeholder="@username" autocomplete="off"></label>
    <label>Role<select name="role">${choices('member')}</select></label>
    <label>Reason<input name="reason" required maxlength="500" placeholder="Why are you granting access?"></label>
    <button type="submit">Add person</button></form></section>`;
  return `<nav><a href="/account">← Your account</a></nav><h2>People &amp; access</h2>
    <p>${csrf === null ? 'Read-only access. Administrators manage roles.' : 'Manage who can sign in and connect to machines.'}</p>
    <p class="secondary">Members can save their work. Testers, moderators and admins can connect. Moderators can view this page; admins can manage access.</p>
    ${add}<section><h3>People</h3><form method="get" action="/admin/people" class="search-form">
    <label>Search by GitHub username or ID<input type="search" name="q" maxlength="40" value="${e(search)}" placeholder="@username or GitHub ID"></label>
    <button type="submit">Search</button><a href="/admin/people">Clear</a></form>
    <div class="table-scroll"><table><caption>Up to 100 matching people. The last admin must keep access.</caption>
    <thead><tr><th scope="col">Person</th><th scope="col">GitHub ID</th><th scope="col">Current role</th>${csrf === null ? '' : '<th scope="col">Change access</th>'}</tr></thead>
    <tbody>${people.map(person => personRow(person, csrf)).join('') || `<tr><td colspan="${csrf === null ? 3 : 4}">No people found.</td></tr>`}</tbody></table></div></section>
    <section><h3>Role audit</h3><div class="table-scroll"><table><caption>Latest 100 changes${search ? ' for this search' : ''}. Times are in UTC.</caption>
    <thead><tr><th scope="col">When</th><th scope="col">Person</th><th scope="col">Change</th><th scope="col">Changed by</th><th scope="col">Reason</th></tr></thead>
    <tbody>${audit.map(auditRow).join('') || '<tr><td colspan="5">No changes recorded.</td></tr>'}</tbody></table></div></section>`;
}
