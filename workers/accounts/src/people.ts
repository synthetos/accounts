import { assertFormMutation, createFormToken, hashToken, readHostCookie } from '../../../packages/auth-core/src/index.ts';
import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import type { Env } from './app.ts';
import type { AccountResponse } from './account.ts';
import { Store } from './store.ts';
import { RoleStore } from './role-store.ts';
import { isRole } from './roles.ts';
import { check, readBody, single } from './security.ts';
import { githubPerson } from './github-person.ts';
import { peoplePage } from './people-page.ts';

export async function people(request: Request, env: Env, now: number, formKey: CryptoKey,
  lookup: (login: string) => Promise<ProviderProfile> = githubPerson): Promise<AccountResponse | null> {
  const url = new URL(request.url);
  if (url.pathname !== '/admin/people' && !url.pathname.startsWith('/admin/people/')) return null;
  check(env.IDENTITY && env.ACCOUNT_ORIGIN, 503, 'service_unavailable');
  const token = readHostCookie(request.headers.get('Cookie'), '__Host-acct_sid');
  const hash = token ? await hashToken(token) : null;
  const session = hash ? await new Store(env.IDENTITY).validate(hash, now) : null;
  check(session && hash && (session.role === 'admin' || session.role === 'moderator'), 403, 'Access denied.');
  const store = new RoleStore(env.IDENTITY);
  if (url.pathname === '/admin/people' && request.method === 'GET') {
    const search = (url.searchParams.get('q') ?? '').replace(/^@/, '').trim();
    check(url.searchParams.getAll('q').length <= 1 && search.length <= 39 && /^[a-zA-Z0-9-]*$/.test(search));
    const csrf = session.role === 'admin' ? await createFormToken(formKey, session.id, 'people', now) : null;
    return { status: 200, html: true, form: true,
      body: peoplePage(await store.people(search), await store.audit(search), search, csrf) };
  }
  check(session.role === 'admin', 403, 'Access denied.');
  if (request.method !== 'POST' || !['/admin/people/add', '/admin/people/change'].includes(url.pathname)) return { status: 404, body: 'Not found.' };
  const add = url.pathname.endsWith('/add');
  const body = new URLSearchParams(await readBody(request, 4096));
  for (const name of body.keys()) check(['csrf', 'role', 'reason', add ? 'login' : 'github_id'].includes(name) && body.getAll(name).length === 1);
  await assertFormMutation(request, env.ACCOUNT_ORIGIN, formKey, session.id, 'people', single(body, 'csrf'), now);
  const value = single(body, 'role');
  check(isRole(value) || (!add && value === 'remove'));
  const role = isRole(value) ? value : null;
  const reason = single(body, 'reason').trim(); check(reason.length > 0 && reason.length <= 500 && !/[\x00-\x1f\x7f]/.test(reason));
  let target: string; let profile: ProviderProfile | undefined;
  if (add) {
    const login = single(body, 'login').replace(/^@/, ''); check(/^[a-zA-Z0-9-]{1,39}$/.test(login));
    await new Store(env.IDENTITY).rateLimit(`people:${session.id}`, now);
    profile = await lookup(login); target = profile.subject;
  } else { target = single(body, 'github_id'); }
  check(/^[1-9][0-9]{0,15}$/.test(target) && Number.isSafeInteger(Number(target)));
  await store.change(hash, target, role, reason, now, profile);
  return { status: 303, body: null, headers: { Location: '/admin/people' } };
}
