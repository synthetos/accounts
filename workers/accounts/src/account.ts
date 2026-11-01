import { assertFormMutation, clearHostCookie, createFormToken, createPkce, hashToken, hostCookie, randomToken, readHostCookie } from '../../../packages/auth-core/src/index.ts';
import type { IdentityProvider } from '../../../packages/idp/src/index.ts';
import type { Env } from './app.ts';
import { AccountStore } from './account-store.ts';
import { Store } from './store.ts';
import { check, escapeHtml, keyedHash, key, readBody, seal, single, unseal } from './security.ts';

const SID = '__Host-acct_sid';
const NONCE = '__Host-acct_manage';
export interface AccountResponse { body: string | null; status: number; headers?: HeadersInit; html?: boolean; form?: boolean }
const redirect = (headers: Record<string, string> = {}): AccountResponse => ({ body: null, status: 303, headers: { Location: '/account', ...headers } });
function labelTime(seconds: number): string { return new Date(seconds * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC'); }
export function coarseClient(request: Request): { device: string; country: string | null } {
  const ua = request.headers.get('User-Agent') ?? '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Other browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Macintosh|Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'unknown OS';
  const country = request.headers.get('CF-IPCountry');
  return { device: `${browser} on ${os}`, country: country && country.length === 2 && /^[A-Z]+$/.test(country) && country !== 'XX' ? country : null };
}

export async function account(request: Request, env: Env, provider: IdentityProvider, now: number, formKey: CryptoKey, stateKey: CryptoKey, clock: () => number): Promise<AccountResponse | null> {
  const url = new URL(request.url);
  if (!['/', '/account', '/auth/github/callback'].includes(url.pathname) && !url.pathname.startsWith('/account/')) return null;
  check(env.IDENTITY && env.ACCOUNT_ORIGIN && env.RATE_KEY, 503, 'service_unavailable');
  const db = new AccountStore(env.IDENTITY);
  const token = readHostCookie(request.headers.get('Cookie'), SID);
  const hash = token ? await hashToken(token) : null;
  if (url.pathname === '/auth/github/callback') {
    if (request.method !== 'GET') return null;
    const state = single(url.searchParams, 'state'); check(state.length === 43);
    const stateHash = await hashToken(state);
    if (await db.peek(stateHash) === null) return null; // Ordinary sign-in is handled separately.
    check(hash !== null, 403, 'verification_refused');
    const nonce = readHostCookie(request.headers.get('Cookie'), NONCE); check(nonce, 403, 'verification_refused');
    const nonceHash = await hashToken(nonce);
    const flow = await db.consume(hash, stateHash, nonceHash, now);
    const headers = new Headers({ 'Set-Cookie': clearHostCookie(NONCE, 'Lax') });
    if (url.searchParams.has('error')) {
      check(single(url.searchParams, 'error') === 'access_denied');
      return { body: '<p>Verification was cancelled. <a href="/account">Return to your account</a>.</p>', status: 400, headers, html: true };
    }
    const code = single(url.searchParams, 'code'); check(code.length <= 1024 && !/[\s\x00-\x1f]/.test(code));
    const verifier = await unseal(flow.pkce_verifier_enc, stateKey, `${env.ACCOUNT_ORIGIN}|management|${flow.purpose}|${flow.session_id}|${stateHash}|${nonceHash}`);
    const profile = await provider.profile(await provider.exchange(code, verifier));
    const finishedAt = clock();
    check(Number.isSafeInteger(finishedAt) && finishedAt >= now && finishedAt < flow.created_at + 600, 403, 'verification_refused');
    if (flow.purpose === 'step_up') {
      const accepted = await db.finishStepUp(hash, flow, provider.name, profile.subject, finishedAt);
      if (!accepted) {
        headers.append('Set-Cookie', clearHostCookie(SID, 'Lax'));
        return { body: '<p>That GitHub account is not linked to this account. This session has been signed out. <a href="/login">Sign in again</a>.</p>', status: 403, headers, html: true };
      }
    } else {
      await db.finishLink(hash, flow, provider.name, profile, finishedAt);
    }
    headers.set('Location', '/account');
    return { body: null, status: 303, headers };
  }
  const session = hash ? await new Store(env.IDENTITY).validate(hash, now) : null;
  if (session === null || hash === null) return { body: null, status: request.method === 'GET' ? 303 : 401,
    headers: { Location: '/login', 'Set-Cookie': clearHostCookie(SID, 'Lax') } };
  if ((url.pathname === '/' || url.pathname === '/account') && request.method === 'GET') {
    const dashboard = await db.dashboard(hash, now);
    const fresh = dashboard.step_up_at !== null && dashboard.step_up_at > now - 600 && dashboard.step_up_at <= now;
    const form = async (path: string, action: string, button: string, field?: { name: string; value: string }, disabled = false): Promise<string> => {
      const csrf = await createFormToken(formKey, session.id, action, now);
      return `<form method="post" action="${path}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}">${field ? `<input type="hidden" name="${field.name}" value="${escapeHtml(field.value)}">` : ''}<button type="submit"${disabled ? ' disabled' : ''}>${escapeHtml(button)}</button></form>`;
    };
    const identities = await Promise.all(dashboard.identities.map(async (identity) => `<li>${escapeHtml(identity.provider)}: @${escapeHtml(identity.login)} (ID ${escapeHtml(identity.subject)})${await form('/account/identities/unlink', `unlink:${identity.id}`, `Unlink ${identity.login}`, { name: 'identity', value: identity.id }, !fresh || dashboard.identities.length < 2)}</li>`));
    const sessions = await Promise.all(dashboard.sessions.map(async (entry) => `<tr><th scope="row">${escapeHtml(entry.client)}${entry.id === session.id ? ' (this session)' : ''}</th><td>${labelTime(entry.created)}</td><td>${labelTime(entry.seen)}</td><td>${escapeHtml(entry.device ?? 'Unknown device')}</td><td>${escapeHtml(entry.country ?? 'Not recorded')}</td><td>${await form('/account/sessions/revoke', `revoke:${entry.id}`, 'Sign out this session', { name: 'session', value: entry.id })}</td></tr>`));
    return { status: 200, html: true, form: true, body: `<p>Signed in as ${escapeHtml(dashboard.name)}.</p><h2>Linked identities</h2><ul>${identities.join('')}</ul>
      <p>${fresh ? 'Identity verified recently. Sensitive account actions are available for ten minutes after verification.' : 'Verify with a linked GitHub account before linking or unlinking an identity.'}</p>
      ${await form('/account/step-up', 'step_up', 'Verify with GitHub')}
      ${await form('/account/identities/link', 'link', 'Link another GitHub account', undefined, !fresh)}
      <p>You cannot unlink your last identity. Linking an identity already used by someone else never merges accounts.</p>
      <h2>Active sessions</h2><p>Up to 100 most recent active sessions, across all Synthetos products.</p>
      <table><caption>Your active sessions</caption><thead><tr><th scope="col">Product</th><th scope="col">Created</th><th scope="col">Last active</th><th scope="col">Device</th><th scope="col">Country</th><th scope="col">Action</th></tr></thead><tbody>${sessions.join('')}</tbody></table>
      ${await form('/account/sessions/revoke-all', 'revoke_all', 'Sign out everywhere')}
      <p>Signing out does not stop a running machine. Pause, Stop and recovery controls remain available.</p>
      <h2>Your data</h2><p>Full data export and account deletion are not available yet. Both will require a fresh identity verification.</p>
      ${await form('/account/export', 'export', 'Request data export', undefined, true)}${await form('/account/delete', 'delete', 'Delete account', undefined, true)}
      <p>Security audit records are retained for one year, including after account deletion. Posts made on GitHub remain on GitHub.</p>` };
  }
  const routes: Record<string, string> = { '/account/step-up': 'step_up', '/account/identities/link': 'link',
    '/account/identities/unlink': 'unlink', '/account/sessions/revoke': 'revoke', '/account/sessions/revoke-all': 'revoke_all',
    '/account/export': 'export', '/account/delete': 'delete' };
  const action = routes[url.pathname];
  if (request.method !== 'POST' || !action) return { body: 'Not found.', status: 404 };
  const body = new URLSearchParams(await readBody(request, 4096));
  const target = action === 'revoke' ? single(body, 'session') : action === 'unlink' ? single(body, 'identity') : null;
  if (target !== null) check(target.length <= 100 && !/[\s\x00-\x1f]/.test(target));
  for (const name of body.keys()) check(['csrf', ...(action === 'revoke' ? ['session'] : action === 'unlink' ? ['identity'] : [])].includes(name) && body.getAll(name).length === 1);
  await assertFormMutation(request, env.ACCOUNT_ORIGIN, formKey, session.id, target === null ? action : `${action}:${target}`, single(body, 'csrf'), now);
  if (action === 'revoke' || action === 'revoke_all') {
    await db.revoke(hash, target, now);
    return redirect(target === null || target === session.id ? { 'Set-Cookie': clearHostCookie(SID, 'Lax') } : {});
  }
  if (action !== 'step_up') await db.requireFresh(hash, now);
  if (action === 'export' || action === 'delete') return { body: '<p>This feature is not available yet. <a href="/account">Return to your account</a>.</p>', status: 501, html: true };
  if (action === 'unlink') {
    check(target !== null); await db.unlink(hash, target, now);
    const active = await new Store(env.IDENTITY).validate(hash, now);
    return redirect(active === null ? { 'Set-Cookie': clearHostCookie(SID, 'Lax') } : {});
  }
  const purpose = action === 'step_up' ? 'step_up' : 'link';
  await new Store(env.IDENTITY).rateLimit(await keyedHash(`management:${session.id}`, await key(env.RATE_KEY, 'HMAC')), now);
  const state = randomToken(); const nonce = randomToken(); const pkce = await createPkce();
  const stateHash = await hashToken(state); const nonceHash = await hashToken(nonce);
  const encrypted = await seal(pkce.verifier, stateKey, `${env.ACCOUNT_ORIGIN}|management|${purpose}|${session.id}|${stateHash}|${nonceHash}`);
  await db.start(hash, stateHash, nonceHash, encrypted, purpose, now);
  const destination = provider.authorizeUrl(state, pkce.challenge, { selectAccount: true });
  // A hyperlink avoids Chromium's form-action check on a form submission's redirect chain.
  // This response has no form and uses no-referrer; /account never gains a GitHub form-action exception.
  return { status: 200, html: true, headers: { 'Set-Cookie': hostCookie(NONCE, nonce, { sameSite: 'Lax', maxAge: 600 }) },
    body: `<p>${purpose === 'step_up' ? 'Choose a GitHub account already linked to this Synthetos account to verify your identity.' : 'Choose the GitHub account you want to link. It must not belong to another Synthetos account.'}</p><p><a href="${escapeHtml(destination)}" rel="noreferrer">Continue to GitHub</a></p><p><a href="/account">Back to account</a></p>` };
}
