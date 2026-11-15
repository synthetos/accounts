import type { IdentityProvider } from '../../../packages/idp/src/index.ts';
import { assertFormMutation, clearHostCookie, createFormToken, createPkce, hashToken, hostCookie, randomToken, readHostCookie } from '../../../packages/auth-core/src/index.ts';
import { ACCOUNT_ABSOLUTE, type Store } from './store.ts';
import { check, escapeHtml, key, keyedHash, readBody, returnPath, seal, single, unseal } from './security.ts';
import { coarseClient } from './account.ts';
import { response } from './http.ts';
import { page } from './page.ts';
const SESSION = '__Host-acct_sid';
const PREAUTH = '__Host-acct_oauth';

export async function signInRoutes(request: Request, origin: string, store: Store, provider: IdentityProvider,
  now: number, formKey: CryptoKey, stateKey: CryptoKey, rateKey: string): Promise<Response | null> {
  const url = new URL(request.url); const callback = `${origin}/auth/github/callback`;
  if (url.pathname === '/login' && request.method === 'GET') {
    const returnTo = returnPath(url.searchParams.has('return_to') ? single(url.searchParams, 'return_to') : '/', origin);
    const nonce = randomToken();
    const csrf = await createFormToken(formKey, nonce, `login:${returnTo}`, now);
    return response(page(`<p>Sign in with your Synthetos GitHub account.</p><form method="post" action="/login"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="return_to" value="${escapeHtml(returnTo)}"><button type="submit">Sign in with GitHub</button></form>`),
      200, { 'Set-Cookie': hostCookie(PREAUTH, nonce, { sameSite: 'Lax', maxAge: 600 }) }, true, true);
  }
  if (url.pathname === '/login' && request.method === 'POST') {
    const nonce = readHostCookie(request.headers.get('Cookie'), PREAUTH); check(nonce, 403);
    const body = new URLSearchParams(await readBody(request, 4096));
    const returnTo = returnPath(single(body, 'return_to'), origin);
    await assertFormMutation(request, origin, formKey, nonce, `login:${returnTo}`, single(body, 'csrf'), now);
    // CF-Connecting-IP is set by Cloudflare; no X-Forwarded-For fallback. Missing metadata shares one fail-safe bucket.
    const bucket = await keyedHash(request.headers.get('CF-Connecting-IP') ?? 'missing-edge-ip', await key(rateKey, 'HMAC'));
    await store.rateLimit(bucket, now);
    const state = randomToken(); const oauthNonce = randomToken(); const pkce = await createPkce();
    const stateHash = await hashToken(state); const nonceHash = await hashToken(oauthNonce);
    const encrypted = await seal(pkce.verifier, stateKey, `${origin}|${stateHash}|${nonceHash}`);
    await store.start({ state_hash: stateHash, browser_nonce_hash: nonceHash, pkce_verifier_enc: encrypted,
      return_to: returnTo, created_at: now }, callback, now);
    return response(null, 303, { Location: provider.authorizeUrl(state, pkce.challenge),
      'Set-Cookie': hostCookie(PREAUTH, oauthNonce, { sameSite: 'Lax', maxAge: 600 }) });
  }
  if (url.pathname === '/auth/github/callback' && request.method === 'GET') {
    // OAuth callback is the protocol-mandated GET exception: nonce-bound single-use state is mandatory.
    const state = single(url.searchParams, 'state');
    const cancelled = url.searchParams.has('error');
    const code = cancelled ? '' : single(url.searchParams, 'code');
    check(state.length === 43 && (cancelled || (code.length <= 1024 && !/[\s\x00-\x1f]/.test(code))));
    if (cancelled) check(single(url.searchParams, 'error') === 'access_denied');
    const nonce = readHostCookie(request.headers.get('Cookie'), PREAUTH); check(nonce);
    const stateHash = await hashToken(state); const nonceHash = await hashToken(nonce);
    const flow = await store.consume(stateHash, nonceHash, callback, now);
    if (cancelled) {
      // Only a browser-bound cancellation consumes the flow or clears its cookie.
      return response(page('<p>Sign-in was cancelled. <a href="/login">Try again</a>.</p>'), 400,
        { 'Set-Cookie': clearHostCookie(PREAUTH, 'Lax') }, true);
    }
    const verifier = await unseal(flow.pkce_verifier_enc, stateKey, `${origin}|${stateHash}|${nonceHash}`);
    // Credential exists only during these calls; only allowlisted profile fields reach storage.
    const profile = await provider.profile(await provider.exchange(code, verifier));
    const token = randomToken();
    await store.signIn(provider.name, profile, await hashToken(token), now, flow.created_at, coarseClient(request));
    const headers = new Headers({ Location: returnPath(flow.return_to, origin) });
    headers.append('Set-Cookie', hostCookie(SESSION, token, { sameSite: 'Lax', maxAge: ACCOUNT_ABSOLUTE }));
    headers.append('Set-Cookie', clearHostCookie(PREAUTH, 'Lax'));
    return response(null, 303, headers);
  }
  return null;
}
