import { GitHubProvider, ProviderError, type IdentityProvider } from '../../../packages/idp/src/index.ts';
import { AuthError, assertFormMutation, clearHostCookie, createFormToken, createPkce,
  hashToken, hostCookie, randomToken, readHostCookie } from '../../../packages/auth-core/src/index.ts';
import { utf8 } from '../../../packages/auth-core/src/encoding.ts';
import { ACCOUNT_ABSOLUTE, Store, type IdentityDatabase } from './store.ts';
import { check, escapeHtml, HttpError, key, keyedHash, readBody, returnPath, seal, single, unseal } from './security.ts';

export interface Env {
  AUTH_ENABLED?: string;
  ACCOUNT_ORIGIN?: string;
  GITHUB_APP_ID?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  OAUTH_STATE_KEY?: string;
  FORM_KEY?: string;
  RATE_KEY?: string;
  GITHUB_WEBHOOK_SECRET?: string;
  IDENTITY?: IdentityDatabase;
}
const SESSION = '__Host-acct_sid';
const PREAUTH = '__Host-acct_oauth';

function response(body: string | null, status = 200, extra: HeadersInit = {}, html = false): Response {
  const headers = new Headers(extra);
  headers.set('Content-Type', html ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Security-Policy', "default-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  headers.set('Permissions-Policy', 'serial=(), usb=(), hid=(), bluetooth=(), camera=(), microphone=(), geolocation=(), payment=()');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  headers.set('X-Frame-Options', 'DENY');
  return new Response(body, { status, headers });
}
function page(content: string): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Synthetos Accounts</title><main><h1>Synthetos Accounts</h1>${content}</main></html>`;
}

/** Test dependencies are injected by callers, never selected from requests or environment flags. */
export function createApp(deps: { provider?: IdentityProvider; now?: () => number } = {}) {
  return {
    async fetch(request: Request, env: Env = {}): Promise<Response> {
      try {
        if (env.AUTH_ENABLED !== 'true') return response('Identity service is not enabled.', 503);
        const origin = env.ACCOUNT_ORIGIN ?? '';
        check(new URL(origin).origin === origin && origin.startsWith('https://'), 503, 'service_unavailable');
        const url = new URL(request.url);
        check(url.origin === origin, 400);
        check(env.IDENTITY && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET && env.GITHUB_APP_ID &&
          /^[1-9][0-9]*$/.test(env.GITHUB_APP_ID) && env.GITHUB_APP_ID !== '5559540' &&
          env.OAUTH_STATE_KEY && env.FORM_KEY && env.RATE_KEY && env.GITHUB_WEBHOOK_SECRET &&
          utf8(env.GITHUB_WEBHOOK_SECRET).length >= 32, 503, 'service_unavailable');
        const now = (deps.now ?? (() => Math.floor(Date.now() / 1000)))();
        check(Number.isSafeInteger(now) && now >= 0 && now <= 281_474_976_710, 503, 'service_unavailable');
        const callback = `${origin}/auth/github/callback`;
        const provider = deps.provider ?? new GitHubProvider({ clientId: env.GITHUB_CLIENT_ID,
          clientSecret: env.GITHUB_CLIENT_SECRET, redirectUri: callback });
        check(provider.name === 'github', 503, 'service_unavailable');
        const store = new Store(env.IDENTITY);
        const formKey = await key(env.FORM_KEY, 'HMAC');
        const stateKey = await key(env.OAUTH_STATE_KEY, 'AES-GCM');

        if (url.pathname === '/login' && request.method === 'GET') {
          const returnTo = returnPath(url.searchParams.has('return_to') ? single(url.searchParams, 'return_to') : '/', origin);
          const nonce = randomToken();
          const csrf = await createFormToken(formKey, nonce, `login:${returnTo}`, now);
          return response(page(`<p>Sign in with your Synthetos GitHub account.</p><form method="post" action="/login"><input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="return_to" value="${returnTo}"><button type="submit">Sign in with GitHub</button></form>`),
            200, { 'Set-Cookie': hostCookie(PREAUTH, nonce, { sameSite: 'Lax', maxAge: 600 }) }, true);
        }
        if (url.pathname === '/login' && request.method === 'POST') {
          const nonce = readHostCookie(request.headers.get('Cookie'), PREAUTH); check(nonce, 403);
          const body = new URLSearchParams(await readBody(request, 4096));
          const returnTo = returnPath(single(body, 'return_to'), origin);
          await assertFormMutation(request, origin, formKey, nonce, `login:${returnTo}`, single(body, 'csrf'), now);
          // CF-Connecting-IP is set by Cloudflare; no X-Forwarded-For fallback. Missing metadata shares one fail-safe bucket.
          const bucket = await keyedHash(request.headers.get('CF-Connecting-IP') ?? 'missing-edge-ip', await key(env.RATE_KEY, 'HMAC'));
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
          check(!url.searchParams.has('error'));
          const state = single(url.searchParams, 'state'); const code = single(url.searchParams, 'code');
          check(state.length === 43 && code.length <= 1024 && !/[\s\x00-\x1f]/.test(code));
          const nonce = readHostCookie(request.headers.get('Cookie'), PREAUTH); check(nonce);
          const stateHash = await hashToken(state); const nonceHash = await hashToken(nonce);
          const flow = await store.consume(stateHash, nonceHash, callback, now);
          const verifier = await unseal(flow.pkce_verifier_enc, stateKey, `${origin}|${stateHash}|${nonceHash}`);
          // Credential exists only during these calls; only allowlisted profile fields reach storage.
          const profile = await provider.profile(await provider.exchange(code, verifier));
          const token = randomToken();
          await store.signIn(provider.name, profile, await hashToken(token), now, flow.created_at);
          const headers = new Headers({ Location: returnPath(flow.return_to, origin) });
          headers.append('Set-Cookie', hostCookie(SESSION, token, { sameSite: 'Lax', maxAge: ACCOUNT_ABSOLUTE }));
          headers.append('Set-Cookie', clearHostCookie(PREAUTH, 'Lax'));
          return response(null, 303, headers);
        }
        if (url.pathname === '/webhooks/github' && request.method === 'POST') {
          check(request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() === 'application/json');
          const signature = request.headers.get('X-Hub-Signature-256') ?? '';
          check(/^sha256=[0-9a-f]{64}$/.test(signature), 403);
          const body = await readBody(request, 65_536);
          const secret = await crypto.subtle.importKey('raw', utf8(env.GITHUB_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
          const bytes = Uint8Array.from(signature.slice(7).match(/../g) ?? [], (part) => parseInt(part, 16));
          check(await crypto.subtle.verify('HMAC', secret, bytes, utf8(body)), 403);
          check(request.headers.get('X-GitHub-Event') === 'github_app_authorization');
          const delivery = request.headers.get('X-GitHub-Delivery') ?? '';
          check(/^[a-zA-Z0-9-]{1,100}$/.test(delivery));
          const payload = JSON.parse(body) as { action?: unknown; sender?: { id?: unknown } };
          check(payload !== null && payload.action === 'revoked' && Number.isSafeInteger(payload.sender?.id) && (payload.sender?.id as number) > 0);
          const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(body))), (b) => b.toString(16).padStart(2, '0')).join('');
          try { await store.revokeFromWebhook(await hashToken(delivery), digest, String(payload.sender?.id), now); }
          catch { throw new HttpError(409, 'webhook_not_applied'); }
          return response(null, 204);
        }
        if ((url.pathname === '/' || url.pathname === '/account') && request.method === 'GET') {
          const token = readHostCookie(request.headers.get('Cookie'), SESSION);
          const session = token ? await store.validate(await hashToken(token), now) : null;
          if (session === null) return response(null, 303, { Location: '/login', 'Set-Cookie': clearHostCookie(SESSION, 'Lax') });
          return response(page(`<p>Signed in as ${escapeHtml(session.display_name)}.</p>`), 200, {}, true);
        }
        return response('Not found.', 404);
      } catch (error) {
        // Never log the request, URL, upstream error, token, code, state or cookie.
        if (error instanceof HttpError) return response(error.message, error.status);
        if (error instanceof AuthError) return response('request_refused', 403);
        if (error instanceof ProviderError) return response('sign_in_unavailable', 502);
        return response('service_unavailable', 503);
      }
    },
  };
}
