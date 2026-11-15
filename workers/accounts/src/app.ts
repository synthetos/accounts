import { GitHubProvider, ProviderError, type IdentityProvider } from '../../../packages/idp/src/index.ts';
import { AuthError } from '../../../packages/auth-core/src/index.ts';
import { utf8 } from '../../../packages/auth-core/src/encoding.ts';
import { Store, type IdentityDatabase } from './store.ts';
import { check, HttpError, key } from './security.ts';

import { response } from './http.ts';
import { signInRoutes } from './sign-in.ts';
import { githubWebhook } from './github-webhook.ts';
import { people } from './people.ts';
import { page, accountStyles } from './page.ts';
import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import { account } from './account.ts';
import { oidc } from './oidc.ts';

export interface Env {
  ID_TOKEN_PRIVATE_JWK?: string;
  ID_TOKEN_PREVIOUS_JWKS?: string;
  AUTH_ENABLED?: string;
  GITHUB_ALLOWED_IDS?: string;
  OPEN_SIGNUP?: string;
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

/** Test dependencies are injected by callers, never selected from requests or environment flags. */
export function createApp(deps: { provider?: IdentityProvider; now?: () => number; lookupPerson?: (login: string) => Promise<ProviderProfile> } = {}) {
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
        const clock = deps.now ?? (() => Math.floor(Date.now() / 1000));
        const now = clock();
        check(Number.isSafeInteger(now) && now >= 0 && now <= 281_474_976_710, 503, 'service_unavailable');
        const callback = `${origin}/auth/github/callback`;
        const provider = deps.provider ?? new GitHubProvider({ clientId: env.GITHUB_CLIENT_ID,
          clientSecret: env.GITHUB_CLIENT_SECRET, redirectUri: callback });
        check(provider.name === 'github', 503, 'service_unavailable');
        const store = new Store(env.IDENTITY, env.GITHUB_ALLOWED_IDS, env.OPEN_SIGNUP === 'true');
        const formKey = await key(env.FORM_KEY, 'HMAC');
        const stateKey = await key(env.OAUTH_STATE_KEY, 'AES-GCM');

        if (url.pathname === '/assets/accounts.css' && request.method === 'GET') return response(accountStyles, 200, { 'Content-Type': 'text/css; charset=utf-8' });
        const administration = await people(request, env, now, formKey, deps.lookupPerson);
        if (administration) return response(administration.html ? page(administration.body ?? '') : administration.body, administration.status, administration.headers, administration.html, false, administration.form);

        const protocolResponse = await oidc(request, env, now);
        if (protocolResponse) return response(protocolResponse.body === null ? null : await protocolResponse.text(), protocolResponse.status, protocolResponse.headers);

        const management = await account(request, env, provider, now, formKey, stateKey, clock);
        if (management) return response(management.html ? page(management.body ?? '') : management.body, management.status, management.headers, management.html, false, management.form);

        const signIn = await signInRoutes(request, origin, store, provider, now, formKey, stateKey, env.RATE_KEY);
        if (signIn) return signIn;
        if (url.pathname === '/webhooks/github' && request.method === 'POST') return await githubWebhook(request, store, env.GITHUB_WEBHOOK_SECRET, now);
        return response('Not found.', 404);
      } catch (error) {
        // Never log the request, URL, upstream error, token, code, state or cookie.
        if (['/token','/introspect'].includes(new URL(request.url).pathname)) {
          const status = error instanceof HttpError ? error.status : error instanceof AuthError ? 400 : 503;
          const code = status === 401 ? 'invalid_client' : status === 429 ? 'rate_limited' : status >= 500 ? 'server_error' : new URL(request.url).pathname === '/introspect' ? 'invalid_request' : 'invalid_grant';
          return response(JSON.stringify({ error: code }), status, { 'Content-Type': 'application/json', ...(status === 401 ? { 'WWW-Authenticate': 'Basic realm="accounts"' } : {}), ...(status === 429 ? { 'Retry-After': '60' } : {}) });
        }
        if (error instanceof HttpError) return response(error.message, error.status);
        if (error instanceof AuthError) return response('request_refused', 403);
        if (error instanceof ProviderError) return response('sign_in_unavailable', 502);
        return response('service_unavailable', 503);
      }
    },
  };
}
