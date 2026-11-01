import { clearHostCookie, hashToken, hostCookie, pkceChallenge, randomToken, readHostCookie, signIdToken } from '../../../packages/auth-core/src/index.ts';
import { base64url, decodeBase64url, utf8 } from '../../../packages/auth-core/src/encoding.ts';
import type { Env } from './app.ts';
import { OidcStore, type Authorization, type Client, type Identity, type Session } from './oidc-store.ts';
import { check, key, keyedHash, readBody, seal, single, unseal } from './security.ts';
import { Store } from './store.ts';

const CONTINUATION = '__Host-acct_authorize';
export interface ExchangeContext { redirectUri: string; deviceRecordId: string; sharedComputer?: boolean }
export interface SessionView {
  id: string; sub: string; name: string; client: string; identities: Identity[]; authAt: number;
  idleExpiresAt: number; absoluteExpiresAt: number; deviceRecordId: string | null; sharedComputer: boolean;
}
export interface ExchangeResult { sessionToken: string; idToken: string; expiresIn: number; session: SessionView }
export function view(row: Session): SessionView {
  return { id: row.id, sub: row.sub, name: row.name, client: row.client, identities: JSON.parse(row.identities_json) as Identity[],
    authAt: row.auth_at, idleExpiresAt: row.idle_expires_at, absoluteExpiresAt: row.abs_expires_at,
    deviceRecordId: row.device_record_id, sharedComputer: row.shared_computer === 1 };
}
function bounded(value: unknown, max = 1024): asserts value is string {
  check(typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x20\x7f]/.test(value));
}
export async function tokenHash(value: string): Promise<string> {
  check(typeof value === 'string' && value.length === 43 && decodeBase64url(value).length === 32);
  return hashToken(value);
}
function issuer(env: Env): string {
  const value = env.ACCOUNT_ORIGIN ?? '';
  check(value.startsWith('https://') && new URL(value).origin === value, 503, 'service_unavailable'); return value;
}
export function enabledStore(env: Env): OidcStore {
  check(env.AUTH_ENABLED === 'true' && env.IDENTITY, 503, 'service_unavailable'); issuer(env);
  return new OidcStore(env.IDENTITY);
}
function redirect(client: Client, value: string): void {
  bounded(value, 2048);
  const url = new URL(value);
  check(url.protocol === 'https:' && !url.username && !url.password && !url.hash);
  const registered: unknown = JSON.parse(client.redirect_uris_json);
  check(Array.isArray(registered) && registered.includes(value));
  // The run binding has one callback; deployment registration must not create ambiguous return paths.
  if (client.id === 'run') check(registered.length === 1 && client.kind === 'binding');
}
async function authorization(params: URLSearchParams, store: OidcStore): Promise<Authorization> {
  // Unsupported request objects, response modes, scopes and prompt combinations fail closed.
  const allowed = ['response_type','client_id','redirect_uri','scope','state','code_challenge','code_challenge_method','nonce','prompt'];
  for (const name of params.keys()) check(allowed.includes(name) && params.getAll(name).length === 1);
  check(single(params, 'response_type') === 'code' && single(params, 'scope') === 'openid' && single(params, 'code_challenge_method') === 'S256');
  const id = single(params, 'client_id'); bounded(id, 100);
  const client = await store.client(id); check(client !== null && id !== 'accounts');
  const redirectUri = single(params, 'redirect_uri'); redirect(client, redirectUri);
  const challenge = single(params, 'code_challenge'); check(challenge.length === 43 && decodeBase64url(challenge).length === 32);
  const state = single(params, 'state'); bounded(state);
  const nonce = params.has('nonce') ? single(params, 'nonce') : null; if (nonce !== null) bounded(nonce);
  const prompt = params.has('prompt') ? single(params, 'prompt') : null; check(prompt === null || prompt === 'none');
  return { client: id, redirectUri, challenge, state, nonce, prompt };
}
interface PublicKey extends JsonWebKey { kid: string; alg: 'ES256'; use: 'sig'; kty: 'EC'; crv: 'P-256'; x: string; y: string }
async function publicJwk(value: JsonWebKey): Promise<PublicKey> {
  check(value.kty === 'EC' && value.crv === 'P-256' && typeof value.x === 'string' && typeof value.y === 'string' &&
    decodeBase64url(value.x).length === 32 && decodeBase64url(value.y).length === 32, 503, 'service_unavailable');
  // RFC 7638: required public EC members only, in lexicographic member order.
  const canonical = JSON.stringify({ crv: 'P-256', kty: 'EC', x: value.x, y: value.y });
  const kid = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(canonical))));
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y, kid, alg: 'ES256', use: 'sig' };
}
async function signing(env: Env): Promise<{ privateKey: CryptoKey; kid: string; keys: PublicKey[] }> {
  check(env.ID_TOKEN_PRIVATE_JWK, 503, 'service_unavailable');
  const jwk = JSON.parse(env.ID_TOKEN_PRIVATE_JWK) as JsonWebKey;
  const current = await publicJwk(jwk);
  check(typeof jwk.d === 'string' && decodeBase64url(jwk.d).length === 32, 503, 'service_unavailable');
  const privateKey = await crypto.subtle.importKey('jwk', { ...current, d: jwk.d }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const publicKey = await crypto.subtle.importKey('jwk', current, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  // Refuse inconsistent private/public coordinates before any one-use code is consumed.
  const proof = utf8('synthetos-signing-key-check');
  check(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey,
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, proof), proof), 503, 'service_unavailable');
  const keys = [current];
  if (env.ID_TOKEN_PREVIOUS_JWKS) {
    const previous: unknown = JSON.parse(env.ID_TOKEN_PREVIOUS_JWKS);
    check(Array.isArray(previous) && previous.length <= 4, 503, 'service_unavailable');
    for (const entry of previous as (JsonWebKey & { kid?: string })[]) {
      check(entry && entry.d === undefined, 503, 'service_unavailable');
      const published = await publicJwk(entry);
      check((entry.kid === undefined || entry.kid === published.kid) && !keys.some((k) => k.kid === published.kid), 503, 'service_unavailable');
      await crypto.subtle.importKey('jwk', published, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      keys.push(published);
    }
  }
  return { privateKey, kid: current.kid, keys };
}
async function exchange(env: Env, client: Client, code: string, verifier: string, context: { redirectUri: string; device: string | null; shared: boolean }, now: number): Promise<ExchangeResult> {
  redirect(client, context.redirectUri);
  const codeHash = await tokenHash(code); const challenge = await pkceChallenge(verifier);
  const signer = await signing(env);
  const token = randomToken();
  const row = await enabledStore(env).redeem({ codeHash, challenge, client: client.id, kind: client.kind,
    secretHash: client.secret_hash, redirectUri: context.redirectUri, device: context.device, shared: context.shared, tokenHash: await hashToken(token) }, now);
  const session = view(row);
  const idToken = await signIdToken({ iss: issuer(env), sub: row.sub, aud: client.id, iat: now, exp: now + 60,
    auth_time: row.auth_at, identities: session.identities, ...(row.nonce === null ? {} : { nonce: row.nonce }) }, signer.privateKey, signer.kid);
  return { sessionToken: token, idToken, expiresIn: row.idle_expires_at - now, session };
}
export async function exchangeRun(env: Env, code: string, verifier: string, context: ExchangeContext, now: number): Promise<ExchangeResult> {
  check(context && typeof context === 'object' && Object.keys(context).every((k) => ['redirectUri','deviceRecordId','sharedComputer'].includes(k)));
  bounded(context.deviceRecordId, 256); check(context.sharedComputer === undefined || typeof context.sharedComputer === 'boolean');
  const client = await enabledStore(env).client('run'); check(client?.kind === 'binding', 503, 'service_unavailable');
  return exchange(env, client, code, verifier, { redirectUri: context.redirectUri, device: context.deviceRecordId, shared: context.sharedComputer ?? false }, now);
}
/** Called inside the application's response-header wrapper. All failures are local, never redirected to an unverified URI. */
export async function oidc(request: Request, env: Env, now: number): Promise<Response | null> {
  const url = new URL(request.url); const origin = issuer(env);
  const store = enabledStore(env);
  if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    return Response.json({ issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, jwks_uri: `${origin}/jwks`,
      response_types_supported: ['code'], response_modes_supported: ['query'], grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['ES256'], token_endpoint_auth_methods_supported: ['client_secret_basic'],
      scopes_supported: ['openid'], code_challenge_methods_supported: ['S256'], claims_supported: ['iss','sub','aud','iat','exp','auth_time','nonce','identities'],
      request_parameter_supported: false, request_uri_parameter_supported: false });
  }
  if (request.method === 'GET' && url.pathname === '/jwks') return Response.json({ keys: (await signing(env)).keys });
  if (request.method === 'POST' && url.pathname === '/token') {
    // Confidential server back-channel only. No cookie auth, browser Origin or CORS relaxation.
    check(!request.headers.has('Origin') && request.headers.get('Content-Type')?.split(';')[0]?.trim() === 'application/x-www-form-urlencoded', 400);
    const header = request.headers.get('Authorization') ?? ''; check(header.startsWith('Basic ') && header.length <= 4096, 401, 'invalid_client');
    let decoded = ''; try { decoded = atob(header.slice(6)); } catch { check(false, 401, 'invalid_client'); }
    const colon = decoded.indexOf(':'); check(colon > 0, 401, 'invalid_client');
    // RFC 6749 2.3.1 encodes client id/secret as application/x-www-form-urlencoded before Basic.
    const decode = (part: string) => decodeURIComponent(part.replaceAll('+', ' '));
    const id = decode(decoded.slice(0, colon)); const secret = decode(decoded.slice(colon + 1)); bounded(secret, 1024);
    const client = await store.client(id); check(client?.kind === 'confidential' && client.secret_hash, 401, 'invalid_client');
    const supplied = await hashToken(secret);
    // Constant-time compare through WebCrypto, never a JS early-exit byte loop.
    const comparisonKey = await crypto.subtle.importKey('raw', utf8(client.secret_hash), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign','verify']);
    const candidateKey = await crypto.subtle.importKey('raw', utf8(supplied), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    check(await crypto.subtle.verify('HMAC', comparisonKey, await crypto.subtle.sign('HMAC', candidateKey, utf8('client-secret')), utf8('client-secret')), 401, 'invalid_client');
    const body = new URLSearchParams(await readBody(request, 8192));
    for (const name of body.keys()) check(['grant_type','code','code_verifier','redirect_uri'].includes(name) && body.getAll(name).length === 1);
    check(single(body, 'grant_type') === 'authorization_code');
    const result = await exchange(env, client, single(body, 'code'), single(body, 'code_verifier'),
      { redirectUri: single(body, 'redirect_uri'), device: null, shared: false }, now);
    return Response.json({ access_token: result.sessionToken, token_type: 'Bearer', expires_in: result.expiresIn, id_token: result.idToken, scope: 'openid' });
  }
  if (request.method !== 'GET' || (url.pathname !== '/authorize' && !url.pathname.startsWith('/authorize/resume/'))) return null;
  check(env.IDENTITY && env.OAUTH_STATE_KEY && env.RATE_KEY, 503, 'service_unavailable');
  const stateKey = await key(env.OAUTH_STATE_KEY, 'AES-GCM');
  const accountToken = readHostCookie(request.headers.get('Cookie'), '__Host-acct_sid');
  const accountHash = accountToken ? await hashToken(accountToken) : null;
  const account = accountHash ? await new Store(env.IDENTITY).validate(accountHash, now) : null;
  let flow: Authorization;
  let clearContinuation = false;
  if (url.pathname === '/authorize') {
    flow = await authorization(url.searchParams, store);
    if (account === null || accountHash === null) {
      if (flow.prompt === 'none') {
        const target = new URL(flow.redirectUri); target.searchParams.set('error','login_required'); target.searchParams.set('state',flow.state);
        return new Response(null, { status: 303, headers: { Location: target.href } });
      }
      await new Store(env.IDENTITY).rateLimit(await keyedHash(`authorize:${request.headers.get('CF-Connecting-IP') ?? 'missing-edge-ip'}`, await key(env.RATE_KEY, 'HMAC')), now);
      const resume = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2,'0')).join('');
      const nonce = randomToken(); const hash = await hashToken(resume); const nonceHash = await hashToken(nonce);
      await store.startResume(hash, nonceHash, await seal(url.searchParams.toString(), stateKey, `${origin}|${hash}|${nonceHash}`), now);
      return new Response(null, { status: 303, headers: { Location: `/login?return_to=/authorize/resume/${resume}`,
        'Set-Cookie': hostCookie(CONTINUATION, nonce, { sameSite: 'Lax', maxAge: 600 }) } });
    }
  } else {
    const resume = url.pathname.slice('/authorize/resume/'.length);
    check(resume.length === 64 && !/[^a-f0-9]/.test(resume) && !url.search);
    const nonce = readHostCookie(request.headers.get('Cookie'), CONTINUATION); check(nonce);
    if (account === null || accountHash === null) return new Response(null, { status: 303, headers: { Location: `/login?return_to=${url.pathname}` } });
    const hash = await hashToken(resume); const nonceHash = await hashToken(nonce);
    const encrypted = await store.consumeResume(hash, nonceHash, now);
    flow = await authorization(new URLSearchParams(await unseal(encrypted, stateKey, `${origin}|${hash}|${nonceHash}`)), store);
    clearContinuation = true;
  }
  check(accountHash !== null);
  const code = randomToken(); await store.issue(await hashToken(code), accountHash, flow, now);
  const target = new URL(flow.redirectUri); target.searchParams.set('code',code); target.searchParams.set('state',flow.state);
  const headers = new Headers({ Location: target.href }); if (clearContinuation) headers.set('Set-Cookie', clearHostCookie(CONTINUATION,'Lax'));
  return new Response(null, { status: 303, headers });
}
