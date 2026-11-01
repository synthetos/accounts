import { base64url, decodeBase64url, decodeUtf8, utf8 } from './encoding.ts';
import { AuthError, requireAuth } from './errors.ts';

/** This helper accepts single-audience ID tokens only, never access tokens. */
export interface IdTokenClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly nbf?: number;
  readonly nonce?: string;
  readonly [key: string]: unknown;
}

export interface VerifyIdTokenOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly kid: string;
  readonly now: number;
  readonly nonce?: string;
  /** Set by the relying party, never read from an untrusted token. */
  readonly maxLifetimeSeconds: number;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function claimsShape(value: unknown): asserts value is IdTokenClaims {
  requireAuth(record(value), 'invalid_token');
  for (const name of ['iss', 'sub', 'aud']) requireAuth(typeof value[name] === 'string' && value[name].length > 0, 'invalid_token');
  for (const name of ['iat', 'exp']) requireAuth(Number.isSafeInteger(value[name]) && (value[name] as number) >= 0, 'invalid_token');
  requireAuth((value['exp'] as number) > (value['iat'] as number), 'invalid_token');
  if (value['nbf'] !== undefined) requireAuth(Number.isSafeInteger(value['nbf']) && (value['nbf'] as number) >= 0, 'invalid_token');
  if (value['nonce'] !== undefined) requireAuth(typeof value['nonce'] === 'string' && value['nonce'].length > 0, 'invalid_token');
}

function assertKey(key: CryptoKey, type: 'public' | 'private'): void {
  const algorithm = key.algorithm as EcKeyAlgorithm;
  requireAuth(key.type === type && algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-256', 'invalid_token');
}

export async function signIdToken(claims: IdTokenClaims, key: CryptoKey, kid: string): Promise<string> {
  assertKey(key, 'private');
  claimsShape(claims);
  requireAuth(kid.length > 0, 'invalid_input');
  const header = base64url(utf8(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid })));
  const payload = base64url(utf8(JSON.stringify(claims)));
  const input = `${header}.${payload}`;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

/** Caller supplies a trusted key and all expected claims; no token-provided URL is fetched. */
export async function verifyIdToken(token: string, key: CryptoKey, options: VerifyIdTokenOptions): Promise<IdTokenClaims> {
  requireAuth(Number.isSafeInteger(options.now) && options.now >= 0 &&
    Number.isSafeInteger(options.maxLifetimeSeconds) && options.maxLifetimeSeconds > 0 &&
    options.issuer.length > 0 && options.audience.length > 0 && options.kid.length > 0, 'invalid_input');
  try {
    assertKey(key, 'public');
    requireAuth(token.length <= 16_384, 'invalid_token');
    const parts = token.split('.');
    requireAuth(parts.length === 3, 'invalid_token');
    const [encodedHeader = '', encodedClaims = '', encodedSignature = ''] = parts;
    const header: unknown = JSON.parse(decodeUtf8(decodeBase64url(encodedHeader)));
    requireAuth(record(header), 'invalid_token');
    requireAuth(Object.keys(header).every((k) => ['alg', 'typ', 'kid'].includes(k)), 'invalid_token');
    requireAuth(header['alg'] === 'ES256' && header['typ'] === 'JWT' && header['kid'] === options.kid, 'invalid_token');
    const signature = decodeBase64url(encodedSignature);
    requireAuth(signature.length === 64, 'invalid_token');
    requireAuth(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature,
      utf8(`${encodedHeader}.${encodedClaims}`)), 'invalid_token');
    const claims: unknown = JSON.parse(decodeUtf8(decodeBase64url(encodedClaims)));
    claimsShape(claims);
    requireAuth(claims.iss === options.issuer && claims.aud === options.audience, 'invalid_token');
    requireAuth(claims.iat <= options.now && claims.exp > options.now &&
      claims.exp - claims.iat <= options.maxLifetimeSeconds, 'invalid_token');
    if (claims.nbf !== undefined) requireAuth(claims.nbf <= options.now, 'invalid_token');
    if (options.nonce !== undefined) requireAuth(claims.nonce === options.nonce, 'invalid_token');
    return claims;
  } catch {
    throw new AuthError('invalid_token');
  }
}
