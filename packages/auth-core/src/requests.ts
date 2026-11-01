import { base64url, decodeBase64url, utf8 } from './encoding.ts';
import { AuthError, requireAuth } from './errors.ts';

function assertOrigin(request: Request, origin: string): void {
  const parsed = new URL(origin);
  requireAuth(parsed.protocol === 'https:' && parsed.origin === origin, 'invalid_input');
  requireAuth(request.headers.get('Origin') === origin, 'csrf_denied');
  const site = request.headers.get('Sec-Fetch-Site');
  requireAuth(site === null || site === 'same-origin', 'csrf_denied');
  requireAuth(['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method), 'csrf_denied');
}

function contentType(request: Request): string | undefined {
  return request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase();
}

/** Script-driven API mutations. Does not establish authentication or authorization. */
export function assertApiMutation(request: Request, origin: string, allowBinary = false): void {
  assertOrigin(request, origin);
  requireAuth(request.headers.get('X-Synthetos-Request') === '1', 'csrf_denied');
  const type = contentType(request);
  requireAuth(type === 'application/json' || (allowBinary && type === 'application/octet-stream'), 'csrf_denied');
}

function formPayload(sessionId: string, action: string, expiry: number): Uint8Array<ArrayBuffer> {
  requireAuth(sessionId.length > 0 && action.length > 0, 'invalid_input');
  // Tuple encoding avoids collisions such as (ab,c) vs (a,bc).
  return utf8(JSON.stringify(['synthetos:form:v1', sessionId, action, expiry]));
}

function assertHmacKey(key: CryptoKey): void {
  const algorithm = key.algorithm as HmacKeyAlgorithm;
  requireAuth(algorithm.name === 'HMAC' && algorithm.hash.name === 'SHA-256' && algorithm.length >= 256, 'invalid_input');
}

export async function createFormToken(key: CryptoKey, sessionId: string, action: string, now: number): Promise<string> {
  requireAuth(Number.isSafeInteger(now) && now >= 0 && now <= Number.MAX_SAFE_INTEGER - 600, 'invalid_input');
  assertHmacKey(key);
  const expiry = now + 600;
  const signature = await crypto.subtle.sign('HMAC', key, formPayload(sessionId, action, expiry));
  return `${expiry}.${base64url(new Uint8Array(signature))}`;
}

/** Server-rendered form mutations use a synchronizer token, not the API-only custom header. */
export async function assertFormMutation(
  request: Request, origin: string, key: CryptoKey, sessionId: string, action: string, token: string, now: number,
): Promise<void> {
  assertOrigin(request, origin);
  requireAuth(request.method === 'POST' && contentType(request) === 'application/x-www-form-urlencoded', 'csrf_denied');
  requireAuth(Number.isSafeInteger(now) && now >= 0, 'invalid_input');
  assertHmacKey(key);
  try {
    const parts = token.split('.');
    requireAuth(parts.length === 2 && /^[0-9]+$/.test(parts[0] ?? ''), 'csrf_denied');
    const expiry = Number(parts[0]);
    requireAuth(Number.isSafeInteger(expiry) && String(expiry) === parts[0] && expiry > now && expiry <= now + 600, 'csrf_denied');
    const signature = decodeBase64url(parts[1] ?? '');
    requireAuth(signature.length === 32, 'csrf_denied');
    requireAuth(await crypto.subtle.verify('HMAC', key, signature, formPayload(sessionId, action, expiry)), 'csrf_denied');
  } catch {
    throw new AuthError('csrf_denied');
  }
}
