import { hashToken } from '../../../packages/auth-core/src/index.ts';
import { utf8 } from '../../../packages/auth-core/src/encoding.ts';
import { check } from './security.ts';
import type { Client, OidcStore } from './oidc-store.ts';

export async function confidentialClient(request: Request, store: OidcStore): Promise<Client> {
  // Confidential server back-channel only. No cookie auth, browser Origin or CORS relaxation.
  check(!request.headers.has('Origin') && request.headers.get('Content-Type')?.split(';')[0]?.trim() === 'application/x-www-form-urlencoded', 400);
  const header = request.headers.get('Authorization') ?? ''; check(header.startsWith('Basic ') && header.length <= 4096, 401, 'invalid_client');
  let decoded = ''; try { decoded = atob(header.slice(6)); } catch { check(false, 401, 'invalid_client'); }
  const colon = decoded.indexOf(':'); check(colon > 0, 401, 'invalid_client');
  // RFC 6749 2.3.1 encodes client id/secret as application/x-www-form-urlencoded before Basic.
  const decode = (part: string) => {
    try { return decodeURIComponent(part.replaceAll('+', ' ')); } catch { check(false, 401, 'invalid_client'); }
  };
  const id = decode(decoded.slice(0, colon)); const secret = decode(decoded.slice(colon + 1));
  check(secret.length > 0 && secret.length <= 1024 && !/[\x00-\x20\x7f]/.test(secret), 401, 'invalid_client');
  const client = await store.client(id);
  // Client ids are public, but unknown/binding clients still run the same HMAC comparison.
  const expectedHash = client?.kind === 'confidential' ? client.secret_hash : null;
  const supplied = await hashToken(secret);
  // Constant-time compare through WebCrypto, never a JS early-exit byte loop.
  const comparisonKey = await crypto.subtle.importKey('raw', utf8(expectedHash ?? '0'.repeat(64)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign','verify']);
  const candidateKey = await crypto.subtle.importKey('raw', utf8(supplied), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const matches = await crypto.subtle.verify('HMAC', comparisonKey, await crypto.subtle.sign('HMAC', candidateKey, utf8('client-secret')), utf8('client-secret'));
  check(matches && client?.kind === 'confidential' && expectedHash, 401, 'invalid_client');
  return client;
}
