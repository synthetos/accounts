import { base64url, utf8 } from './encoding.ts';
import { requireAuth } from './errors.ts';

/** 256 bits of entropy, for sessions, state, pre-auth nonces and auth codes. */
export function randomToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

/** Store this digest, never the bearer token. Hex is the database representation. */
export async function hashToken(token: string): Promise<string> {
  requireAuth(token.length > 0 && token.length <= 4096, 'invalid_input');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(token)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function pkceChallenge(verifier: string): Promise<string> {
  requireAuth(/^[A-Za-z0-9._~-]{43,128}$/.test(verifier), 'invalid_input');
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(verifier))));
}

export async function createPkce(): Promise<{ verifier: string; challenge: string; method: 'S256' }> {
  const verifier = randomToken();
  return { verifier, challenge: await pkceChallenge(verifier), method: 'S256' };
}
