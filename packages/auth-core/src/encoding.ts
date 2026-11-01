import { AuthError, requireAuth } from './errors.ts';

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** Reject padding, noncanonical trailing bits and oversized inputs. */
export function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  requireAuth(value.length > 0 && value.length <= 65_536 && /^[A-Za-z0-9_-]+$/.test(value), 'invalid_input');
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    requireAuth(base64url(bytes) === value, 'invalid_input');
    return bytes;
  } catch {
    throw new AuthError('invalid_input');
  }
}

export const utf8 = (value: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(value);

export function decodeUtf8(bytes: Uint8Array<ArrayBuffer>): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
