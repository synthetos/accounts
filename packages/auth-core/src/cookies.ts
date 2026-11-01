import { decodeBase64url } from './encoding.ts';
import { AuthError, requireAuth } from './errors.ts';

export interface CookieOptions {
  readonly sameSite: 'Strict' | 'Lax';
  /** Omit for a browser-session cookie (shared computers). */
  readonly maxAge?: number;
}

function validName(name: string): void {
  requireAuth(/^__Host-[A-Za-z0-9_-]+$/.test(name), 'invalid_cookie');
}

function validValue(value: string): void {
  try {
    requireAuth(decodeBase64url(value).length === 32, 'invalid_cookie');
  } catch {
    throw new AuthError('invalid_cookie');
  }
}

function suffix(options: CookieOptions): string {
  requireAuth(options.sameSite === 'Strict' || options.sameSite === 'Lax', 'invalid_cookie');
  let attributes = `; Path=/; Secure; HttpOnly; SameSite=${options.sameSite}`;
  if (options.maxAge !== undefined) {
    requireAuth(Number.isSafeInteger(options.maxAge) && options.maxAge >= 0, 'invalid_cookie');
    attributes += `; Max-Age=${options.maxAge}`;
  }
  return attributes;
}

export function hostCookie(name: string, token: string, options: CookieOptions): string {
  validName(name);
  validValue(token);
  return `${name}=${token}${suffix(options)}`;
}

export function clearHostCookie(name: string, sameSite: 'Strict' | 'Lax'): string {
  validName(name);
  return `${name}=${suffix({ sameSite, maxAge: 0 })}`;
}

/** Duplicate cookies fail closed rather than picking an attacker-controlled first/last value. */
export function readHostCookie(header: string | null, name: string): string | undefined {
  validName(name);
  if (header === null) return undefined;
  const matches = header.split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${name}=`));
  requireAuth(matches.length <= 1, 'invalid_cookie');
  const match = matches[0];
  if (match === undefined) return undefined;
  const value = match.slice(name.length + 1);
  validValue(value);
  return value;
}
