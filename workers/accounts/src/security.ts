import { base64url, decodeBase64url, utf8 } from '../../../packages/auth-core/src/encoding.ts';

export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}
export function check(condition: unknown, status = 400, message = 'request_refused'): asserts condition {
  if (!condition) throw new HttpError(status, message);
}
export async function readBody(request: Request, max: number): Promise<string> {
  check(request.body !== null);
  const reader = request.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let text = ''; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length; check(size <= max, 413, 'request_too_large');
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { await reader.cancel(); }
}
export function single(params: URLSearchParams, name: string): string {
  const values = params.getAll(name);
  check(values.length === 1 && values[0] !== undefined && values[0].length > 0);
  return values[0];
}
export function returnPath(value: string, origin: string): string {
  check(value.length <= 256 && /^\/(?![/\\])[a-z0-9/_-]*$/.test(value) && !/[^a-z0-9/_-]/.test(value) && new URL(value, origin).origin === origin);
  return value;
}
export function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
export async function key(encoded: string, algorithm: 'AES-GCM' | 'HMAC'): Promise<CryptoKey> {
  const bytes = decodeBase64url(encoded); check(bytes.length === 32, 503, 'service_unavailable');
  return crypto.subtle.importKey('raw', bytes, algorithm === 'HMAC' ? { name: 'HMAC', hash: 'SHA-256' } : algorithm,
    false, algorithm === 'HMAC' ? ['sign', 'verify'] : ['encrypt', 'decrypt']);
}
export async function seal(value: string, secret: CryptoKey, binding: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(binding) }, secret, utf8(value));
  return `${base64url(iv)}.${base64url(new Uint8Array(encrypted))}`;
}
export async function unseal(value: string, secret: CryptoKey, binding: string): Promise<string> {
  const parts = value.split('.'); check(parts.length === 2);
  const iv = decodeBase64url(parts[0] ?? ''); check(iv.length === 12);
  return new TextDecoder('utf-8', { fatal: true }).decode(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(binding) }, secret, decodeBase64url(parts[1] ?? '')));
}
export async function keyedHash(value: string, secret: CryptoKey): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', secret, utf8(value))));
}
export function userId(now: number): string {
  let value = BigInt(now * 1000);
  for (const byte of crypto.getRandomValues(new Uint8Array(10))) value = (value << 8n) | BigInt(byte);
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let encoded = '';
  for (let i = 0; i < 26; i++) { encoded = alphabet[Number(value & 31n)] + encoded; value >>= 5n; }
  return `usr_${encoded}`;
}
