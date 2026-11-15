import { utf8 } from '../../../packages/auth-core/src/encoding.ts';
import { hashToken } from '../../../packages/auth-core/src/index.ts';
import type { Store } from './store.ts';
import { check, readBody, HttpError } from './security.ts';
import { response } from './http.ts';

export async function githubWebhook(request: Request, store: Store, secretValue: string, now: number): Promise<Response> {
  check(request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() === 'application/json');
  const signature = request.headers.get('X-Hub-Signature-256') ?? '';
  check(/^sha256=[0-9a-f]{64}$/.test(signature), 403);
  const body = await readBody(request, 65_536);
  const secret = await crypto.subtle.importKey('raw', utf8(secretValue), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
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
