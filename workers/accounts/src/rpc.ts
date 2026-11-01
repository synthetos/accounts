import { AuthError } from '../../../packages/auth-core/src/index.ts';
import { HttpError } from './security.ts';
import type { Env } from './app.ts';
import { enabledStore, exchangeRun, tokenHash, view, type ExchangeContext, type ExchangeResult, type SessionView } from './oidc.ts';

/** Trusted service-binding contract. The RP checks its own CSRF/state/nonce before invoking mutations. */
export interface RunRpc {
  exchangeCode(code: string, verifier: string, context: ExchangeContext): Promise<ExchangeResult>;
  validateSession(token: string): Promise<SessionView | null>;
  revokeSession(token: string): Promise<void>;
  revokeAll(token: string): Promise<void>;
  listSessions(token: string): Promise<unknown[]>;
  requestDeletion(token: string): Promise<void>;
}
async function guarded<T>(operation: () => Promise<T>): Promise<T> {
  try { return await operation(); } catch (error) {
    // D1/runtime errors may contain SQL or bindings; never serialize those over RPC.
    throw new Error(error instanceof HttpError || error instanceof AuthError ? error.message : 'service_unavailable');
  }
}
/** No caller-selectable client or user id. Unit tests inject time; the exported entrypoint never does. */
export function runRpc(env: Env, now = Math.floor(Date.now() / 1000)): RunRpc {
  return {
    exchangeCode(code, verifier, context) { return guarded(() => exchangeRun(env, code, verifier, context, now)); },
    validateSession(token) { return guarded(async () => {
      const row = await enabledStore(env).validate(await tokenHash(token), 'run', now);
      return row === null ? null : view(row);
    }); },
    revokeSession(token) { return guarded(async () => { await enabledStore(env).revoke(await tokenHash(token), 'run', false, now); }); },
    revokeAll(token) { return guarded(async () => { await enabledStore(env).revoke(await tokenHash(token), 'run', true, now); }); },
    listSessions(token) { return guarded(async () => enabledStore(env).list(await tokenHash(token), 'run', now)); },
    requestDeletion(token) { return guarded(async () => { await enabledStore(env).requestDeletion(await tokenHash(token), 'run', now); }); },
  };
}
