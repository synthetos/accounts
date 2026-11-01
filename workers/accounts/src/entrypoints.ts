import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Env } from './app.ts';
import type { ExchangeContext } from './oidc.ts';
import { runRpc, type RunRpc } from './rpc.ts';

// Do not add a generic client argument or export a factory as an entrypoint.
export class RunEntrypoint extends WorkerEntrypoint<Env> implements RunRpc {
  exchangeCode(code: string, verifier: string, context: ExchangeContext) { return runRpc(this.env).exchangeCode(code, verifier, context); }
  validateSession(token: string) { return runRpc(this.env).validateSession(token); }
  revokeSession(token: string) { return runRpc(this.env).revokeSession(token); }
  revokeAll(token: string) { return runRpc(this.env).revokeAll(token); }
  listSessions(token: string) { return runRpc(this.env).listSessions(token); }
  requestDeletion(token: string) { return runRpc(this.env).requestDeletion(token); }
}
