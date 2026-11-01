import type { RunRpc } from '../../workers/accounts/src/rpc.ts';
declare const rpc: RunRpc;
void rpc.exchangeCode('code', 'verifier', { redirectUri: 'https://run.test/auth/callback', deviceRecordId: 'device' });
void rpc.validateSession('opaque-session-token');
// @ts-expect-error Identity is always derived from a session token.
void rpc.validateSession({ userId: 'usr_attacker' });
// @ts-expect-error No caller-selected client or user.
void rpc.validateSession('token', 'forum-synthetos');
// @ts-expect-error No raw user id parameter on revoke.
void rpc.revokeSession({ userId: 'usr_attacker' });
// @ts-expect-error No raw user id parameter on revoke-all.
void rpc.revokeAll({ userId: 'usr_attacker' });
// @ts-expect-error No raw user id parameter on listing.
void rpc.listSessions({ userId: 'usr_attacker' });
// @ts-expect-error No raw user id parameter on deletion.
void rpc.requestDeletion({ userId: 'usr_attacker' });
// @ts-expect-error Mandatory exact redirect and device context.
void rpc.exchangeCode('code', 'verifier');
// @ts-expect-error Identity and client cannot be supplied in trusted exchange context either.
void rpc.exchangeCode('code', 'verifier', { redirectUri: 'https://run.test/auth/callback', deviceRecordId: 'd', userId: 'usr_attacker', client: 'forum-synthetos' });
