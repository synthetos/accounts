import { randomToken } from '../../../packages/auth-core/src/index.ts';
import { check } from './security.ts';
import type { DatabaseSession, IdentityDatabase, Statement } from './store.ts';

export interface Client { id: string; kind: 'binding' | 'confidential'; redirect_uris_json: string; secret_hash: string | null }
export interface Authorization { client: string; redirectUri: string; challenge: string; state: string; nonce: string | null; prompt: 'none' | null }
export interface Identity { provider: string; id: string; login: string }
export interface Session {
  id: string; sub: string; name: string; client: string; auth_at: number; step_up_at: number | null;
  created_at: number; last_seen_at: number; idle_expires_at: number; abs_expires_at: number;
  device_record_id: string | null; shared_computer: number; identities_json: string;
}
const ACTIVE = `s.revoked_at IS NULL AND s.idle_expires_at>? AND s.abs_expires_at>? AND s.created_at<=? AND u.status='active'`;
const SESSION_FIELDS = `s.id,u.id AS sub,u.display_name AS name,s.client,s.auth_at,s.step_up_at,
  s.created_at,s.last_seen_at,s.idle_expires_at,s.abs_expires_at,s.device_record_id,s.shared_computer,
  (SELECT json_group_array(json_object('provider',provider,'id',provider_subject,'login',login)) FROM identities WHERE user_id=u.id) AS identities_json`;
export const RP_IDLE = 12 * 3600;
export const RP_ABSOLUTE = 7 * 86400;

/** Each instance starts with a primary read; no identity or session cache survives requests. */
export class OidcStore {
  private readonly db: DatabaseSession;
  constructor(database: IdentityDatabase) { this.db = database.withSession('first-primary'); }
  private q(sql: string, ...args: (string | number | null)[]): Statement { return this.db.prepare(sql).bind(...args); }
  client(id: string): Promise<Client | null> {
    return this.q('SELECT id,kind,redirect_uris_json,secret_hash FROM oauth_clients WHERE id=?', id).first<Client>();
  }
  async startResume(hash: string, nonce: string, encrypted: string, now: number): Promise<void> {
    await this.db.batch([
      this.q(`DELETE FROM authorization_requests WHERE resume_hash IN
        (SELECT resume_hash FROM authorization_requests WHERE expires_at<=? ORDER BY expires_at LIMIT 100)`, now),
      this.q('INSERT INTO authorization_requests(resume_hash,browser_nonce_hash,request_enc,created_at,expires_at) VALUES (?,?,?,?,?)', hash, nonce, encrypted, now, now + 600),
    ]);
  }
  async consumeResume(hash: string, nonce: string, now: number): Promise<string> {
    const row = await this.q(`UPDATE authorization_requests SET used_at=? WHERE resume_hash=? AND browser_nonce_hash=?
      AND used_at IS NULL AND created_at<=? AND expires_at>? RETURNING request_enc`, now, hash, nonce, now, now).first<{ request_enc: string }>();
    check(row !== null); return row.request_enc;
  }
  async issue(codeHash: string, accountHash: string, request: Authorization, now: number): Promise<void> {
    const results = await this.db.batch([
      this.q(`INSERT INTO auth_codes(code_hash,user_id,client,redirect_uri,code_challenge,auth_at,expires_at,nonce,origin_session_id,step_up_at)
      SELECT ?,s.user_id,?,?,?,s.auth_at,?,?,s.id,s.step_up_at FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=? AND s.client='accounts' AND ${ACTIVE}
      AND EXISTS(SELECT 1 FROM oauth_clients c,json_each(c.redirect_uris_json) r WHERE c.id=? AND r.type='text' AND r.value=?)`,
    codeHash, request.client, request.redirectUri, request.challenge, now + 60, request.nonce, accountHash, now, now, now, request.client, request.redirectUri),
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event,detail_json)
        SELECT ?,user_id,?,origin_session_id,client,'authorization.code_issued',json_object('auth_at',auth_at)
        FROM auth_codes WHERE code_hash=?`, `aud_${randomToken()}`, now, codeHash),
    ]);
    check(results[0]?.meta.changes === 1 && results[1]?.meta.changes === 1, 403, 'authorization_refused');
  }
  async redeem(input: { codeHash: string; challenge: string; client: string; kind: string; secretHash: string | null;
    redirectUri: string; device: string | null; shared: boolean; tokenHash: string }, now: number): Promise<Session & { nonce: string | null }> {
    const attempt = randomToken(); const id = `ses_${randomToken()}`;
    const result = await this.db.batch([
      this.q(`UPDATE auth_codes SET used_at=?,redemption_id=? WHERE code_hash=? AND client=? AND redirect_uri=? AND code_challenge=?
        AND used_at IS NULL AND expires_at>? AND auth_at<=? AND origin_session_id IN
        (SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.client='accounts' AND ${ACTIVE} AND s.user_id=auth_codes.user_id)
        AND EXISTS(SELECT 1 FROM oauth_clients c,json_each(c.redirect_uris_json) r WHERE c.id=auth_codes.client
          AND c.kind=? AND c.secret_hash IS ? AND r.type='text' AND r.value=auth_codes.redirect_uri)`,
      now, attempt, input.codeHash, input.client, input.redirectUri, input.challenge, now, now, now, now, now, input.kind, input.secretHash),
      // A unique attempt marker, not used_at=now: two exchanges in the same second cannot both mint sessions.
      this.q(`INSERT INTO sessions(token_hash,id,user_id,client,device_record_id,created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at,shared_computer,step_up_at,sign_in_identity_id,ua_summary,country)
        SELECT ?,?,user_id,client,?,?,?,?,?,auth_at,?,step_up_at,(SELECT sign_in_identity_id FROM sessions WHERE id=auth_codes.origin_session_id),
        (SELECT ua_summary FROM sessions WHERE id=auth_codes.origin_session_id),(SELECT country FROM sessions WHERE id=auth_codes.origin_session_id) FROM auth_codes WHERE redemption_id=?`,
      input.tokenHash, id, input.device, now, now, now + (input.shared ? 3600 : RP_IDLE), now + RP_ABSOLUTE, input.shared ? 1 : 0, attempt),
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,user_id,?,id,client,'session.created' FROM sessions WHERE id=?`, `aud_${randomToken()}`, now, id),
    ]);
    check(result[0]?.meta.changes === 1 && result[1]?.meta.changes === 1, 400, 'invalid_grant');
    const row = await this.q(`SELECT ${SESSION_FIELDS},c.nonce FROM sessions s JOIN users u ON u.id=s.user_id
      JOIN auth_codes c ON c.redemption_id=? WHERE s.id=? AND ${ACTIVE}`, attempt, id, now, now, now).first<Session & { nonce: string | null }>();
    check(row !== null, 400, 'invalid_grant'); return row;
  }
  private read(hash: string, client: string, now: number): Promise<Session | null> {
    return this.q(`SELECT ${SESSION_FIELDS} FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=? AND s.client=? AND ${ACTIVE}`, hash, client, now, now, now).first<Session>();
  }
  async validate(hash: string, client: string, now: number): Promise<Session | null> {
    const row = await this.read(hash, client, now);
    if (row === null || now - row.last_seen_at < 300) return row;
    await this.q(`UPDATE sessions SET last_seen_at=?,idle_expires_at=MIN(?,abs_expires_at)
      WHERE token_hash=? AND client=? AND revoked_at IS NULL AND idle_expires_at>? AND abs_expires_at>? AND last_seen_at<=?
      AND EXISTS(SELECT 1 FROM users WHERE id=sessions.user_id AND status='active')`,
    now, now + (row.shared_computer ? 3600 : RP_IDLE), hash, client, now, now, now - 300).run();
    return this.read(hash, client, now);
  }
  async list(hash: string, client: string, now: number): Promise<unknown[]> {
    const row = await this.q(`SELECT (SELECT json_group_array(json_object('id',id,'client',client,'createdAt',created_at,
      'lastSeenAt',last_seen_at,'absoluteExpiresAt',abs_expires_at,'deviceRecordId',device_record_id,'sharedComputer',shared_computer))
      FROM (SELECT * FROM sessions WHERE user_id=s.user_id AND client=s.client AND revoked_at IS NULL AND idle_expires_at>?
        AND abs_expires_at>? ORDER BY created_at DESC,id LIMIT 100)) AS items
      FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.client=? AND ${ACTIVE}`,
    now, now, hash, client, now, now, now).first<{ items: string }>();
    check(row !== null, 401, 'invalid_session'); return JSON.parse(row.items) as unknown[];
  }
  async revoke(hash: string, client: string, all: boolean, now: number): Promise<void> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,s.user_id,?,s.id,s.client,? FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND s.client=? AND ${ACTIVE}`, audit, now, all ? 'sessions.revoked' : 'session.revoked', hash, client, now, now, now),
      this.q(`UPDATE sessions SET revoked_at=?,revoke_reason='user_revoked' WHERE revoked_at IS NULL AND client=?
        AND user_id=(SELECT user_id FROM security_audit WHERE id=?) AND (?=1 OR token_hash=?)`, now, client, audit, all ? 1 : 0, hash),
    ]);
    check(results[0]?.meta.changes === 1, 401, 'invalid_session');
  }
  async requestDeletion(hash: string, client: string, now: number): Promise<void> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,s.user_id,?,s.id,s.client,'account.deletion_requested' FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND s.client=? AND ${ACTIVE} AND s.step_up_at>? AND s.step_up_at<=?`,
      audit, now, hash, client, now, now, now, now - 600, now),
      this.q(`UPDATE users SET status='deleting',deletion_requested_at=? WHERE id=(SELECT user_id FROM security_audit WHERE id=?)`, now, audit),
      this.q(`INSERT INTO deletion_jobs(user_id,product,next_at) SELECT a.user_id,c.id,? FROM security_audit a CROSS JOIN oauth_clients c
        WHERE a.id=? AND c.id<>'accounts' ON CONFLICT(user_id,product) DO NOTHING`, now, audit),
      this.q(`UPDATE sessions SET revoked_at=?,revoke_reason='account_deletion' WHERE revoked_at IS NULL
        AND user_id=(SELECT user_id FROM security_audit WHERE id=?)`, now, audit),
    ]);
    check(results[0]?.meta.changes === 1, 403, 'step_up_required');
  }
}
