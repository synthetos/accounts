import { randomToken } from '../../../packages/auth-core/src/index.ts';
import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import { check } from './security.ts';
import type { DatabaseSession, IdentityDatabase, Statement } from './store.ts';

const ACTIVE = `s.client='accounts' AND s.revoked_at IS NULL AND s.idle_expires_at>? AND s.abs_expires_at>? AND u.status='active'`;
const FRESH = 's.step_up_at>? AND s.step_up_at<=?';
export interface ManagementFlow { state_hash: string; session_id: string; purpose: 'step_up' | 'link'; pkce_verifier_enc: string; created_at: number }
export interface LinkedIdentity { id: string; provider: string; subject: string; login: string }
export interface ListedSession { id: string; client: string; created: number; seen: number; device: string | null; country: string | null }
export interface Dashboard { id: string; name: string; step_up_at: number | null; identities: LinkedIdentity[]; sessions: ListedSession[] }

export class AccountStore {
  private readonly db: DatabaseSession;
  constructor(database: IdentityDatabase) { this.db = database.withSession('first-primary'); }
  private q(sql: string, ...values: (string | number | null)[]): Statement { return this.db.prepare(sql).bind(...values); }
  async dashboard(hash: string, now: number): Promise<Dashboard> {
    const row = await this.q(`SELECT s.id,u.display_name AS name,s.step_up_at,
      (SELECT json_group_array(json_object('id',id,'provider',provider,'subject',provider_subject,'login',login)) FROM identities WHERE user_id=u.id) identities,
      (SELECT json_group_array(json_object('id',id,'client',client,'created',created_at,'seen',last_seen_at,'device',ua_summary,'country',country))
        FROM (SELECT * FROM sessions WHERE user_id=u.id AND revoked_at IS NULL AND idle_expires_at>? AND abs_expires_at>? ORDER BY created_at DESC,id LIMIT 100)) sessions
      FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND ${ACTIVE}`, now, now, hash, now, now)
      .first<{ id: string; name: string; step_up_at: number | null; identities: string; sessions: string }>();
    check(row !== null, 401, 'invalid_session');
    return { ...row, identities: JSON.parse(row.identities) as LinkedIdentity[], sessions: JSON.parse(row.sessions) as ListedSession[] };
  }
  async requireFresh(hash: string, now: number): Promise<void> {
    const row = await this.q(`SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND ${ACTIVE} AND ${FRESH}`,
      hash, now, now, now - 600, now).first<{ id: string }>();
    check(row !== null, 403, 'step_up_required');
  }
  async revoke(hash: string, target: string | null, now: number): Promise<void> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event,detail_json)
        SELECT ?,s.user_id,?,s.id,'accounts',?,json_object('target_session',?) FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND ${ACTIVE} AND (? IS NULL OR EXISTS(SELECT 1 FROM sessions t WHERE t.id=? AND t.user_id=s.user_id AND t.revoked_at IS NULL))`,
      audit, now, target === null ? 'sessions.revoked_all' : 'session.revoked', target, hash, now, now, target, target),
      this.q(`UPDATE sessions SET revoked_at=?,revoke_reason='user_revoked' WHERE revoked_at IS NULL
        AND user_id=(SELECT user_id FROM security_audit WHERE id=?) AND (? IS NULL OR id=?)`, now, audit, target, target),
    ]);
    check(results[0]?.meta.changes === 1, 403, 'action_refused');
  }
  async start(hash: string, state: string, nonce: string, encrypted: string, purpose: ManagementFlow['purpose'], now: number): Promise<void> {
    const results = await this.db.batch([
      this.q(`DELETE FROM management_requests WHERE state_hash IN (SELECT state_hash FROM management_requests WHERE expires_at<=? ORDER BY expires_at LIMIT 100)`, now),
      this.q(`INSERT INTO management_requests(state_hash,browser_nonce_hash,session_id,purpose,pkce_verifier_enc,created_at,expires_at)
        SELECT ?,?,s.id,?,?,?,? FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND ${ACTIVE}
          AND (?='step_up' OR (${FRESH}))`, state, nonce, purpose, encrypted, now, now + 600, hash, now, now, purpose, now - 600, now),
      this.q(`UPDATE sessions SET step_up_at=NULL WHERE id=(SELECT session_id FROM management_requests WHERE state_hash=? AND purpose='step_up')`, state),
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,s.user_id,?,s.id,'accounts',? FROM sessions s JOIN management_requests m ON m.session_id=s.id WHERE m.state_hash=?`,
      `aud_${randomToken()}`, now, purpose === 'step_up' ? 'step_up.started' : 'identity.link_started', state),
    ]);
    check(results[1]?.meta.changes === 1, 403, 'action_refused');
  }
  peek(state: string): Promise<{ purpose: ManagementFlow['purpose'] } | null> {
    return this.q('SELECT purpose FROM management_requests WHERE state_hash=?', state).first();
  }
  async consume(hash: string, state: string, nonce: string, now: number): Promise<ManagementFlow> {
    const row = await this.q(`UPDATE management_requests SET used_at=? WHERE state_hash=? AND browser_nonce_hash=? AND used_at IS NULL
      AND created_at<=? AND expires_at>? AND session_id IN (SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND ${ACTIVE}) RETURNING state_hash,session_id,purpose,pkce_verifier_enc,created_at`,
    now, state, nonce, now, now, hash, now, now).first<ManagementFlow>();
    check(row !== null, 403, 'verification_refused'); return row;
  }
  async finishStepUp(hash: string, flow: ManagementFlow, provider: string, subject: string, now: number): Promise<boolean> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,s.user_id,?,s.id,'accounts',CASE WHEN EXISTS(SELECT 1 FROM identities WHERE user_id=s.user_id AND provider=? AND provider_subject=?)
          AND NOT EXISTS(SELECT 1 FROM provider_revocations WHERE provider=? AND provider_subject=? AND revoked_at>=?)
          THEN 'step_up.succeeded' ELSE 'step_up.subject_mismatch' END
        FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.id=? AND ${ACTIVE}`,
      audit, now, provider, subject, provider, subject, flow.created_at, hash, flow.session_id, now, now),
      this.q(`UPDATE sessions SET step_up_at=? WHERE id=(SELECT session_id FROM security_audit WHERE id=? AND event='step_up.succeeded')`, now, audit),
      this.q(`UPDATE sessions SET revoked_at=?,revoke_reason='step_up_subject_mismatch',step_up_at=NULL
        WHERE id=(SELECT session_id FROM security_audit WHERE id=? AND event='step_up.subject_mismatch')`, now, audit),
    ]);
    check(results[0]?.meta.changes === 1, 403, 'verification_refused');
    return results[1]?.meta.changes === 1;
  }
  async finishLink(hash: string, flow: ManagementFlow, provider: string, profile: ProviderProfile, now: number): Promise<void> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,s.user_id,?,s.id,'accounts',CASE WHEN EXISTS(SELECT 1 FROM identities WHERE provider=? AND provider_subject=? AND user_id<>s.user_id)
          THEN 'identity.link_refused' ELSE 'identity.linked' END
        FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.id=? AND ${ACTIVE} AND ${FRESH}
          AND NOT EXISTS(SELECT 1 FROM provider_revocations WHERE provider=? AND provider_subject=? AND revoked_at>=?)`,
      audit, now, provider, profile.subject, hash, flow.session_id, now, now, now - 600, now, provider, profile.subject, flow.created_at),
      this.q(`INSERT INTO identities(id,user_id,provider,provider_subject,login,email,email_verified,linked_at,last_used_at)
        SELECT ?,user_id,?,?,?,NULL,0,?,? FROM security_audit WHERE id=? AND event='identity.linked'
          AND NOT EXISTS(SELECT 1 FROM identities WHERE provider=? AND provider_subject=?)`,
      `idn_${randomToken()}`, provider, profile.subject, profile.login, now, now, audit, provider, profile.subject),
    ]);
    check(results[0]?.meta.changes === 1, 403, 'link_refused');
    const row = await this.q("SELECT id FROM security_audit WHERE id=? AND event='identity.linked'", audit).first();
    check(row !== null, 403, 'link_refused');
  }
  async unlink(hash: string, identity: string, now: number): Promise<void> {
    const audit = `aud_${randomToken()}`;
    const results = await this.db.batch([
      this.q(`INSERT INTO security_audit(id,user_id,at,session_id,client,event,detail_json)
        SELECT ?,s.user_id,?,s.id,'accounts','identity.unlinked',json_object('identity_id',?) FROM sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND ${ACTIVE} AND ${FRESH} AND (SELECT COUNT(*) FROM identities WHERE user_id=s.user_id)>1
          AND EXISTS(SELECT 1 FROM identities WHERE id=? AND user_id=s.user_id)`, audit, now, identity, hash, now, now, now - 600, now, identity),
      // Legacy sessions have unknown sign-in identity; revoke them conservatively, across products.
      this.q(`UPDATE sessions SET revoked_at=?,revoke_reason='identity_unlinked',step_up_at=NULL WHERE revoked_at IS NULL
        AND user_id=(SELECT user_id FROM security_audit WHERE id=?) AND (sign_in_identity_id=? OR sign_in_identity_id IS NULL)`, now, audit, identity),
      this.q(`DELETE FROM identities WHERE id=? AND user_id=(SELECT user_id FROM security_audit WHERE id=?)`, identity, audit),
    ]);
    check(results[0]?.meta.changes === 1, 403, 'unlink_refused');
  }
}
