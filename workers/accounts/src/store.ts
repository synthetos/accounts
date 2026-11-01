import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';
import { check, userId } from './security.ts';

type Binding = string | number | null;
export interface Statement {
  bind(...values: Binding[]): Statement;
  first<T>(): Promise<T | null>;
  run(): Promise<{ meta: { changes: number } }>;
}
export interface DatabaseSession {
  prepare(sql: string): Statement;
  batch(statements: Statement[]): Promise<{ meta: { changes: number } }[]>;
}
export interface IdentityDatabase { withSession(constraint: 'first-primary'): DatabaseSession }
export interface LoginRequest {
  state_hash: string; browser_nonce_hash: string; pkce_verifier_enc: string; return_to: string; created_at: number;
}
export interface AccountSession {
  id: string; user_id: string; display_name: string; last_seen_at: number; abs_expires_at: number; step_up_at: number | null;
}
export const ACCOUNT_IDLE = 14 * 86400;
export const ACCOUNT_ABSOLUTE = 30 * 86400;

export class Store {
  private readonly db: DatabaseSession;
  private readonly allowedIds: string | undefined;
  constructor(database: IdentityDatabase, allowedIds?: string) {
    this.db = database.withSession('first-primary'); this.allowedIds = allowedIds;
  }
  private statement(sql: string, ...values: Binding[]): Statement { return this.db.prepare(sql).bind(...values); }
  async rateLimit(bucket: string, now: number): Promise<void> {
    // Bound maintenance work per attempt; the time index makes this independent of active rows.
    await this.statement(`DELETE FROM login_rate_limits WHERE bucket_hash IN (
      SELECT bucket_hash FROM login_rate_limits WHERE window_start<=? ORDER BY window_start LIMIT 100)`, now - 600).run();
    const row = await this.statement(`INSERT INTO login_rate_limits(bucket_hash,window_start,attempts) VALUES (?,?,1)
      ON CONFLICT(bucket_hash) DO UPDATE SET
        attempts=CASE WHEN window_start<=? THEN 1 ELSE attempts+1 END,
        window_start=CASE WHEN window_start<=? THEN excluded.window_start ELSE window_start END
      RETURNING attempts`, bucket, now, now - 600, now - 600).first<{ attempts: number }>();
    check(row !== null && row.attempts <= 10, 429, 'try_again_later');
  }
  async start(flow: LoginRequest, callback: string, now: number): Promise<void> {
    await this.statement(`INSERT INTO auth_requests(state_hash,browser_nonce_hash,client,redirect_uri,return_to,pkce_verifier_enc,expires_at,created_at)
      VALUES (?,?,'accounts',?,?,?,?,?)`, flow.state_hash, flow.browser_nonce_hash, callback, flow.return_to,
    flow.pkce_verifier_enc, now + 600, now).run();
  }
  async consume(state: string, nonce: string, callback: string, now: number): Promise<LoginRequest> {
    const row = await this.statement(`UPDATE auth_requests SET used_at=? WHERE state_hash=? AND browser_nonce_hash=?
      AND client='accounts' AND redirect_uri=? AND used_at IS NULL AND expires_at>? AND created_at<=?
      RETURNING state_hash,browser_nonce_hash,pkce_verifier_enc,return_to,created_at`,
    now, state, nonce, callback, now, now).first<LoginRequest>();
    check(row !== null, 400, 'sign_in_refused');
    return row;
  }
  async signIn(provider: string, profile: ProviderProfile, tokenHash: string, now: number, startedAt: number, metadata?: { device: string; country: string | null }): Promise<void> {
    // D37 is fail-closed in every environment. There is no request-controlled or missing-config bypass.
    check(this.allowedIds !== undefined && this.allowedIds.length <= 100_000, 503, 'service_unavailable');
    let allowed: unknown;
    try { allowed = JSON.parse(this.allowedIds); } catch { check(false, 503, 'service_unavailable'); }
    check(Array.isArray(allowed) && allowed.length <= 1000 && allowed.every((id: unknown) =>
      typeof id === 'string' && Number.isSafeInteger(Number(id)) && Number(id) > 0 && String(Number(id)) === id)
      && new Set(allowed).size === allowed.length, 503, 'service_unavailable');
    if (provider !== 'github' || !allowed.includes(profile.subject)) {
      await this.statement(`INSERT INTO security_audit(id,user_id,at,client,event,detail_json)
        VALUES (?,(SELECT user_id FROM identities WHERE provider=? AND provider_subject=?),?,'accounts','sign_in.denied',
        '{"reason":"allowlist"}')`, `aud_${randomToken()}`, provider, profile.subject, now).run();
      check(false, 403, 'Sign-in opens with the public beta');
    }
    const candidate = userId(now); const identity = `idn_${randomToken()}`; const session = `ses_${randomToken()}`;
    const results = await this.db.batch([
      this.statement(`INSERT INTO users(id,display_name,avatar_url,created_at)
        SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM identities WHERE provider=? AND provider_subject=?)`,
      candidate, profile.displayName, profile.avatarUrl, now, provider, profile.subject),
      this.statement(`INSERT INTO identities(id,user_id,provider,provider_subject,login,email,email_verified,linked_at,last_used_at)
        VALUES (?,COALESCE((SELECT user_id FROM identities WHERE provider=? AND provider_subject=?),?), ?,?,?,NULL,0,?,?)
        ON CONFLICT(provider,provider_subject) DO UPDATE SET login=excluded.login,last_used_at=excluded.last_used_at,email=NULL,email_verified=0`,
      identity, provider, profile.subject, candidate, provider, profile.subject, profile.login, now, now),
      this.statement(`UPDATE users SET display_name=?,avatar_url=? WHERE status='active'
        AND id=(SELECT user_id FROM identities WHERE provider=? AND provider_subject=?)`,
      profile.displayName, profile.avatarUrl, provider, profile.subject),
      this.statement(`INSERT INTO sessions(token_hash,id,user_id,client,created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at,sign_in_identity_id,ua_summary,country)
        SELECT ?,?,u.id,'accounts',?,?,?,?,?,i.id,?,? FROM users u JOIN identities i ON i.user_id=u.id
        WHERE i.provider=? AND i.provider_subject=? AND u.status='active'
          AND NOT EXISTS(SELECT 1 FROM provider_revocations WHERE provider=? AND provider_subject=? AND revoked_at>=?)`,
      tokenHash, session, now, now, now + ACCOUNT_IDLE, now + ACCOUNT_ABSOLUTE, now, metadata?.device ?? null, metadata?.country ?? null, provider, profile.subject, provider, profile.subject, startedAt),
      this.statement(`INSERT INTO security_audit(id,user_id,at,session_id,client,event)
        SELECT ?,user_id,?,id,'accounts','session.created' FROM sessions WHERE id=?`, `aud_${randomToken()}`, now, session),
    ]);
    check(results[3]?.meta.changes === 1, 403, 'sign_in_refused');
  }
  private readSession(tokenHash: string, now: number): Promise<AccountSession | null> {
    return this.statement(`SELECT s.id,s.user_id,u.display_name,s.last_seen_at,s.abs_expires_at,s.step_up_at FROM sessions s
      JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.client='accounts' AND s.revoked_at IS NULL
      AND s.idle_expires_at>? AND s.abs_expires_at>? AND u.status='active'`, tokenHash, now, now).first<AccountSession>();
  }
  async validate(tokenHash: string, now: number): Promise<AccountSession | null> {
    const row = await this.readSession(tokenHash, now);
    if (row !== null && now - row.last_seen_at >= 300) {
      const changed = await this.statement(`UPDATE sessions SET last_seen_at=?,idle_expires_at=MIN(?,abs_expires_at)
        WHERE token_hash=? AND revoked_at IS NULL AND idle_expires_at>? AND abs_expires_at>?
        AND last_seen_at<=? AND EXISTS(SELECT 1 FROM users WHERE id=sessions.user_id AND status='active') RETURNING id`,
      now, now + ACCOUNT_IDLE, tokenHash, now, now, now - 300).first<{ id: string }>();
      // A concurrent request may have refreshed the timestamp; re-read the primary instead of trusting stale state.
      if (changed === null) return this.readSession(tokenHash, now);
    }
    return row;
  }
  async revokeFromWebhook(deliveryHash: string, payloadHash: string, subject: string, now: number): Promise<void> {
    // Deduplicate GitHub's delivery ID. Distinct legitimate revocations may have identical bodies.
    await this.db.batch([
      this.statement('DELETE FROM webhook_deliveries WHERE expires_at<=?', now),
      this.statement('INSERT INTO webhook_deliveries(delivery_hash,payload_hash,expires_at) VALUES (?,?,?)', deliveryHash, payloadHash, now + 7 * 86400),
      this.statement(`INSERT INTO provider_revocations(provider,provider_subject,revoked_at) VALUES ('github',?,?)
        ON CONFLICT(provider,provider_subject) DO UPDATE SET revoked_at=MAX(revoked_at,excluded.revoked_at)`, subject, now),
      this.statement(`UPDATE sessions SET revoked_at=?,revoke_reason='provider_revoked'
        WHERE revoked_at IS NULL AND user_id IN (SELECT user_id FROM identities WHERE provider='github' AND provider_subject=?)`, now, subject),
      this.statement(`INSERT INTO security_audit(id,user_id,at,client,event)
        SELECT ?,user_id,?,'accounts','provider.revoked' FROM identities WHERE provider='github' AND provider_subject=?`,
      `aud_${randomToken()}`, now, subject),
    ]);
  }
}

