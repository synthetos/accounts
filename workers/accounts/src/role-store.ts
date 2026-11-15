import { randomToken } from '../../../packages/auth-core/src/index.ts';
import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import { check, HttpError, userId } from './security.ts';
import type { DatabaseSession, IdentityDatabase, Statement } from './store.ts';
import type { Role } from './roles.ts';

export interface Person { id: string; login: string; githubId: string; name: string; role: Role | null }
export interface RoleAudit { actor: string | null; login: string; githubId: string; oldRole: Role | null; newRole: Role | null; reason: string; at: number }
const ADMIN = `EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN roles r ON r.user_id=u.id
  WHERE s.token_hash=? AND s.client='accounts' AND s.revoked_at IS NULL AND s.idle_expires_at>?
  AND s.abs_expires_at>? AND u.status='active' AND r.role='admin')`;

export class RoleStore {
  private readonly db: DatabaseSession;
  constructor(database: IdentityDatabase) { this.db = database.withSession('first-primary'); }
  private q(sql: string, ...args: (string | number | null)[]): Statement { return this.db.prepare(sql).bind(...args); }
  async people(search: string): Promise<Person[]> {
    const row = await this.q(`SELECT json_group_array(json_object('id',id,'login',login,'githubId',provider_subject,
      'name',display_name,'role',role)) AS items FROM (
      SELECT u.id,i.login,i.provider_subject,u.display_name,r.role FROM users u JOIN identities i ON i.user_id=u.id
      LEFT JOIN roles r ON r.user_id=u.id WHERE i.provider='github' AND u.status='active'
      AND (?='' OR instr(lower(i.login),lower(?))>0 OR i.provider_subject=?)
      ORDER BY lower(i.login),i.provider_subject LIMIT 100)`, search, search, search).first<{ items: string }>();
    return JSON.parse(row?.items ?? '[]') as Person[];
  }
  async audit(search: string): Promise<RoleAudit[]> {
    const row = await this.q(`SELECT json_group_array(json_object('actor',actor,'login',login,'githubId',github_id,
      'oldRole',old_role,'newRole',new_role,'reason',reason,'at',at)) AS items FROM (
      SELECT a.*,COALESCE(i.login,a.github_id) AS login,
        COALESCE((SELECT login FROM identities WHERE user_id=a.actor_id AND provider='github' ORDER BY linked_at LIMIT 1),a.actor_id) AS actor
      FROM role_audit a LEFT JOIN identities i ON i.provider='github' AND i.provider_subject=a.github_id
      WHERE ?='' OR instr(lower(i.login),lower(?))>0 OR a.github_id=? ORDER BY a.at DESC,a.rowid DESC LIMIT 100)`,
    search, search, search).first<{ items: string }>();
    return JSON.parse(row?.items ?? '[]') as RoleAudit[];
  }
  async change(hash: string, target: string, role: Role | null, reason: string, now: number, profile?: ProviderProfile): Promise<void> {
    const audit = `rol_${randomToken()}`;
    const statements = profile ? this.provision(hash, profile, now) : [];
    statements.push(
      this.q(`INSERT INTO role_audit(id,actor_id,user_id,github_id,old_role,new_role,reason,at)
        SELECT ?,s.user_id,u.id,i.provider_subject,r.role,?,?,? FROM users u JOIN identities i ON i.user_id=u.id
        LEFT JOIN roles r ON r.user_id=u.id JOIN sessions s ON s.token_hash=?
        WHERE i.provider='github' AND i.provider_subject=? AND u.status='active' AND r.role IS NOT ? AND ${ADMIN}`,
      audit, role, reason, now, hash, target, role, hash, now, now),
      this.q(`INSERT INTO roles(user_id,role,granted_by,granted_at)
        SELECT user_id,new_role,actor_id,at FROM role_audit WHERE id=? AND new_role IS NOT NULL
        ON CONFLICT(user_id) DO UPDATE SET role=excluded.role,granted_by=excluded.granted_by,granted_at=excluded.granted_at`, audit),
      this.q(`DELETE FROM roles WHERE user_id=(SELECT user_id FROM role_audit WHERE id=? AND new_role IS NULL)`, audit),
      this.q(`UPDATE sessions SET revoked_at=MAX(?,created_at),revoke_reason='access_removed' WHERE revoked_at IS NULL
        AND user_id=(SELECT user_id FROM role_audit WHERE id=? AND new_role IS NULL)`, now, audit),
    );
    let results;
    try { results = await this.db.batch(statements); } catch (error) {
      if (error instanceof Error && error.message.includes('last_admin')) throw new HttpError(409, 'The last administrator cannot be removed or demoted.');
      throw error;
    }
    check(results[profile ? 2 : 0]?.meta.changes === 1, 409, 'No change made. Refresh the people page and try again.');
  }
  private provision(hash: string, profile: ProviderProfile, now: number): Statement[] {
    const candidate = userId(now);
    return [
      this.q(`INSERT INTO users(id,display_name,avatar_url,created_at) SELECT ?,?,?,? WHERE ${ADMIN}
        AND NOT EXISTS(SELECT 1 FROM identities WHERE provider='github' AND provider_subject=?)`,
      candidate, profile.displayName, profile.avatarUrl, now, hash, now, now, profile.subject),
      this.q(`INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at)
        SELECT ?,?,'github',?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=?)`,
      `idn_${randomToken()}`, candidate, profile.subject, profile.login, now, candidate),
    ];
  }
}
