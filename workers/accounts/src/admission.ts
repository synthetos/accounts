import { randomToken } from '../../../packages/auth-core/src/index.ts';
import { check } from './security.ts';
import type { DatabaseSession, Statement } from './store.ts';
import type { Role } from './roles.ts';

/** The allowlist only seeds roles; neither it nor open signup can undo an access removal. */
export async function admission(db: DatabaseSession, allowedIds: string | undefined, open: boolean,
  provider: string, subject: string, now: number): Promise<Role | null> {
  const existing = await db.prepare(`SELECT r.role FROM roles r JOIN identities i ON i.user_id=r.user_id
    WHERE i.provider=? AND i.provider_subject=?`).bind(provider, subject).first<{ role: Role }>();
  if (provider === 'github' && existing) return null;
  check(allowedIds !== undefined && allowedIds.length <= 100_000, 503, 'service_unavailable');
  let allowed: unknown;
  try { allowed = JSON.parse(allowedIds); } catch { check(false, 503, 'service_unavailable'); }
  check(Array.isArray(allowed) && allowed.length <= 1000 && allowed.every((id: unknown) =>
    typeof id === 'string' && Number.isSafeInteger(Number(id)) && Number(id) > 0 && String(Number(id)) === id)
    && new Set(allowed).size === allowed.length, 503, 'service_unavailable');
  const history = await db.prepare(`SELECT id FROM role_audit WHERE github_id=? OR user_id IN
    (SELECT user_id FROM identities WHERE provider=? AND provider_subject=?) LIMIT 1`)
    .bind(subject, provider, subject).first();
  if (provider === 'github' && !history && (allowed.includes(subject) || open)) return allowed.includes(subject) ? 'admin' : 'member';
  await db.prepare(`INSERT INTO security_audit(id,user_id,at,client,event,detail_json)
    VALUES (?,(SELECT user_id FROM identities WHERE provider=? AND provider_subject=?),?,'accounts','sign_in.denied',
    '{"reason":"role_required"}')`).bind(`aud_${randomToken()}`, provider, subject, now).run();
  check(false, 403, 'Access requires a role. Contact an administrator.');
}

export function bootstrap(db: DatabaseSession, subject: string, role: Role | null, now: number): Statement[] {
  const audit = `rol_${randomToken()}`;
  return [
    db.prepare(`INSERT INTO role_audit(id,actor_id,user_id,github_id,old_role,new_role,reason,at)
      SELECT ?,NULL,u.id,?,NULL,?,?,? FROM users u JOIN identities i ON i.user_id=u.id
      WHERE i.provider='github' AND i.provider_subject=? AND u.status='active' AND ? IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM roles WHERE user_id=u.id)
      AND NOT EXISTS(SELECT 1 FROM role_audit WHERE user_id=u.id OR github_id=?)`)
      .bind(audit, subject, role, role === 'admin' ? 'Allowlist bootstrap' : 'Open signup', now, subject, role, subject),
    db.prepare(`INSERT INTO roles(user_id,role,granted_by,granted_at)
      SELECT user_id,new_role,actor_id,at FROM role_audit WHERE id=?`).bind(audit),
  ];
}
