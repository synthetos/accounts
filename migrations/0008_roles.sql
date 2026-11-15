-- Roles are authoritative. Audit history also prevents automatic re-admission after removal.
CREATE TABLE roles (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('member','tester','moderator','admin')),
  granted_by TEXT,
  granted_at INTEGER NOT NULL CHECK (granted_at>=0)
) STRICT;
CREATE INDEX roles_by_role ON roles(role);
CREATE TABLE role_audit (
  id TEXT PRIMARY KEY NOT NULL,
  actor_id TEXT,
  user_id TEXT NOT NULL,
  github_id TEXT NOT NULL,
  old_role TEXT CHECK (old_role IN ('member','tester','moderator','admin')),
  new_role TEXT CHECK (new_role IN ('member','tester','moderator','admin')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 500),
  at INTEGER NOT NULL CHECK (at>=0),
  CHECK (old_role IS NOT new_role)
) STRICT;
CREATE INDEX role_audit_user ON role_audit(user_id);
CREATE INDEX role_audit_github ON role_audit(github_id);
CREATE INDEX role_audit_time ON role_audit(at DESC,id);
CREATE TRIGGER role_audit_no_update BEFORE UPDATE ON role_audit
BEGIN SELECT RAISE(ABORT, 'role_audit is append-only'); END;
CREATE TRIGGER role_audit_no_delete BEFORE DELETE ON role_audit
BEGIN SELECT RAISE(ABORT, 'role_audit is append-only'); END;

-- These guards execute within the write transaction, including concurrent admin requests.
CREATE TRIGGER roles_last_admin_delete BEFORE DELETE ON roles
WHEN OLD.role='admin' AND NOT EXISTS (
  SELECT 1 FROM roles r JOIN users u ON u.id=r.user_id
  WHERE r.role='admin' AND r.user_id<>OLD.user_id AND u.status='active')
BEGIN SELECT RAISE(ABORT, 'last_admin'); END;
CREATE TRIGGER roles_last_admin_update BEFORE UPDATE ON roles
WHEN OLD.role='admin' AND (NEW.role<>'admin' OR NEW.user_id<>OLD.user_id) AND NOT EXISTS (
  SELECT 1 FROM roles r JOIN users u ON u.id=r.user_id
  WHERE r.role='admin' AND r.user_id<>OLD.user_id AND u.status='active')
BEGIN SELECT RAISE(ABORT, 'last_admin'); END;
CREATE TRIGGER users_last_admin_status BEFORE UPDATE OF status ON users
WHEN NEW.status<>'active' AND EXISTS (SELECT 1 FROM roles WHERE user_id=OLD.id AND role='admin')
  AND NOT EXISTS (SELECT 1 FROM roles r JOIN users u ON u.id=r.user_id
    WHERE r.role='admin' AND r.user_id<>OLD.id AND u.status='active')
BEGIN SELECT RAISE(ABORT, 'last_admin'); END;
CREATE TRIGGER users_last_admin_delete BEFORE DELETE ON users
WHEN EXISTS (SELECT 1 FROM roles WHERE user_id=OLD.id AND role='admin') AND NOT EXISTS (
  SELECT 1 FROM roles r JOIN users u ON u.id=r.user_id
  WHERE r.role='admin' AND r.user_id<>OLD.id AND u.status='active')
BEGIN SELECT RAISE(ABORT, 'last_admin'); END;
