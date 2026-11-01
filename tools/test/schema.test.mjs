import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const migrations = readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort();
const sql = (name) => readFileSync(join('migrations', name), 'utf8');
const user = 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAV';
function database() {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys=ON');
  for (const name of migrations) db.exec(sql(name));
  db.exec(readFileSync('test/fixtures/identity.sql', 'utf8'));
  return db;
}

test('expand migrations preserve existing records and baseline and sign-in tables exist', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    db.exec(sql(migrations[0]));
    db.exec(readFileSync('test/fixtures/identity.sql', 'utf8'));
    db.prepare("INSERT INTO security_audit(id,at,event) VALUES ('pre_migration',1000,'test')").run();
    const before = db.prepare('SELECT * FROM identities').all();
    const auditBefore = db.prepare('SELECT * FROM security_audit').all();
    for (const name of migrations.slice(1)) db.exec(sql(name));
    assert.deepEqual(db.prepare('SELECT * FROM identities').all(), before);
    assert.deepEqual(db.prepare('SELECT * FROM security_audit').all(), auditBefore);
    assert.deepEqual(db.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").all().map((r) => r.name),
      ['auth_codes', 'auth_requests', 'authorization_requests', 'deletion_jobs', 'identities', 'introspection_rate_limits', 'login_rate_limits', 'management_requests', 'oauth_clients', 'provider_revocations', 'security_audit', 'sessions', 'users', 'webhook_deliveries']);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { db.close(); }
});

test('provider+subject is unique across users; display login does not link accounts', () => {
  const db = database();
  try {
    const insert = db.prepare('INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at) VALUES (?,?,?,?,?,?)');
    assert.throws(() => insert.run('idn_other', 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'github', '100000001', 'different-login', 1000), /UNIQUE/);
    insert.run('idn_google', user, 'google', '100000001', 'fixture-login', 1000);
    insert.run('idn_same_login', 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAW', 'github', '100000002', 'fixture-login', 1000);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identities').get().n, 3);
    assert.throws(() => insert.run('orphan', 'usr_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'github', 'other', '', 1000), /FOREIGN KEY/);
  } finally { db.close(); }
});

test('sessions store hashes, bind run devices and reject impossible expiry/revocation states', () => {
  const db = database();
  try {
    const insert = db.prepare(`INSERT INTO sessions(token_hash,id,user_id,client,device_record_id,
      created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at,revoked_at,revoke_reason)
      VALUES (?,?,?,?,?,1000,1000,?,?,999,?,?)`);
    insert.run('a'.repeat(64), 's1', user, 'run', 'device_fixture', 1100, 1200, null, null);
    insert.run('b'.repeat(64), 's2', user, 'accounts', null, 1100, 1200, null, null);
    for (const [hash, client, device, idle, absolute, revoked, reason] of [
      ['raw-token', 'accounts', null, 1100, 1200, null, null],
      ['c'.repeat(64), 'run', null, 1100, 1200, null, null],
      ['d'.repeat(64), 'accounts', null, 1300, 1200, null, null],
      ['e'.repeat(64), 'accounts', null, 1000, 1200, null, null],
      ['f'.repeat(64), 'accounts', null, 1100, 1200, 1050, null],
      ['g'.repeat(64), 'accounts', null, 1100, 1200, null, null],
    ]) assert.throws(() => insert.run(hash, 'invalid', user, client, device, idle, absolute, revoked, reason), /CHECK/);
    assert.throws(() => insert.run('a'.repeat(64), 'duplicate', user, 'run', 'device_fixture', 1100, 1200, null, null), /UNIQUE/);
  } finally { db.close(); }
});

test('one-time codes and requests support atomic conditional consumption', () => {
  const db = database();
  try {
    db.prepare(`INSERT INTO auth_codes(code_hash,user_id,client,redirect_uri,code_challenge,auth_at,expires_at)
      VALUES (?,?, 'run', 'https://run.example.test/auth/callback', ?,1000,1060)`).run('a'.repeat(64), user, 'a'.repeat(43));
    const consume = db.prepare('UPDATE auth_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>? RETURNING user_id');
    assert.equal(consume.get(1001, 'a'.repeat(64), 1001).user_id, user);
    assert.equal(consume.get(1002, 'a'.repeat(64), 1002), undefined);
    db.prepare(`INSERT INTO auth_requests(state_hash,browser_nonce_hash,client,redirect_uri,return_to,pkce_verifier_enc,expires_at)
      VALUES (?,?,'run','https://run.example.test/auth/callback','/','fixture-encrypted-verifier',1600)`).run('b'.repeat(64), 'c'.repeat(64));
    const use = db.prepare('UPDATE auth_requests SET used_at=? WHERE state_hash=? AND browser_nonce_hash=? AND used_at IS NULL AND expires_at>? RETURNING client');
    assert.equal(use.get(1001, 'b'.repeat(64), 'd'.repeat(64), 1001), undefined);
    assert.equal(use.get(1600, 'b'.repeat(64), 'c'.repeat(64), 1600), undefined);
    assert.equal(use.get(1001, 'b'.repeat(64), 'c'.repeat(64), 1001).client, 'run');
    assert.equal(use.get(1002, 'b'.repeat(64), 'c'.repeat(64), 1002), undefined);
  } finally { db.close(); }
});

test('audit is append-only and survives account deletion without cascading changes', () => {
  const db = database();
  try {
    db.prepare("INSERT INTO security_audit(id,user_id,at,event) VALUES ('audit_1',?,CAST(strftime('%s','now') AS INTEGER),'session.created')").run(user);
    assert.throws(() => db.exec("UPDATE security_audit SET event='changed'"), /append-only/);
    assert.throws(() => db.exec('DELETE FROM security_audit'), /append-only/);
    db.prepare('DELETE FROM users WHERE id=?').run(user);
    assert.equal(db.prepare('SELECT user_id FROM security_audit').get().user_id, user);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM identities WHERE user_id=?').get(user).n, 0);
  } finally { db.close(); }
});

test('deletion cannot finish while product fan-out jobs still reference the user', () => {
  const db = database();
  try {
    db.prepare("INSERT INTO deletion_jobs(user_id,product,next_at) VALUES (?,'run',1000)").run(user);
    assert.throws(() => db.prepare('DELETE FROM users WHERE id=?').run(user), /FOREIGN KEY/);
    assert.throws(() => db.prepare("INSERT INTO deletion_jobs(user_id,product,next_at) VALUES (?,'run',1000)").run(user), /UNIQUE/);
    // Finalizer must first confirm all products, then purge jobs before deleting the user.
    db.prepare("UPDATE deletion_jobs SET status='completed' WHERE user_id=?").run(user);
    db.prepare("DELETE FROM deletion_jobs WHERE user_id=? AND status='completed'").run(user);
    db.prepare('DELETE FROM users WHERE id=?').run(user);
    assert.equal(db.prepare('SELECT id FROM users WHERE id=?').get(user), undefined);
  } finally { db.close(); }
});

test('audit pruning allows only rows older than 365 days and never allows updates', () => {
  const db = database();
  try {
    const now = 2_000_000_000;
    db.function('strftime', (format, value) => {
      assert.equal(format, '%s'); assert.equal(value, 'now');
      return String(now);
    });
    const cutoff = now - 31_536_000;
    const insert = db.prepare("INSERT INTO security_audit(id,at,event) VALUES (?,?,'session.created')");
    for (const [id, at] of [['old', cutoff - 1], ['boundary', cutoff], ['recent', cutoff + 1], ['future', now + 1]]) {
      insert.run(id, at);
      assert.throws(() => db.prepare("UPDATE security_audit SET at=0 WHERE id=?").run(id), /append-only/);
    }
    for (const id of ['boundary', 'recent', 'future']) {
      assert.throws(() => db.prepare('DELETE FROM security_audit WHERE id=?').run(id), /append-only/);
    }
    assert.equal(db.prepare('DELETE FROM security_audit WHERE at < ?').run(cutoff).changes, 1);
    assert.deepEqual(db.prepare('SELECT id FROM security_audit ORDER BY id').all().map((r) => r.id), ['boundary', 'future', 'recent']);
  } finally { db.close(); }
});

test('Worker source has no audit UPDATE/DELETE path; migrations preserve tables and columns', () => {
  const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]);
  for (const path of walk('workers/accounts/src')) {
    assert.doesNotMatch(readFileSync(path, 'utf8'), /\b(?:UPDATE\s+security_audit|DELETE\s+FROM\s+security_audit)\b/i);
  }
  for (const name of migrations) assert.doesNotMatch(sql(name), /\b(?:DROP\s+(?:TABLE|COLUMN)|RENAME\s+COLUMN)\b/i);
});
