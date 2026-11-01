// Local-only proxy for the real built Worker. Every upstream provider request is refused.
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { realpathSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const artifactRoot = resolve(process.env.BROWSER_ARTIFACT_DIR ?? 'dist');
if (!process.env.BROWSER_ARTIFACT_DIR) execFileSync(process.execPath, ['tools/build.mjs']);
const require = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const { unstable_splitSqlQuery } = require('wrangler');
const origin = 'https://accounts.example.test';
const entry = join(artifactRoot, 'workers/accounts/src/index.js');
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]);
const modules = [entry, ...files(artifactRoot).filter((p) => p.endsWith('.js') && p !== entry)].map((path) => ({ type: 'ESModule', path }));
const mf = new Miniflare(convertV4MiniflareOptions({ modules, modulesRoot: artifactRoot, compatibilityDate: '2026-10-01',
  d1Databases: ['IDENTITY'], bindings: { GITHUB_ALLOWED_IDS: JSON.stringify(['12345']), AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
    GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-secret',
    OAUTH_STATE_KEY: Buffer.alloc(32, 1).toString('base64url'), FORM_KEY: Buffer.alloc(32, 2).toString('base64url'),
    RATE_KEY: Buffer.alloc(32, 3).toString('base64url'), GITHUB_WEBHOOK_SECRET: 'fixture-webhook-secret-long-enough' },
  outboundService: () => { throw new Error('Browser fixture must not contact GitHub'); },
}));
const db = await mf.getD1Database('IDENTITY');
for (const file of readdirSync(join(artifactRoot, 'migrations')).filter((f) => f.endsWith('.sql')).sort()) {
  await db.batch(unstable_splitSqlQuery(readFileSync(join(artifactRoot, 'migrations', file), 'utf8')).map((sql) => db.prepare(sql)));
}
// Synthetic signed-in browser fixture; never part of the Worker bundle.
const now=Math.floor(Date.now()/1000); const user='usr_'+'0'.repeat(26);
await db.prepare('INSERT INTO users(id,display_name,created_at) VALUES (?,?,?)').bind(user,'Browser fixture',now).run();
await db.prepare("INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at) VALUES ('idn_browser',?,'github','12345','browser-fixture',?)").bind(user,now).run();
const cookieToken=Buffer.alloc(32,9).toString('base64url');
await db.prepare("INSERT INTO sessions(token_hash,id,user_id,client,created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at,sign_in_identity_id) VALUES (?,'ses_browser',?,'accounts',?,?,?,?,?,'idn_browser')")
  .bind(createHash('sha256').update(cookieToken).digest('hex'),user,now,now,now+86400,now+2592000,now).run();
const server = createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value && !['host', 'content-length', 'connection'].includes(name)) headers.set(name, String(value));
    }
    const result = await mf.dispatchFetch(`${origin}${req.url}`, { method: req.method, headers, redirect: 'manual',
      ...(['GET', 'HEAD'].includes(req.method) ? {} : { body: Buffer.concat(chunks) }) });
    for (const [name, value] of result.headers) if (name !== 'set-cookie') res.setHeader(name, value);
    if (result.headers.getSetCookie().length) res.setHeader('Set-Cookie', result.headers.getSetCookie());
    res.writeHead(result.status); res.end(Buffer.from(await result.arrayBuffer()));
  } catch { res.writeHead(500); res.end('fixture_failed'); }
});
server.listen(Number(process.env.PORT ?? 18983), '127.0.0.1', () => console.log('Browser fixture ready'));
async function stop() { server.close(); await mf.dispose(); process.exit(0); }
process.on('SIGTERM', stop); process.on('SIGINT', stop);
