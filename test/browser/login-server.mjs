// Local-only proxy for the real built Worker. Every upstream provider request is refused.
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { realpathSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';

execFileSync(process.execPath, ['tools/build.mjs']);
const require = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');
const { unstable_splitSqlQuery } = require('wrangler');
const origin = 'https://accounts.example.test';
const entry = resolve('dist/workers/accounts/src/index.js');
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]);
const modules = [entry, ...files(resolve('dist')).filter((p) => p.endsWith('.js') && p !== entry)].map((path) => ({ type: 'ESModule', path }));
const mf = new Miniflare(convertV4MiniflareOptions({ modules, modulesRoot: resolve('dist'), compatibilityDate: '2026-10-01',
  d1Databases: ['IDENTITY'], bindings: { AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
    GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-secret',
    OAUTH_STATE_KEY: Buffer.alloc(32, 1).toString('base64url'), FORM_KEY: Buffer.alloc(32, 2).toString('base64url'),
    RATE_KEY: Buffer.alloc(32, 3).toString('base64url'), GITHUB_WEBHOOK_SECRET: 'fixture-webhook-secret-long-enough' },
  outboundService: () => { throw new Error('Browser fixture must not contact GitHub'); },
}));
const db = await mf.getD1Database('IDENTITY');
for (const file of readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort()) {
  await db.batch(unstable_splitSqlQuery(readFileSync(`migrations/${file}`, 'utf8')).map((sql) => db.prepare(sql)));
}
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
