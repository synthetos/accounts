import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

export async function workerRuntime() {
  execFileSync(process.execPath, ['tools/build.mjs']);
  const require = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
  // Use the Miniflare version already pinned by the isolated Wrangler test toolchain.
  const { Miniflare, convertV4MiniflareOptions, Response: RuntimeResponse } = require('miniflare');
  const origin = 'https://accounts.example.test';
  const { unstable_splitSqlQuery } = require('wrangler');
  let challenge; let profileSubject = 23456; let calls = 0; const requests = [];
  const entry = resolve('dist/workers/accounts/src/index.js');
  const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]);
  const modules = [entry, ...files(resolve('dist')).filter((p) => p.endsWith('.js') && p !== entry)].map((path) => ({ type: 'ESModule', path }));
  const signer = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [{ name: 'accounts',
    modules, modulesRoot: resolve('dist'),
    compatibilityDate: '2026-10-01', d1Databases: ['IDENTITY'],
    bindings: { ID_TOKEN_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey('jwk', signer.privateKey)), GITHUB_ALLOWED_IDS: JSON.stringify(['23456']), AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
      GITHUB_CLIENT_ID: 'fixture-client', GITHUB_CLIENT_SECRET: 'fixture-secret',
      OAUTH_STATE_KEY: Buffer.alloc(32, 1).toString('base64url'), FORM_KEY: Buffer.alloc(32, 2).toString('base64url'),
      RATE_KEY: Buffer.alloc(32, 3).toString('base64url'), GITHUB_WEBHOOK_SECRET: 'fixture-webhook-secret-long-enough' },
    outboundService: async (request) => {
      calls++; requests.push(request.url);
      if (request.url === 'https://github.com/login/oauth/access_token') {
        const body = new URLSearchParams(await request.text());
        assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'), challenge);
        return RuntimeResponse.json({ token_type: 'bearer', access_token: 'ghu_local_only' });
      }
      assert.equal(request.url, 'https://api.github.com/user');
      assert.equal(request.headers.get('Authorization'), 'Bearer ghu_local_only');
      return RuntimeResponse.json({ id: profileSubject, login: 'local-test', name: 'Local Test', avatar_url: null, email: 'discard@example.test' });
    },
  }, { name: 'rp-test', compatibilityDate: '2026-10-01', modulesRoot: resolve('dist'),
    modules: [{ type: 'ESModule', path: resolve('dist/rpc-probe.js'), contents:
      `import * as main from './workers/accounts/src/index.js';
       import {WorkerEntrypoint} from 'cloudflare:workers';
       export default { async fetch(request,env) { const body=await request.json(); try {
         if(body.method==='exports') return Response.json({names:Object.keys(main).sort(),
           entrypoints:Object.entries(main).filter(([,value])=>typeof value==='function' && value.prototype instanceof WorkerEntrypoint).map(([name])=>name),
           defaultMethods:Object.keys(main.default)});
         const binding=body.default ? env.DEFAULT : env.ACCOUNTS;
         return Response.json({result:await binding[body.method](...body.args)});
       } catch { return Response.json({error:'refused'},{status:400}); } } };` }, ...modules],
    serviceBindings: { ACCOUNTS: { name: 'accounts', entrypoint: 'RunEntrypoint' }, DEFAULT: 'accounts' }
  }] }));
  return { mf, origin, unstable_splitSqlQuery, get calls() { return calls; }, get requests() { return requests; },
    set challenge(value) { challenge = value; }, set profileSubject(value) { profileSubject = value; } };
}
