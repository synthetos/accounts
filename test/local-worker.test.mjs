import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

test('built Worker completes GitHub/OIDC login and enforces named RPC binding, single-use codes and client isolation in workerd D1', { timeout: 60_000 }, async () => {
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
    bindings: { ID_TOKEN_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey('jwk', signer.privateKey)), AUTH_ENABLED: 'true', ACCOUNT_ORIGIN: origin, GITHUB_APP_ID: '123456',
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
  try {
    const db = await mf.getD1Database('IDENTITY', 'accounts');
    for (const file of readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort()) {
      await db.batch(unstable_splitSqlQuery(readFileSync(`migrations/${file}`, 'utf8')).map((sql) => db.prepare(sql)));
    }
    const get = await mf.dispatchFetch(`${origin}/login`, { redirect: 'manual' }); assert.equal(get.status, 200);
    const form = await get.text(); const csrf = form.match(/name="csrf" value="([^"]+)"/)[1];
    const start = await mf.dispatchFetch(`${origin}/login`, { method: 'POST', redirect: 'manual',
      headers: { Cookie: get.headers.get('Set-Cookie').split(';')[0], Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf, return_to: '/' }).toString() });
    assert.equal(start.status, 303);
    const github = new URL(start.headers.get('Location')); challenge = github.searchParams.get('code_challenge');
    const callback = `${origin}/auth/github/callback?state=${github.searchParams.get('state')}&code=local-code`;
    const headers = { Cookie: start.headers.get('Set-Cookie').split(';')[0] };
    const done = await mf.dispatchFetch(callback, { headers, redirect: 'manual' }); assert.equal(done.status, 303, JSON.stringify({ calls, requests, body: await done.text() }));
    const sid = done.headers.getSetCookie().find((s) => s.startsWith('__Host-acct_sid=')); assert.ok(sid);
    const account = await mf.dispatchFetch(origin, { headers: { Cookie: sid.split(';')[0] }, redirect: 'manual' });
    assert.equal(account.status, 200); assert.match(await account.text(), /Local Test/);
    assert.equal((await mf.dispatchFetch(callback, { headers, redirect: 'manual' })).status, 400);
    assert.equal(calls, 2);
    assert.equal((await db.prepare('SELECT email FROM identities').first()).email, null);
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM sessions').first()).n, 1);
    const accountCookie=sid.split(';')[0];
    async function managementStart() {
      const page=await mf.dispatchFetch(`${origin}/account`,{headers:{Cookie:accountCookie},redirect:'manual'});
      assert.equal(page.headers.get('Referrer-Policy'),'same-origin');
      assert.match(page.headers.get('Content-Security-Policy'),/form-action 'self'$/);
      const csrf=(await page.text()).match(/action="\/account\/step-up"><input type="hidden" name="csrf" value="([^"]+)"/)[1];
      const body=new URLSearchParams({csrf}).toString();
      const bad=await mf.dispatchFetch(`${origin}/account/step-up`,{method:'POST',redirect:'manual',headers:{Cookie:accountCookie,Origin:'https://sibling.example.test','Content-Type':'application/x-www-form-urlencoded'},body});
      assert.equal(bad.status,403);
      const started=await mf.dispatchFetch(`${origin}/account/step-up`,{method:'POST',redirect:'manual',headers:{Cookie:accountCookie,Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body});
      assert.equal(started.status,200);assert.equal(started.headers.get('Referrer-Policy'),'no-referrer');
      assert.match(started.headers.get('Content-Security-Policy'),/form-action 'self'$/);
      const destination=new URL((await started.text()).match(/href="(https:\/\/github.com[^"]+)"/)[1].replaceAll('&amp;','&'));
      assert.equal(destination.searchParams.get('prompt'),'select_account');challenge=destination.searchParams.get('code_challenge');
      return {url:`${origin}/auth/github/callback?state=${destination.searchParams.get('state')}&code=local-management`,
        headers:{Cookie:`${accountCookie}; ${started.headers.get('Set-Cookie').split(';')[0]}`}};
    }
    const verification=await managementStart();
    assert.equal((await mf.dispatchFetch(verification.url,{headers:verification.headers,redirect:'manual'})).status,303);
    assert.ok((await db.prepare("SELECT step_up_at FROM sessions WHERE client='accounts'").first()).step_up_at);
    assert.equal((await mf.dispatchFetch(verification.url,{headers:verification.headers,redirect:'manual'})).status,403);
    await db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding','[\"https://run.example.test/auth/callback\"]')").run();
    const rp = await mf.getWorker('rp-test');
    const rpc = (method,args,defaultBinding=false) => rp.fetch('https://rp.invalid/', {method:'POST',body:JSON.stringify({method,args,default:defaultBinding})});
    assert.deepEqual(await (await rpc('exports',[])).json(), {names:['RunEntrypoint','default'],entrypoints:['RunEntrypoint'],defaultMethods:['fetch']});
    const verifier = Buffer.alloc(32, 5).toString('base64url');
    const params = new URLSearchParams({response_type:'code',scope:'openid',client_id:'run',redirect_uri:'https://run.example.test/auth/callback',
      state:'local-state',nonce:'local-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
    const auth = await mf.dispatchFetch(`${origin}/authorize?${params}`, {headers:{Cookie:sid.split(';')[0]},redirect:'manual'});
    assert.equal(auth.status,303,await auth.clone().text());
    const issuedAudit = await db.prepare("SELECT client,detail_json FROM security_audit WHERE event='authorization.code_issued'").first();
    assert.equal(issuedAudit.client,'run');
    assert.equal(JSON.parse(issuedAudit.detail_json).auth_at,(await db.prepare("SELECT auth_at FROM sessions WHERE client='accounts'").first()).auth_at);
    const code = new URL(auth.headers.get('Location')).searchParams.get('code');
    const args = [code,verifier,{redirectUri:'https://run.example.test/auth/callback',deviceRecordId:'device-local'}];
    assert.equal((await rpc('exchangeCode',args,true)).status,400);
    const exchanges=await Promise.all([rpc('exchangeCode',args),rpc('exchangeCode',args)]);
    assert.deepEqual(exchanges.map(r=>r.status).sort(),[200,400]);
    const {result} = await exchanges.find(r=>r.status===200).json();
    assert.equal((await (await rpc('validateSession',[result.sessionToken])).json()).result.client,'run');
    assert.equal((await rpc('validateSession',[result.sessionToken],true)).status,400);
    const jwks=await (await mf.dispatchFetch(`${origin}/jwks`)).json();
    const [h,p,sig]=result.idToken.split('.');
    const key=await crypto.subtle.importKey('jwk',jwks.keys[0],{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
    assert.ok(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,Buffer.from(sig,'base64url'),Buffer.from(`${h}.${p}`)));
    assert.equal(JSON.parse(Buffer.from(p,'base64url')).nonce,'local-nonce');
    await db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES ('forum-synthetos','Forum','confidential','[]',?)").bind('a'.repeat(64)).run();
    await db.prepare("UPDATE sessions SET client='forum-synthetos' WHERE id=?").bind(result.session.id).run();
    assert.equal((await (await rpc('validateSession',[result.sessionToken])).json()).result,null);
    assert.equal((await rpc('revokeAll',[result.sessionToken])).status,400);
    await db.prepare("UPDATE sessions SET client='run' WHERE id=?").bind(result.session.id).run();
    assert.equal((await rpc('revokeSession',[result.sessionToken])).status,200);
    assert.equal((await (await rpc('validateSession',[result.sessionToken])).json()).result,null);
    assert.equal((await db.prepare("SELECT count(*) n FROM sessions WHERE client='run'").first()).n,1);
    assert.equal(calls,4,'OIDC/RPC do not fetch remote keys or providers beyond sign-in and step-up');
    const wrong=await managementStart();profileSubject=99999;
    const refused=await mf.dispatchFetch(wrong.url,{headers:wrong.headers,redirect:'manual'});assert.equal(refused.status,403);
    assert.match(refused.headers.getSetCookie().find(v=>v.startsWith('__Host-acct_sid=')),/Max-Age=0/);
    assert.equal((await db.prepare("SELECT revoke_reason FROM sessions WHERE client='accounts'").first()).revoke_reason,'step_up_subject_mismatch');
    assert.equal((await db.prepare("SELECT count(*) n FROM security_audit WHERE event='step_up.subject_mismatch'").first()).n,1);
    assert.equal((await db.prepare('SELECT count(*) n FROM users').first()).n,1);

  } finally { await mf.dispose(); }
});

test('a service binding to an unexported entrypoint refuses startup rather than falling back to default', { timeout: 30_000 }, async () => {
  const require = createRequire(realpathSync('ci/deploy-toolchain/node_modules/wrangler/package.json'));
  const { Miniflare, convertV4MiniflareOptions, Log, LogLevel } = require('miniflare');
  const mf = new Miniflare(convertV4MiniflareOptions({ log: new Log(LogLevel.NONE), workers: [
    { name: 'caller', modules: true, script: 'export default {fetch(){return new Response("unused")}}',
      serviceBindings: { ACCOUNTS: { name: 'accounts', entrypoint: 'WrongEntrypoint' } } },
    { name: 'accounts', modules: true, script: 'import {WorkerEntrypoint} from "cloudflare:workers"; export class RunEntrypoint extends WorkerEntrypoint {} export default {fetch(){return new Response("unused")}}' },
  ] }));
  try {
    await assert.rejects(mf.ready, (error) => error.code === 'ERR_RUNTIME_FAILURE' && /WrongEntrypoint/.test(error.message));
  } finally {
    // Miniflare repeats the failed startup promise during disposal.
    await mf.dispose().catch((error) => assert.equal(error.code, 'ERR_RUNTIME_FAILURE'));
  }
});
