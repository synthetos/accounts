import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync, readFileSync, readdirSync } from 'node:fs';
import { workerRuntime } from './support/worker-runtime.mjs';
import { startManagement, verifyRelyingParties } from './support/worker-protocol.mjs';

test('built Worker completes GitHub/OIDC login and enforces named RPC binding, single-use codes and client isolation in workerd D1', { timeout: 60_000 }, async () => {
  const f = await workerRuntime();
  const { mf, origin, unstable_splitSqlQuery } = f;
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
    const github = new URL(start.headers.get('Location')); f.challenge = github.searchParams.get('code_challenge');
    const callback = `${origin}/auth/github/callback?state=${github.searchParams.get('state')}&code=local-code`;
    const headers = { Cookie: start.headers.get('Set-Cookie').split(';')[0] };
    const done = await mf.dispatchFetch(callback, { headers, redirect: 'manual' }); assert.equal(done.status, 303, JSON.stringify({ calls: f.calls, requests: f.requests, body: await done.text() }));
    const sid = done.headers.getSetCookie().find((s) => s.startsWith('__Host-acct_sid=')); assert.ok(sid);
    const account = await mf.dispatchFetch(origin, { headers: { Cookie: sid.split(';')[0] }, redirect: 'manual' });
    assert.equal(account.status, 200); assert.match(await account.text(), /Local Test/);
    assert.equal((await mf.dispatchFetch(callback, { headers, redirect: 'manual' })).status, 400);
    assert.equal(f.calls, 2);
    assert.equal((await db.prepare('SELECT email FROM identities').first()).email, null);
    assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM sessions').first()).n, 1);
    const accountCookie=sid.split(';')[0];
    const managementStart = () => startManagement(f, accountCookie);
    const verification=await managementStart();
    assert.equal((await mf.dispatchFetch(verification.url,{headers:verification.headers,redirect:'manual'})).status,303);
    assert.ok((await db.prepare("SELECT step_up_at FROM sessions WHERE client='accounts'").first()).step_up_at);
    assert.equal((await mf.dispatchFetch(verification.url,{headers:verification.headers,redirect:'manual'})).status,403);
    await verifyRelyingParties(f, db, accountCookie);
    const wrong=await managementStart();f.profileSubject=99999;
    const refused=await mf.dispatchFetch(wrong.url,{headers:wrong.headers,redirect:'manual'});assert.equal(refused.status,403);
    assert.match(refused.headers.getSetCookie().find(v=>v.startsWith('__Host-acct_sid=')),/Max-Age=0/);
    assert.equal((await db.prepare("SELECT revoke_reason FROM sessions WHERE client='accounts'").first()).revoke_reason,'step_up_subject_mismatch');
    assert.equal((await db.prepare("SELECT count(*) n FROM security_audit WHERE event='step_up.subject_mismatch'").first()).n,1);
    assert.equal((await db.prepare('SELECT count(*) n FROM users').first()).n,1);
    const deniedPage=await mf.dispatchFetch(`${origin}/login`,{redirect:'manual'});
    const deniedCsrf=(await deniedPage.text()).match(/name="csrf" value="([^"]+)"/)[1];
    const deniedStart=await mf.dispatchFetch(`${origin}/login`,{method:'POST',redirect:'manual',headers:{Cookie:deniedPage.headers.get('Set-Cookie').split(';')[0],Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:deniedCsrf,return_to:'/'}).toString()});
    const deniedUrl=new URL(deniedStart.headers.get('Location'));f.challenge=deniedUrl.searchParams.get('code_challenge');
    const denied=await mf.dispatchFetch(`${origin}/auth/github/callback?state=${deniedUrl.searchParams.get('state')}&code=denied`,{headers:{Cookie:deniedStart.headers.get('Set-Cookie').split(';')[0]},redirect:'manual'});
    assert.equal(denied.status,403);assert.equal(await denied.text(),'Access requires a role. Contact an administrator.');assert.equal(denied.headers.get('Set-Cookie'),null);
    assert.equal((await db.prepare("SELECT count(*) n FROM security_audit WHERE event='sign_in.denied'").first()).n,1);
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
