import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, origin } from './fixture.mjs';
import { createApp } from '../src/app.ts';
import { runRpc } from '../src/rpc.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';

test('every response carries the browser isolation policy, including disabled and refused requests',async()=>{
  const f=fixture();try{
    for(const response of [await createApp().fetch(new Request(origin)),await f.call('/login'),await f.call('/missing'),await f.call('/login',{method:'POST',body:'bad'})]){
      const h=response.headers;
      assert.equal(h.get('Cache-Control'),'no-store');assert.equal(h.get('X-Content-Type-Options'),'nosniff');
      assert.equal(h.get('Strict-Transport-Security'),'max-age=63072000; includeSubDomains');
      assert.equal(h.get('Permissions-Policy'),'serial=(), usb=(), hid=(), bluetooth=(), camera=(), microphone=(), geolocation=(), payment=()');
      assert.equal(h.get('Cross-Origin-Opener-Policy'),'same-origin');assert.equal(h.get('Cross-Origin-Resource-Policy'),'same-origin');assert.equal(h.get('X-Frame-Options'),'DENY');
      for(const policy of ["default-src 'none'","script-src 'none'","base-uri 'none'","frame-ancestors 'none'"])assert.ok(h.get('Content-Security-Policy').includes(policy));
      assert.equal(h.has('Access-Control-Allow-Origin'),false);assert.equal(h.has('Clear-Site-Data'),false);
    }
    const missing=await f.call('/missing');assert.equal(missing.status,404);assert.equal(await missing.text(),'Not found.');
    const login=await f.call('/login');assert.equal(login.headers.get('Content-Type'),'text/html; charset=utf-8');
    assert.match(await login.text(),/<!doctype html><html lang="en"><meta charset="utf-8">/);
  }finally{f.close();}
});
test('configuration refuses every missing secret, noncanonical app ID, untrusted origin and unsafe clock',async()=>{
  const f=fixture();try{
    for(const name of ['IDENTITY','GITHUB_CLIENT_ID','GITHUB_CLIENT_SECRET','GITHUB_APP_ID','OAUTH_STATE_KEY','FORM_KEY','RATE_KEY','GITHUB_WEBHOOK_SECRET']){
      assert.equal((await f.app.fetch(new Request(origin+'/login'),{...f.env,[name]:undefined})).status,503,name);
    }
    for(const id of ['5559540','5559540\n','0','-1','00123','123\n','123a','1e3'])assert.equal((await f.app.fetch(new Request(origin+'/login'),{...f.env,GITHUB_APP_ID:id})).status,503,id);
    for(const id of ['1','9007199254740991'])assert.equal((await f.app.fetch(new Request(origin+'/login'),{...f.env,GITHUB_APP_ID:id})).status,200);
    for(const ACCOUNT_ORIGIN of ['','http://accounts.test',origin+'/',origin+'?x=1','https://user:pass@accounts.test'])assert.equal((await f.app.fetch(new Request(origin+'/login'),{...f.env,ACCOUNT_ORIGIN})).status,503);
    assert.equal((await f.app.fetch(new Request('https://evil.test/login'),f.env)).status,400);
    for(const now of [-1,0.5,NaN,Infinity,281474976711]){f.now=now;assert.equal((await f.call('/missing')).status,503);}
    for(const now of [0,281474976710]){f.now=now;assert.equal((await f.call('/missing')).status,404);}
    const wrong=createApp({provider:{name:'other'},now:()=>1});assert.equal((await wrong.fetch(new Request(origin+'/login'),f.env)).status,503);
  }finally{f.close();}
});
test('webhooks require a valid signature, expected event, bounded delivery ID and a positive numeric subject',async()=>{
  const f=fixture();try{
    for(const headers of [{'Content-Type':'text/plain'},{'X-GitHub-Event':'other'},{'X-GitHub-Delivery':''},{'X-GitHub-Delivery':'a'.repeat(101)},{'X-GitHub-Delivery':'bad_id'},{'X-Hub-Signature-256':'sha256='+'0'.repeat(63)},{'X-Hub-Signature-256':'SHA256='+'0'.repeat(64)}]){
      const r=await f.webhook('refuse',undefined,headers);assert.ok([400,403].includes(r.status));
    }
    for(const payload of [null,{},[],{action:'other',sender:{id:123}},{action:'revoked'},{action:'revoked',sender:{id:0}},{action:'revoked',sender:{id:-1}},{action:'revoked',sender:{id:'123'}},{action:'revoked',sender:{id:1.5}}])assert.equal((await f.webhook('invalid',JSON.stringify(payload))).status,400);
    assert.equal(f.db.prepare('SELECT count(*) n FROM webhook_deliveries').get().n,0);
    assert.equal((await f.webhook('a'.repeat(100),JSON.stringify({action:'revoked',sender:{id:1}}),{'Content-Type':'Application/JSON; charset=utf-8'})).status,204);
    const row=f.db.prepare('SELECT * FROM provider_revocations').get();assert.equal(row.provider_subject,'1');assert.equal(row.revoked_at,f.now);
  }finally{f.close();}
});
test('RPC and HTTP failures never serialize database internals or credentials',async()=>{
  const f=fixture();try{
    const bad={...f.env,IDENTITY:{withSession(){throw new Error('sensitive SQL and token');}}};
    const response=await f.app.fetch(new Request(origin+'/missing'),bad);assert.equal(response.status,503);assert.equal(await response.text(),'service_unavailable');
    const protocol=await f.app.fetch(new Request(origin+'/introspect',{method:'POST'}),bad);assert.equal(protocol.status,503);assert.deepEqual(await protocol.json(),{error:'server_error'});
    await assert.rejects(runRpc(bad,f.now).validateSession(randomToken()),{message:'service_unavailable'});
    await assert.rejects(runRpc(f.env,f.now).validateSession('invalid'),{message:'request_refused'});
  }finally{f.close();}
});
