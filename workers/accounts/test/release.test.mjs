import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, origin, cookie, sha } from './fixture.mjs';
import { Store } from '../src/store.ts';
import { randomToken, createPkce } from '../../../packages/auth-core/src/index.ts';

const profile={subject:'12345',login:'fixture',displayName:'Fixture',avatarUrl:null};
test('D37 admission is config-only, numeric, fail-closed and audited before any identity creation',async()=>{
  for(const configuration of [undefined,'not-json','{}','[12345]','["01"]','["1e3"]','["0"]','["-1"]','["9007199254740992"]','["12345","12345"]','["12345\\n"]',JSON.stringify(Array.from({length:1001},(_,i)=>String(i+1))),' '.repeat(100001)]){
    const f=fixture();try{
      await assert.rejects(new Store(f.env.IDENTITY,configuration).signIn('github',profile,sha(randomToken()),f.now,f.now),{message:'service_unavailable'});
      for(const table of ['users','identities','sessions'])assert.equal(f.db.prepare(`SELECT count(*) n FROM ${table}`).get().n,0);
    }finally{f.close();}
  }
  const f=fixture();try{
    f.env.GITHUB_ALLOWED_IDS='[]';const flow=await f.start();const r=await f.callback(flow,{GITHUB_ALLOWED_IDS:'["12345"]'});
    assert.equal(r.status,403);assert.equal(await r.text(),'Sign-in opens with the public beta');assert.equal(cookie(r,'__Host-acct_sid'),undefined);
    for(const table of ['users','identities','sessions'])assert.equal(f.db.prepare(`SELECT count(*) n FROM ${table}`).get().n,0);
    const audit=f.db.prepare('SELECT * FROM security_audit').get();assert.equal(audit.event,'sign_in.denied');assert.equal(audit.user_id,null);assert.deepEqual(JSON.parse(audit.detail_json),{reason:'allowlist'});
    f.env.GITHUB_ALLOWED_IDS='["12345"]';assert.equal((await f.callback(await f.start())).status,303);
    f.env.GITHUB_ALLOWED_IDS='[]';assert.equal((await f.callback(await f.start())).status,403);
    assert.equal(f.db.prepare('SELECT count(*) n FROM users').get().n,1);assert.equal(f.db.prepare('SELECT count(*) n FROM sessions').get().n,1);
    assert.equal(f.db.prepare("SELECT user_id FROM security_audit WHERE event='sign_in.denied' AND user_id IS NOT NULL").get().user_id,f.db.prepare('SELECT id FROM users').get().id);
    await assert.rejects(new Store(f.env.IDENTITY,'["12345"]').signIn('other',profile,sha(randomToken()),f.now,f.now),/public beta/);
  }finally{f.close();}
});

async function introspectionFixture(){
  const f=fixture();f.accountToken=randomToken();await new Store(f.env.IDENTITY,f.env.GITHUB_ALLOWED_IDS).signIn('github',profile,sha(f.accountToken),f.now,f.now);
  const user=f.db.prepare('SELECT id FROM users').get().id;
  for(const id of ['forum','other'])f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES (?,?,'confidential','[]',?)").run(id,id,sha(`${id}-secret`));
  f.token=randomToken();f.db.prepare("INSERT INTO sessions(token_hash,id,user_id,client,created_at,last_seen_at,idle_expires_at,abs_expires_at,auth_at) VALUES (?,'ses_forum',?,'forum',?,?,?,?,?)")
    .run(sha(f.token),user,f.now,f.now,f.now+43200,f.now+604800,f.now-40);
  f.introspect=(token=f.token,client='forum',fields={},headers={})=>f.call('/introspect',{method:'POST',headers:{Authorization:`Basic ${btoa(`${client}:${client}-secret`)}`,'Content-Type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams({token,...fields})});
  return f;
}
test('RFC7662 introspection reads primary on each call and observes revoke, user lock and both expiry limits',async()=>{
  for(const change of ['revoke','lock','idle','absolute']){
    const f=await introspectionFixture();try{
      const before=f.primaryReads;const response=await f.introspect();assert.equal(response.status,200);assert.ok(f.primaryReads>before);
      const result=await response.json();assert.equal(result.active,true);assert.equal(result.client_id,'forum');
      assert.equal(result.sub,f.db.prepare('SELECT id FROM users').get().id);assert.equal(result.iat,f.now);assert.equal(result.auth_time,f.now-40);assert.equal(result.exp,f.now+43200);assert.equal(result.sid,'ses_forum');
      assert.deepEqual(Object.keys(result).sort(),['active','auth_time','client_id','exp','iat','identities','sid','sub']);
      assert.deepEqual(result.identities,[{provider:'github',id:'12345',login:'fixture'}]);
      assert.equal(response.headers.get('Cache-Control'),'no-store');assert.equal(response.headers.get('Referrer-Policy'),'no-referrer');assert.equal(response.headers.has('Access-Control-Allow-Origin'),false);
      if(change==='revoke')f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test' WHERE id='ses_forum'").run(f.now);
      if(change==='lock')f.db.exec("UPDATE users SET status='locked'");
      if(change==='idle')f.now+=43200;
      if(change==='absolute'){f.db.exec("UPDATE sessions SET idle_expires_at=abs_expires_at WHERE id='ses_forum'");f.now+=604800;}
      assert.deepEqual(await (await f.introspect()).json(),{active:false},change);
    }finally{f.close();}
  }
});
test('introspection never reveals foreign or malformed tokens, authenticates before lookup and keeps cookie/browser callers out',async()=>{
  const f=await introspectionFixture();try{
    for(const token of [f.token,randomToken(),'bad','='.repeat(43)])assert.deepEqual(await(await f.introspect(token,'other')).json(),{active:false});
    for(const token of [randomToken(),'bad','A'.repeat(42)+'B'])assert.deepEqual(await(await f.introspect(token)).json(),{active:false});
    assert.equal((await(await f.introspect(f.token,'forum',{token_type_hint:'unrecognized'})).json()).active,true);
    for(const headers of [{Authorization:''},{Authorization:`Basic ${btoa('forum:wrong')}`},{Authorization:`Basic ${btoa('unknown:secret')}`},{Authorization:`Basic ${btoa('forum:%')}`}]){
      const r=await f.introspect(f.token,'forum',{},headers);assert.equal(r.status,401);assert.deepEqual(await r.json(),{error:'invalid_client'});
    }
    for(const headers of [{Origin:origin},{Origin:'null'},{'Content-Type':'application/json'}])assert.equal((await f.introspect(f.token,'forum',{},headers)).status,400);
    const extra=await f.introspect(f.token,'forum',{userId:'attacker'});assert.equal(extra.status,400);assert.deepEqual(await extra.json(),{error:'invalid_request'});
    assert.equal((await f.call('/introspect',{method:'GET'})).status,404);
    f.now+=300;const result=await(await f.introspect()).json();assert.equal(result.exp,f.now+43200);assert.equal(f.db.prepare("SELECT last_seen_at FROM sessions WHERE id='ses_forum'").get().last_seen_at,f.now);
  }finally{f.close();}
});

// Platform-only RPC dispatch remains verified in real workerd separately. This narrow loader lets
// native mutation tests execute each adapter method, without substituting its application logic.
test('main module exposes only the run entrypoint and forwards all RPC methods through client-scoped validation',async()=>{
  const {registerHooks}=await import('node:module');
  const stub='data:text/javascript,'+encodeURIComponent('export class WorkerEntrypoint { constructor(_context,env){this.env=env;} }');
  const hook=registerHooks({resolve(specifier,context,next){return specifier==='cloudflare:workers'?{url:stub,shortCircuit:true}:next(specifier,context);}});
  let main;try{main=await import('../src/index.ts');}finally{hook.deregister();}
  assert.deepEqual(Object.keys(main).sort(),['RunEntrypoint','default']);assert.equal((await main.default.fetch(new Request(origin))).status,503);
  const f=fixture();try{
    f.now=Math.floor(Date.now()/1000);
    const signed=await f.callback(await f.start());const sid=cookie(signed,'__Host-acct_sid');
    // Entrypoint uses wall-clock time, so keep fixture timestamps in the same current second.
    const now=Math.floor(Date.now()/1000);f.now=now;
    f.db.prepare('UPDATE sessions SET created_at=?,last_seen_at=?,auth_at=?,idle_expires_at=?,abs_expires_at=?').run(now,now,now,now+86400,now+2592000);
    f.db.exec("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding','[\"https://run.example.test/callback\"]')");
    const rpc=new main.RunEntrypoint({},f.env);
    async function exchange(){const pkce=await createPkce();const params=new URLSearchParams({response_type:'code',scope:'openid',client_id:'run',redirect_uri:'https://run.example.test/callback',state:randomToken(),code_challenge:pkce.challenge,code_challenge_method:'S256'});
      const response=await f.call(`/authorize?${params}`,{headers:{Cookie:sid}});assert.equal(response.status,303);
      return rpc.exchangeCode(new URL(response.headers.get('Location')).searchParams.get('code'),pkce.verifier,{redirectUri:'https://run.example.test/callback',deviceRecordId:'device'});}
    const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);f.env.ID_TOKEN_PRIVATE_JWK=JSON.stringify(await crypto.subtle.exportKey('jwk',key.privateKey));
    const first=await exchange();assert.equal((await rpc.validateSession(first.sessionToken)).client,'run');assert.equal((await rpc.listSessions(first.sessionToken)).length,1);
    await rpc.revokeSession(first.sessionToken);assert.equal(await rpc.validateSession(first.sessionToken),null);
    const second=await exchange();await rpc.revokeAll(second.sessionToken);assert.equal(await rpc.validateSession(second.sessionToken),null);
    const third=await exchange();await assert.rejects(rpc.requestDeletion(third.sessionToken),/step_up_required/);
    f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(now,third.session.id);await rpc.requestDeletion(third.sessionToken);
    assert.equal(f.db.prepare('SELECT status FROM users').get().status,'deleting');
  }finally{f.close();}
});

test('admission accepts exact configuration bounds and refuses oversized valid JSON before creating users',async()=>{
  const value='["12345"]';
  for(const [configuration,accepted] of [[value+' '.repeat(100000-value.length),true],[value+' '.repeat(100001-value.length),false],
    [JSON.stringify([...Array.from({length:999},(_,i)=>String(i+1)),'12345']),true]]){
    const f=fixture();try{
      const call=new Store(f.env.IDENTITY,configuration).signIn('github',profile,sha(randomToken()),f.now,f.now);
      if(accepted){await call;assert.equal(f.db.prepare('SELECT count(*) n FROM users').get().n,1);}else await assert.rejects(call,{message:'service_unavailable'});
    }finally{f.close();}
  }
});

test('introspection limits are per authenticated client across requests, bounded and reset at sixty seconds',async()=>{
  const f=await introspectionFixture();try{
    assert.equal((await f.introspect()).status,200);
    f.db.exec("UPDATE introspection_rate_limits SET attempts=599 WHERE client='forum'");
    f.now+=59;
    assert.equal((await f.introspect(randomToken())).status,200);
    const limited=await f.introspect();assert.equal(limited.status,429);
    assert.deepEqual(await limited.json(),{error:'rate_limited'});assert.equal(limited.headers.get('Retry-After'),'60');
    assert.equal(limited.headers.get('Cache-Control'),'no-store');
    assert.equal((await f.introspect(f.token,'other')).status,200);
    for(let i=0;i<3;i++)assert.equal((await f.introspect()).status,429);
    assert.equal(f.db.prepare("SELECT attempts FROM introspection_rate_limits WHERE client='forum'").get().attempts,601);
    f.now++;assert.equal((await f.introspect()).status,200);
    assert.deepEqual({...f.db.prepare("SELECT attempts,window_start FROM introspection_rate_limits WHERE client='forum'").get()},{attempts:1,window_start:f.now});
    assert.equal((await f.introspect(f.token,'forum',{}, {Authorization:'Basic '+btoa('forum:wrong')})).status,401);
    assert.equal(f.db.prepare("SELECT attempts FROM introspection_rate_limits WHERE client='forum'").get().attempts,1);
    f.db.exec("DELETE FROM oauth_clients WHERE id='other'");
    assert.equal(f.db.prepare("SELECT count(*) n FROM introspection_rate_limits WHERE client='other'").get().n,0);
  }finally{f.close();}
});

test('known, foreign, unknown and malformed introspection tokens take identical parameterized database operations',async()=>{
  const f=await introspectionFixture();try{
    const underlying=f.env.IDENTITY;let queries=[];
    f.env.IDENTITY={withSession(mode){const db=underlying.withSession(mode);return {...db,prepare(sql){queries.push(sql);return db.prepare(sql);}};}};
    const paths=[];
    for(const [token,client] of [[f.token,'forum'],[randomToken(),'forum'],['malformed','forum'],[f.token,'other']]){
      queries=[];const response=await f.introspect(token,client);
      assert.equal(response.status,200);assert.equal((await response.json()).active,token===f.token&&client==='forum');
      paths.push(queries.slice());
    }
    for(const path of paths.slice(1))assert.deepEqual(path,paths[0]);
    assert.ok(paths[0].some(sql=>sql.startsWith('UPDATE sessions SET last_seen_at=')));
    const cookieOnly=await f.introspect(f.token,'forum',{}, {Authorization:'',Cookie:'__Host-acct_sid='+f.accountToken});
    assert.equal(cookieOnly.status,401);
    const withCookie=await f.introspect(f.token,'forum',{}, {Cookie:'__Host-acct_sid=irrelevant'});
    assert.equal((await withCookie.json()).active,true);
  }finally{f.close();}
});

test('introspection refreshes only active owned sessions, preserves absolute expiry and uses shared-computer idle limits',async()=>{
  for(const shared of [0,1]){
    const f=await introspectionFixture();try{
      f.db.prepare("UPDATE sessions SET shared_computer=? WHERE id='ses_forum'").run(shared);
      const initial=f.now;f.now+=299;await f.introspect();
      assert.equal(f.db.prepare("SELECT last_seen_at FROM sessions WHERE id='ses_forum'").get().last_seen_at,initial);
      f.now++;const value=await(await f.introspect()).json();
      assert.equal(value.exp,f.now+(shared?3600:43200));
      f.db.prepare("UPDATE sessions SET abs_expires_at=?,idle_expires_at=? WHERE id='ses_forum'").run(f.now+301,f.now+301);
      f.now+=300;assert.equal((await(await f.introspect()).json()).exp,f.now+1);
      f.now++;assert.deepEqual(await(await f.introspect()).json(),{active:false});
    }finally{f.close();}
  }
});

test('introspection cannot refresh foreign, revoked, expired, future or disabled-account sessions',async()=>{
  for(const state of ['foreign','revoked','idle','absolute','future','locked','deleting']){
    const f=await introspectionFixture();try{
      f.now+=300;
      if(state==='revoked')f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test' WHERE id='ses_forum'").run(f.now);
      if(state==='idle')f.db.prepare("UPDATE sessions SET idle_expires_at=? WHERE id='ses_forum'").run(f.now);
      if(state==='absolute')f.db.prepare("UPDATE sessions SET idle_expires_at=?,abs_expires_at=? WHERE id='ses_forum'").run(f.now,f.now);
      if(state==='future')f.db.prepare("UPDATE sessions SET created_at=?,last_seen_at=? WHERE id='ses_forum'").run(f.now+1,f.now+1);
      if(state==='locked'||state==='deleting')f.db.prepare('UPDATE users SET status=?,deletion_requested_at=?').run(state,state==='deleting'?f.now:null);
      const before=f.db.prepare("SELECT * FROM sessions WHERE id='ses_forum'").get();
      assert.deepEqual(await(await f.introspect(f.token,state==='foreign'?'other':'forum')).json(),{active:false},state);
      assert.deepEqual(f.db.prepare("SELECT * FROM sessions WHERE id='ses_forum'").get(),before,state);
    }finally{f.close();}
  }
});
