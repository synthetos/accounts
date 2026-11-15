import { test } from 'node:test';
import assert from 'node:assert/strict';
import { origin, cookie, sha } from './fixture.mjs';
import { runRpc } from '../src/rpc.ts';
import { randomToken, createPkce } from '../../../packages/auth-core/src/index.ts';

import { setup, runRedirect, forumRedirect } from './oidc-fixture.mjs';

test('unknown client and wrong known-client secret both execute the HMAC verification path',async()=>{
  const f=await setup();const descriptor=Object.getOwnPropertyDescriptor(crypto.subtle,'verify');const verify=crypto.subtle.verify;let comparisons=0;
  try {
    const flow=await f.authorize('forum-synthetos');
    crypto.subtle.verify=async function(...args){if(args[0]==='HMAC')comparisons++;return verify.apply(this,args);};
    for(const credential of ['unknown:forum-secret','forum-synthetos:wrong-secret']){
      comparisons=0;const r=await f.forumExchange(flow,{}, {Authorization:`Basic ${btoa(credential)}`});
      assert.equal(r.status,401);assert.equal(comparisons,1);
    }
  } finally {if(descriptor)Object.defineProperty(crypto.subtle,'verify',descriptor);else delete crypto.subtle.verify;f.close();}
});

test('discovery advertises the complete restricted protocol and only GET exposes metadata',async()=>{
  const f=await setup();try{
    assert.deepEqual(await(await f.call('/.well-known/openid-configuration')).json(),{
      issuer:origin,authorization_endpoint:origin+'/authorize',token_endpoint:origin+'/token',jwks_uri:origin+'/jwks',
      response_types_supported:['code'],response_modes_supported:['query'],grant_types_supported:['authorization_code'],subject_types_supported:['public'],
      id_token_signing_alg_values_supported:['ES256'],token_endpoint_auth_methods_supported:['client_secret_basic'],
      introspection_endpoint:origin+'/introspect',introspection_endpoint_auth_methods_supported:['client_secret_basic'],
      scopes_supported:['openid'],code_challenge_methods_supported:['S256'],claims_supported:['iss','sub','aud','iat','exp','auth_time','nonce','identities'],
      request_parameter_supported:false,request_uri_parameter_supported:false});
    for(const path of ['/.well-known/openid-configuration','/jwks','/authorize'])assert.equal((await f.call(path,{method:'POST'})).status,404);
    assert.equal((await f.call('/token')).status,404);
  }finally{f.close();}
});
test('binding context and authorization fields enforce their bounds before consuming codes',async()=>{
  const f=await setup();try{
    const flow=await f.authorize();
    for(const context of [null,{},[],{redirectUri:runRedirect,deviceRecordId:'d',unexpected:true},
      ...['',123,'a'.repeat(257),'a b','a\u007fb','a\u0000b'].map(deviceRecordId=>({redirectUri:runRedirect,deviceRecordId})),
      {redirectUri:runRedirect,deviceRecordId:'d',sharedComputer:'false'}])await assert.rejects(f.rpc().exchangeCode(flow.code,flow.pkce.verifier,context));
    assert.equal(f.db.prepare('SELECT used_at FROM auth_codes').get().used_at,null);
    const result=await f.exchange(flow,{deviceRecordId:'a'.repeat(256),sharedComputer:false});assert.equal(result.session.sharedComputer,false);assert.equal(result.session.deviceRecordId.length,256);
    for(const field of ['state','nonce']){
      for(const value of ['a b','a\u007fb','a\u0000b','a'.repeat(1025)]){
        const {params}=await f.params();params.set(field,value);assert.equal((await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}})).status,400);
      }
      const {params}=await f.params();params.set(field,'a'.repeat(1024));assert.equal((await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}})).status,303);
    }
    const {params}=await f.params();params.append('nonce','second');assert.equal((await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}})).status,400);
  }finally{f.close();}
});
test('misregistered clients cannot relax redirect protocol, credentials, fragment or run cardinality',async()=>{
  const f=await setup();try{
    for(const uri of ['http://run.example.test/auth/callback','https://user@run.example.test/auth/callback','https://:pass@run.example.test/auth/callback',runRedirect+'#fragment',runRedirect+'?q='+'a'.repeat(2048)]){
      f.db.prepare('UPDATE oauth_clients SET redirect_uris_json=? WHERE id=\'run\'').run(JSON.stringify([uri]));
      const {params}=await f.params();params.set('redirect_uri',uri);
      assert.equal((await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}})).status,400,uri);
    }
    f.db.prepare('UPDATE oauth_clients SET redirect_uris_json=? WHERE id=\'run\'').run(JSON.stringify([runRedirect,runRedirect+'/other']));
    assert.equal((await f.call(`/authorize?${(await f.params()).params}`,{headers:{Cookie:f.accountCookie}})).status,400);
    f.db.prepare("UPDATE oauth_clients SET redirect_uris_json=?,kind='confidential',secret_hash=? WHERE id='run'").run(JSON.stringify([runRedirect]),sha('secret'));
    assert.equal((await f.call(`/authorize?${(await f.params()).params}`,{headers:{Cookie:f.accountCookie}})).status,400);
    f.db.prepare("UPDATE oauth_clients SET redirect_uris_json=? WHERE id='accounts'").run(JSON.stringify([runRedirect]));
    const {params}=await f.params();params.set('client_id','accounts');assert.equal((await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}})).status,400);
    await assert.rejects(f.rpc().exchangeCode(randomToken(),(await createPkce()).verifier,{redirectUri:runRedirect,deviceRecordId:'d'}),{message:'service_unavailable'});
  }finally{f.close();}
});
test('binding calls fail closed without enablement, database or an exact trusted HTTPS issuer',async()=>{
  const f=await setup();try{
    for(const patch of [{AUTH_ENABLED:undefined},{AUTH_ENABLED:'false'},{IDENTITY:undefined},...['http://accounts.test',origin+'/','https://u@accounts.test',undefined].map(ACCOUNT_ORIGIN=>({ACCOUNT_ORIGIN}))]){
      await assert.rejects(runRpc({...f.env,...patch},f.now).validateSession(randomToken()),{message:'service_unavailable'});
    }
  }finally{f.close();}
});
test('confidential exchange refuses wrong grant and extra or duplicate parameters without consuming the code',async()=>{
  const f=await setup();try{
    const flow=await f.authorize('forum-synthetos');
    for(const patch of [{grant_type:'refresh_token'},{extra:'injected'}])assert.equal((await f.forumExchange(flow,patch)).status,400);
    const body=new URLSearchParams({grant_type:'authorization_code',code:flow.code,code_verifier:flow.pkce.verifier,redirect_uri:forumRedirect});body.append('grant_type','authorization_code');
    assert.equal((await f.call('/token',{method:'POST',headers:{Authorization:`Basic ${btoa('forum-synthetos:forum-secret')}`,'Content-Type':'application/x-www-form-urlencoded'},body})).status,400);
    assert.equal(f.db.prepare('SELECT used_at FROM auth_codes').get().used_at,null);
    const result=await(await f.forumExchange(flow)).json();assert.equal(result.expires_in,43200);
    assert.equal(f.db.prepare("SELECT shared_computer FROM sessions WHERE client='forum-synthetos'").get().shared_computer,0);
  }finally{f.close();}
});
test('resume with a missing or revoked account session returns to login without consuming the continuation',async()=>{
  const f=await setup();try{
    const {params}=await f.params();
    const started=await f.call(`/authorize?${params}`);const nonce=cookie(started,'__Host-acct_authorize');const path=new URL(started.headers.get('Location'),origin).searchParams.get('return_to');
    for(const account of ['',`; ${f.accountCookie}`]){
      if(account)f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test'").run(f.now);
      const response=await f.call(path,{headers:{Cookie:nonce+account}});assert.equal(response.status,303);assert.equal(response.headers.get('Location'),`/login?return_to=${path}`);
      assert.equal(f.db.prepare('SELECT used_at FROM authorization_requests').get().used_at,null);
    }
    for(const bad of [path+'?extra=1',path.slice(0,-1),path.replace(/.$/,'g')])assert.equal((await f.call(bad,{headers:{Cookie:nonce}})).status,400);
    const again=await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}});assert.equal(again.status,303);assert.match(again.headers.get('Location'),/^\/login\?/);
    params.set('prompt','none');const silent=await f.call(`/authorize?${params}`);assert.equal(new URL(silent.headers.get('Location')).searchParams.get('state'),params.get('state'));
  }finally{f.close();}
});

test('JWKS refuses mislabeled key types, inconsistent coordinates and excessive or duplicate rotation keys',async()=>{
  const f=await setup();try{
    const current=JSON.parse(f.env.ID_TOKEN_PRIVATE_JWK);
    for(const patch of [{kty:'RSA'},{crv:'P-384'},{x:1},{y:1},{x:'AA'},{y:'AA'},{d:undefined},{d:'AA'}]){
      f.env.ID_TOKEN_PRIVATE_JWK=JSON.stringify({...current,...patch});const r=await f.call('/jwks');assert.equal(r.status,503);assert.equal(await r.text(),'service_unavailable');
    }
    f.env.ID_TOKEN_PRIVATE_JWK=JSON.stringify(current);const old=[];
    for(let i=0;i<5;i++){const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);old.push(await crypto.subtle.exportKey('jwk',keys.publicKey));}
    f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify(old.slice(0,4));assert.equal((await(await f.call('/jwks')).json()).keys.length,5);
    for(const previous of [old,[old[0],old[0]],{},[null],[current]]){f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify(previous);const r=await f.call('/jwks');assert.equal(r.status,503);assert.equal(await r.text(),'service_unavailable');}
  }finally{f.close();}
});
test('Basic credentials preserve form-encoding and enforce bounds even for registered clients',async()=>{
  const f=await setup();try{
    const call=header=>f.call('/introspect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded ; charset=utf-8',Authorization:header},body:new URLSearchParams({token:randomToken()})});
    const registered=(id,secret)=>f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES (?,?,'confidential','[]',?)").run(id,id,sha(secret));
    for(const secret of ['s'.repeat(1024),'literal+plus']){f.db.prepare("UPDATE oauth_clients SET secret_hash=? WHERE id='forum-synthetos'").run(sha(secret));assert.deepEqual(await(await call(`Basic ${btoa('forum-synthetos:'+encodeURIComponent(secret))}`)).json(),{active:false});}
    registered('client with spaces','secret');assert.deepEqual(await(await call(`Basic ${btoa('client+with+spaces:secret')}`)).json(),{active:false});
    registered('','secret');registered('f'.repeat(3064),'s');registered('f'.repeat(3067),'s');
    const exact=`Basic   ${btoa('f'.repeat(3064)+':s')}`;assert.equal(exact.length,4096);assert.equal((await call(exact)).status,200);
    for(const secret of ['s'.repeat(1025),'a b','a\x7fb']){
      f.db.prepare("UPDATE oauth_clients SET secret_hash=? WHERE id='forum-synthetos'").run(sha(secret));const r=await call(`Basic ${btoa('forum-synthetos:'+encodeURIComponent(secret))}`);assert.equal(r.status,401);assert.deepEqual(await r.json(),{error:'invalid_client'});
    }
    for(const header of [`Other ${btoa('client+with+spaces:secret')}`,`Basic ${btoa(':secret')}`,'Basic %%%',`Basic ${btoa('no-colon')}`,`Basic ${btoa('f'.repeat(3067)+':s')}`]){const r=await call(header);assert.equal(r.status,401);assert.deepEqual(await r.json(),{error:'invalid_client'});}
    const absent=await f.call('/introspect',{method:'POST',headers:{Authorization:`Basic ${btoa('client+with+spaces:secret')}`},body:new Uint8Array([1])});assert.equal(absent.status,400);assert.deepEqual(await absent.json(),{error:'invalid_request'});
  }finally{f.close();}
});
