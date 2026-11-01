import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { fixture, origin, cookie, sha } from './fixture.mjs';
import { Store } from '../src/store.ts';
import { runRpc } from '../src/rpc.ts';
import { randomToken, createPkce } from '../../../packages/auth-core/src/index.ts';

const runRedirect = 'https://run.example.test/auth/callback';
const forumRedirect = 'https://forum.example.test/auth/callback';
async function setup() {
  const f = fixture();
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
  f.env.ID_TOKEN_PRIVATE_JWK = JSON.stringify(await crypto.subtle.exportKey('jwk', keys.privateKey));
  f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding',?)").run(JSON.stringify([runRedirect]));
  f.db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES ('forum-synthetos','Forum','confidential',?,?)")
    .run(JSON.stringify([forumRedirect]), sha('forum-secret'));
  f.accountToken = randomToken();
  await new Store(f.env.IDENTITY).signIn('github', { subject: '12345', login: 'alice', displayName: 'Alice', avatarUrl: null }, sha(f.accountToken), f.now, f.now);
  f.accountCookie = `__Host-acct_sid=${f.accountToken}`;
  f.rpc = () => runRpc(f.env, f.now);
  f.params = async (client = 'run') => {
    const pkce = await createPkce();
    return { pkce, params: new URLSearchParams({ response_type: 'code', scope: 'openid', client_id: client,
      redirect_uri: client === 'run' ? runRedirect : forumRedirect, state: randomToken(), nonce: randomToken(), code_challenge: pkce.challenge, code_challenge_method: 'S256' }) };
  };
  f.authorize = async (client = 'run') => {
    const flow = await f.params(client);
    const response = await f.call(`/authorize?${flow.params}`, { headers: { Cookie: f.accountCookie } });
    assert.equal(response.status, 303, await response.clone().text());
    return { ...flow, response, code: new URL(response.headers.get('Location')).searchParams.get('code') };
  };
  f.exchange = (flow, context = {}) => f.rpc().exchangeCode(flow.code, flow.pkce.verifier, { redirectUri: runRedirect, deviceRecordId: 'device_fixture', ...context });
  f.forumExchange = (flow, patch = {}, header = {}) => f.call('/token', { method: 'POST', headers: {
    'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${btoa('forum-synthetos:forum-secret')}`, ...header },
  body: new URLSearchParams({ grant_type: 'authorization_code', code: flow.code, code_verifier: flow.pkce.verifier, redirect_uri: forumRedirect, ...patch }) });
  return f;
}

test('authorization code binds client, exact redirect and S256; JWKS verifies ES256 identity with stable keys and nonce', async () => {
  const f = await setup();
  try {
    const discovery = await f.call('/.well-known/openid-configuration'); const metadata = await discovery.json();
    assert.equal(metadata.issuer, origin); assert.deepEqual(metadata.response_types_supported, ['code']);
    assert.deepEqual(metadata.code_challenge_methods_supported,['S256']);
    assert.deepEqual(metadata.token_endpoint_auth_methods_supported,['client_secret_basic']);
    assert.deepEqual(metadata.id_token_signing_alg_values_supported,['ES256']); assert.equal(discovery.headers.get('Cache-Control'), 'no-store');
    const flow = await f.authorize();
    assert.equal(new URL(flow.response.headers.get('Location')).searchParams.get('state'), flow.params.get('state'));
    const stored = f.db.prepare('SELECT * FROM auth_codes').get();
    assert.equal(stored.code_hash, sha(flow.code)); assert.equal(stored.expires_at - f.now, 60); assert.equal(stored.code_challenge, flow.pkce.challenge);
    const result = await f.exchange(flow);
    assert.equal(result.session.client, 'run'); assert.equal(result.session.deviceRecordId, 'device_fixture');
    assert.equal(result.session.idleExpiresAt - f.now, 43200); assert.equal(result.session.absoluteExpiresAt - f.now, 604800);
    assert.equal(f.db.prepare("SELECT token_hash FROM sessions WHERE client='run'").get().token_hash, sha(result.sessionToken));
    const jwks = await (await f.call('/jwks')).json(); assert.equal(jwks.keys.length, 1); assert.equal(jwks.keys[0].d, undefined);
    const [h, p, s] = result.idToken.split('.'); const header = JSON.parse(Buffer.from(h,'base64url')); const claims = JSON.parse(Buffer.from(p,'base64url'));
    assert.deepEqual(header, { alg: 'ES256', typ: 'JWT', kid: jwks.keys[0].kid });
    assert.ok(verify('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: jwks.keys[0], format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s,'base64url')));
    assert.equal(claims.iss, origin); assert.equal(claims.aud,'run'); assert.equal(claims.sub,result.session.sub);
    assert.equal(claims.exp - claims.iat,60); assert.equal(claims.auth_time,f.now); assert.equal(claims.nonce,flow.params.get('nonce'));
    assert.deepEqual(claims.identities,[{ provider:'github',id:'12345',login:'alice' }]); assert.equal(claims.email,undefined);
    assert.equal(flow.response.headers.get('Referrer-Policy'),'no-referrer');
  } finally { f.close(); }
});

test('parallel same-second redemption creates exactly one session and audit; wrong verifier/redirect/client and expired codes cannot redeem', async () => {
  const f = await setup();
  try {
    const flow = await f.authorize();
    await assert.rejects(f.rpc().exchangeCode(flow.code,(await createPkce()).verifier,{redirectUri:runRedirect,deviceRecordId:'d'}));
    await assert.rejects(f.exchange(flow,{redirectUri:runRedirect+'?evil=1'}));
    await assert.rejects(f.exchange(flow,{redirectUri:runRedirect+'/'}));
    const forum = await f.authorize('forum-synthetos'); await assert.rejects(f.exchange(forum));
    const attempts = await Promise.allSettled([f.exchange(flow),f.exchange(flow)]);
    assert.equal(attempts.filter((r)=>r.status==='fulfilled').length,1);
    assert.equal(f.db.prepare("SELECT count(*) n FROM sessions WHERE client='run'").get().n,1);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE client='run' AND event='session.created'").get().n,1);
    await assert.rejects(f.exchange(flow));
    const expired = await f.authorize(); f.now += 60; await assert.rejects(f.exchange(expired));
  } finally { f.close(); }
});

test('code exchange rechecks originating session, account lock and live client registration', async () => {
  for (const mutation of [
    "UPDATE sessions SET revoked_at=created_at,revoke_reason='test' WHERE client='accounts'",
    "UPDATE users SET status='locked'",
    "UPDATE oauth_clients SET redirect_uris_json='[]' WHERE id='run'",
    "UPDATE sessions SET idle_expires_at=created_at+1 WHERE client='accounts'",
  ]) {
    const f = await setup();
    try { const flow = await f.authorize(); f.db.exec(mutation); f.now += 1; await assert.rejects(f.exchange(flow));
      assert.equal(f.db.prepare("SELECT count(*) n FROM sessions WHERE client='run'").get().n,0);
    } finally { f.close(); }
  }
});

test('authorization rejects redirects, malformed/duplicate fields, non-S256, unsupported modes and raw identities without redirecting', async () => {
  const f = await setup();
  try {
    for (const [name,value] of [['redirect_uri',runRedirect+'/'],['redirect_uri','https://evil.test'],['redirect_uri',runRedirect+'#frag'],
      ['client_id','unknown'],['code_challenge_method','plain'],['code_challenge','A'.repeat(42)+'B'],['response_type','token'],['scope','openid email'],
      ['request_uri','https://evil.test'],['userId','usr_attacker'],['prompt','login']]) {
      const {params}=await f.params(); params.set(name,value);
      const response = await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}}); assert.equal(response.status>=400,true,`${name}:${value}`); assert.equal(response.headers.has('Location'),false);
    }
    const {params}=await f.params();params.append('state','extra');assert.equal((await f.call(`/authorize?${params}`)).status,400);
    const none=await f.params();none.params.set('prompt','none');const response=await f.call(`/authorize?${none.params}`);
    assert.equal(new URL(response.headers.get('Location')).searchParams.get('error'),'login_required'); assert.equal(f.db.prepare('SELECT count(*) n FROM authorization_requests').get().n,0);
  } finally { f.close(); }
});

test('unauthenticated continuation is encrypted, cookie-bound, expiring and single-use through the actual GitHub login flow', async () => {
  const f=await setup();
  try {
    const {params,pkce}=await f.params();const response=await f.call(`/authorize?${params}`);assert.equal(response.status,303);
    const continuationCookie=cookie(response,'__Host-acct_authorize');const returnTo=new URL(response.headers.get('Location'),origin).searchParams.get('return_to');
    const stored=f.db.prepare('SELECT * FROM authorization_requests').get();assert.equal(stored.request_enc.includes(params.get('state')),false);assert.equal(stored.request_enc.includes(params.get('nonce')),false);
    const login=await f.start(await f.form(returnTo));const done=await f.callback(login);assert.equal(done.headers.get('Location'),returnTo);
    assert.equal((await f.call(returnTo,{headers:{Cookie:cookie(done,'__Host-acct_sid')}})).status,400);
    const cookies=`${cookie(done,'__Host-acct_sid')}; ${continuationCookie}`;
    const resume=await f.call(returnTo,{headers:{Cookie:cookies}});assert.equal(resume.status,303);assert.match(resume.headers.get('Set-Cookie'),/Max-Age=0/);
    const target=new URL(resume.headers.get('Location'));assert.equal(target.searchParams.get('state'),params.get('state'));
    const result=await f.exchange({code:target.searchParams.get('code'),pkce});assert.equal(JSON.parse(Buffer.from(result.idToken.split('.')[1],'base64url')).nonce,params.get('nonce'));
    assert.equal((await f.call(returnTo,{headers:{Cookie:cookies}})).status,400);
    const fresh=await f.call(`/authorize?${params}`);f.now+=600;
    const path=new URL(fresh.headers.get('Location'),origin).searchParams.get('return_to');
    assert.equal((await f.call(path,{headers:{Cookie:`${f.accountCookie}; ${cookie(fresh,'__Host-acct_authorize')}`}})).status,400);
  } finally { f.close(); }
});

test('confidential backchannel requires Basic, never browser cookies, and binding client cannot use public token endpoint', async () => {
  const f=await setup();
  try {
    const flow=await f.authorize('forum-synthetos');
    for(const headers of [{Authorization:''},{Authorization:`Basic ${btoa('forum-synthetos:wrong')}`},{Origin:origin},{Authorization:`Basic ${btoa('run:secret')}`}]) {
      const r=await f.forumExchange(flow,{},headers);assert.ok(r.status>=400);assert.ok((await r.json()).error);assert.equal(r.headers.has('Access-Control-Allow-Origin'),false);
    }
    const response=await f.forumExchange(flow);assert.equal(response.status,200,await response.clone().text());const result=await response.json();
    assert.equal(result.token_type,'Bearer');assert.equal(result.scope,'openid');assert.equal(typeof result.id_token,'string');
    assert.equal(await f.rpc().validateSession(result.access_token),null);
    await assert.rejects(f.rpc().revokeAll(result.access_token)); await assert.rejects(f.rpc().listSessions(result.access_token)); await assert.rejects(f.rpc().requestDeletion(result.access_token));
    assert.equal((await f.forumExchange(flow)).status,400);
    assert.equal(f.db.prepare("SELECT revoked_at FROM sessions WHERE client='forum-synthetos'").get().revoked_at,null);
  } finally { f.close(); }
});

test('run session validation is primary-backed, refreshes idle safely, respects shared/absolute expiry and immediately observes revocation', async () => {
  const f=await setup();
  try {
    const first=await f.exchange(await f.authorize());const second=await f.exchange(await f.authorize(),{sharedComputer:true});
    assert.equal(second.expiresIn,3600);assert.equal(second.session.sharedComputer,true);
    const reads=f.primaryReads;assert.equal((await f.rpc().validateSession(first.sessionToken)).sub,first.session.sub);assert.ok(f.primaryReads>reads);
    f.now+=300;await f.rpc().validateSession(second.sessionToken);
    assert.equal(f.db.prepare('SELECT last_seen_at,idle_expires_at FROM sessions WHERE id=?').get(second.session.id).idle_expires_at,f.now+3600);
    const list=await f.rpc().listSessions(first.sessionToken);assert.equal(list.length,2);assert.ok(list.every(s=>s.client==='run' && s.token_hash===undefined));
    await f.rpc().revokeSession(second.sessionToken);assert.equal(await f.rpc().validateSession(second.sessionToken),null);
    assert.ok(await f.rpc().validateSession(first.sessionToken));await f.rpc().revokeAll(first.sessionToken);
    assert.equal(await f.rpc().validateSession(first.sessionToken),null);assert.equal(f.db.prepare("SELECT revoked_at FROM sessions WHERE client='accounts'").get().revoked_at,null);
    const third=await f.exchange(await f.authorize());f.now=third.session.idleExpiresAt;assert.equal(await f.rpc().validateSession(third.sessionToken),null);
  } finally { f.close(); }
});

test('deletion requires an explicit fresh step-up, then atomically locks account, revokes every client and queues products', async () => {
  const f=await setup();
  try {
    const result=await f.exchange(await f.authorize());await assert.rejects(f.rpc().requestDeletion(result.sessionToken),/step_up_required/);
    assert.equal(f.db.prepare('SELECT status FROM users').get().status,'active');assert.equal(f.db.prepare('SELECT count(*) n FROM deletion_jobs').get().n,0);
    f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(f.now-600,result.session.id);await assert.rejects(f.rpc().requestDeletion(result.sessionToken));
    f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(f.now+1,result.session.id);await assert.rejects(f.rpc().requestDeletion(result.sessionToken));
    f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(f.now,result.session.id);await f.rpc().requestDeletion(result.sessionToken);
    assert.equal(f.db.prepare('SELECT status FROM users').get().status,'deleting');assert.equal(f.db.prepare('SELECT count(*) n FROM sessions WHERE revoked_at IS NULL').get().n,0);
    assert.deepEqual(f.db.prepare('SELECT product FROM deletion_jobs ORDER BY product').all().map(r=>r.product),['forum-synthetos','run']);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='account.deletion_requested'").get().n,1);
    await assert.rejects(f.rpc().requestDeletion(result.sessionToken));
  } finally { f.close(); }
});

test('signing configuration fails before code consumption and rotation publishes only public allowlisted fields', async () => {
  const f=await setup();
  try {
    const flow=await f.authorize();const original=f.env.ID_TOKEN_PRIVATE_JWK;
    delete f.env.ID_TOKEN_PRIVATE_JWK;await assert.rejects(f.exchange(flow));assert.equal(f.db.prepare('SELECT used_at FROM auth_codes').get().used_at,null);
    f.env.ID_TOKEN_PRIVATE_JWK=original;const old=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify([{...await crypto.subtle.exportKey('jwk',old.publicKey),x5u:'https://evil.test'}]);
    const keys=(await (await f.call('/jwks')).json()).keys;assert.equal(keys.length,2);assert.equal(keys[1].x5u,undefined);assert.equal(keys[1].d,undefined);
    await f.exchange(flow);
    f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify([{...await crypto.subtle.exportKey('jwk',old.privateKey)}]);assert.equal((await f.call('/jwks')).status,503);
  } finally { f.close(); }
});

test('session operations cannot cross users, and failed audit insertion rolls back code redemption and session creation', async () => {
  const f=await setup();
  try {
    const alice=await f.exchange(await f.authorize());
    const bobAccount=randomToken();await new Store(f.env.IDENTITY).signIn('github',{subject:'67890',login:'bob',displayName:'Bob',avatarUrl:null},sha(bobAccount),f.now,f.now);
    f.accountCookie=`__Host-acct_sid=${bobAccount}`;
    const bob=await f.exchange(await f.authorize());assert.notEqual(bob.session.sub,alice.session.sub);
    assert.deepEqual((await f.rpc().listSessions(alice.sessionToken)).map(s=>s.id),[alice.session.id]);
    await f.rpc().revokeAll(alice.sessionToken);assert.ok(await f.rpc().validateSession(bob.sessionToken));
    const code=await f.authorize();
    f.db.exec("CREATE TRIGGER test_audit_failure BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT,'test-secret-SQL-must-not-leak'); END");
    await assert.rejects(f.exchange(code),{message:'service_unavailable'});
    assert.equal(f.db.prepare('SELECT used_at FROM auth_codes WHERE code_hash=?').get(sha(code.code)).used_at,null);
    assert.equal(f.db.prepare("SELECT count(*) n FROM sessions WHERE client='run'").get().n,2);
    f.db.exec('DROP TRIGGER test_audit_failure');await f.exchange(code);
  } finally { f.close(); }
});

test('absolute expiry and account lock are checked even when idle time is still valid; idle refresh cannot exceed absolute expiry', async () => {
  const f=await setup();
  try {
    const result=await f.exchange(await f.authorize());
    f.db.prepare('UPDATE sessions SET idle_expires_at=abs_expires_at WHERE id=?').run(result.session.id);
    f.now=result.session.absoluteExpiresAt-1;const near=await f.rpc().validateSession(result.sessionToken);
    assert.equal(near.idleExpiresAt,result.session.absoluteExpiresAt);
    f.now+=1;assert.equal(await f.rpc().validateSession(result.sessionToken),null);
    f.now-=2;f.db.exec("UPDATE users SET status='locked'");assert.equal(await f.rpc().validateSession(result.sessionToken),null);
  } finally { f.close(); }
});

test('confidential clients must supply a verifier even with valid Basic credentials', async () => {
  const f=await setup();
  try {
    const flow=await f.authorize('forum-synthetos');
    const response=await f.call('/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Authorization:`Basic ${btoa('forum-synthetos:forum-secret')}`},
      body:new URLSearchParams({grant_type:'authorization_code',code:flow.code,redirect_uri:forumRedirect})});
    assert.equal(response.status,400);assert.equal((await response.json()).error,'invalid_grant');
    assert.equal(f.db.prepare('SELECT used_at FROM auth_codes').get().used_at,null);
    assert.equal((await f.forumExchange(flow)).status,200);
  } finally { f.close(); }
});

test('every issued code is atomically audited with client and original auth_at; failed audit leaves no code', async () => {
  const f=await setup();
  try {
    const authAt=f.now;f.now+=20;await f.authorize();
    const audit=f.db.prepare("SELECT * FROM security_audit WHERE event='authorization.code_issued'").get();
    assert.equal(audit.client,'run');assert.equal(audit.at,f.now);assert.deepEqual(JSON.parse(audit.detail_json),{auth_at:authAt});
    assert.equal(audit.session_id,f.db.prepare("SELECT id FROM sessions WHERE client='accounts'").get().id);
    const count=f.db.prepare('SELECT count(*) n FROM auth_codes').get().n;
    f.db.exec("CREATE TRIGGER test_issue_audit BEFORE INSERT ON security_audit WHEN NEW.event='authorization.code_issued' BEGIN SELECT RAISE(ABORT,'synthetic-secret'); END");
    const {params}=await f.params();const response=await f.call(`/authorize?${params}`,{headers:{Cookie:f.accountCookie}});
    assert.equal(response.status,503);assert.equal(response.headers.has('Location'),false);assert.equal((await response.text()).includes('synthetic-secret'),false);
    assert.equal(f.db.prepare('SELECT count(*) n FROM auth_codes').get().n,count);
  } finally { f.close(); }
});

test('resume rechecks client removal/redirect changes and refuses ciphertext transplanted between nonce-bound continuations', async () => {
  for(const change of ['client','redirect','ciphertext']) {
    const f=await setup();
    try {
      const {params}=await f.params();const first=await f.call(`/authorize?${params}`);
      let response=first;
      if(change==='client') f.db.exec("DELETE FROM oauth_clients WHERE id='run'");
      if(change==='redirect') f.db.exec("UPDATE oauth_clients SET redirect_uris_json='[\"https://run.example.test/other\"]' WHERE id='run'");
      if(change==='ciphertext') {
        const saved=f.db.prepare('SELECT request_enc FROM authorization_requests').get().request_enc;
        response=await f.call(`/authorize?${params}`);
        const secondResume=new URL(response.headers.get('Location'),origin).searchParams.get('return_to').split('/').pop();
        f.db.prepare('UPDATE authorization_requests SET request_enc=? WHERE resume_hash=?').run(saved,sha(secondResume));
      }
      const path=new URL(response.headers.get('Location'),origin).searchParams.get('return_to');
      const resumed=await f.call(path,{headers:{Cookie:`${f.accountCookie}; ${cookie(response,'__Host-acct_authorize')}`}});
      assert.ok(resumed.status>=400,change);assert.equal(resumed.headers.has('Location'),false);
      assert.equal(f.db.prepare('SELECT count(*) n FROM auth_codes').get().n,0);
    } finally { f.close(); }
  }
});

test('JWKS contains only public fields; key-derived kids survive metadata changes and rotation preserves old token verification', async () => {
  const f=await setup();
  const allowed=['alg','crv','kid','kty','use','x','y'];
  const thumbprint=(k)=>createHash('sha256').update(JSON.stringify({crv:k.crv,kty:k.kty,x:k.x,y:k.y})).digest('base64url');
  try {
    const oldToken=(await f.exchange(await f.authorize())).idToken;
    const oldPublic=(await (await f.call('/jwks')).json()).keys[0];
    assert.deepEqual(Object.keys(oldPublic).sort(),allowed);assert.equal(oldPublic.kid,thumbprint(oldPublic));
    const privateJwk=JSON.parse(f.env.ID_TOKEN_PRIVATE_JWK);
    f.env.ID_TOKEN_PRIVATE_JWK=JSON.stringify({...privateJwk,kid:'ignored-metadata',x5u:'https://invalid.test/key'});
    assert.equal((await (await f.call('/jwks')).json()).keys[0].kid,oldPublic.kid);
    const next=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    f.env.ID_TOKEN_PRIVATE_JWK=JSON.stringify(await crypto.subtle.exportKey('jwk',next.privateKey));
    f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify([oldPublic]);
    const keys=(await (await f.call('/jwks')).json()).keys;
    assert.equal(keys.length,2);assert.notEqual(keys[0].kid,oldPublic.kid);
    for(const k of keys){assert.deepEqual(Object.keys(k).sort(),allowed);assert.equal(k.kid,thumbprint(k));}
    const [h,p,s]=oldToken.split('.');const old=keys.find(k=>k.kid===JSON.parse(Buffer.from(h,'base64url')).kid);
    assert.ok(verify('sha256',Buffer.from(`${h}.${p}`),{key:createPublicKey({key:old,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(s,'base64url')));
    const newToken=(await f.exchange(await f.authorize())).idToken;
    assert.equal(JSON.parse(Buffer.from(newToken.split('.')[0],'base64url')).kid,keys[0].kid);
    f.env.ID_TOKEN_PREVIOUS_JWKS=JSON.stringify([{...oldPublic,kid:keys[0].kid}]);assert.equal((await f.call('/jwks')).status,503);
  } finally { f.close(); }
});

test('default HTTP handler has no RPC dispatch route even with a valid run session', async () => {
  const f=await setup();
  try {
    const session=await f.exchange(await f.authorize());
    for(const method of ['exchangeCode','validateSession','revokeSession','revokeAll','listSessions','requestDeletion']) {
      for(const prefix of ['/','/rpc/']) {
        const response=await f.call(`${prefix}${method}`,{method:'POST',headers:{'Content-Type':'application/json',Cookie:f.accountCookie},body:JSON.stringify({token:session.sessionToken})});
        assert.equal(response.status,404);
      }
    }
    assert.ok(await f.rpc().validateSession(session.sessionToken));
    assert.equal(f.db.prepare('SELECT status FROM users').get().status,'active');
  } finally { f.close(); }
});
