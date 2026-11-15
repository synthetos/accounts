import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export async function startManagement(f, accountCookie) {
  const { mf, origin } = f;
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
  assert.equal(destination.searchParams.get('prompt'),'select_account');f.challenge=destination.searchParams.get('code_challenge');
  return {url:`${origin}/auth/github/callback?state=${destination.searchParams.get('state')}&code=local-management`,
    headers:{Cookie:`${accountCookie}; ${started.headers.get('Set-Cookie').split(';')[0]}`}};
}

export async function verifyRelyingParties(f, db, accountCookie) {
  const { mf, origin } = f;
  await db.prepare("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('run','Run','binding','[\"https://run.example.test/auth/callback\"]')").run();
  const rp = await mf.getWorker('rp-test');
  const rpc = (method,args,defaultBinding=false) => rp.fetch('https://rp.invalid/', {method:'POST',body:JSON.stringify({method,args,default:defaultBinding})});
  assert.deepEqual(await (await rpc('exports',[])).json(), {names:['RunEntrypoint','default'],entrypoints:['RunEntrypoint'],defaultMethods:['fetch']});
  const verifier = Buffer.alloc(32, 5).toString('base64url');
  const params = new URLSearchParams({response_type:'code',scope:'openid',client_id:'run',redirect_uri:'https://run.example.test/auth/callback',
    state:'local-state',nonce:'local-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
  const auth = await mf.dispatchFetch(`${origin}/authorize?${params}`, {headers:{Cookie:accountCookie},redirect:'manual'});
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
  assert.equal(f.calls,4,'OIDC/RPC do not fetch remote keys or providers beyond sign-in and step-up');
  const forumSecret='local-confidential-secret';
  await db.prepare("UPDATE oauth_clients SET secret_hash=?,redirect_uris_json=? WHERE id='forum-synthetos'")
    .bind(createHash('sha256').update(forumSecret).digest('hex'),JSON.stringify(['https://forum.example.test/callback'])).run();
  params.set('client_id','forum-synthetos');params.set('redirect_uri','https://forum.example.test/callback');
  const forumAuth=await mf.dispatchFetch(`${origin}/authorize?${params}`,{headers:{Cookie:accountCookie},redirect:'manual'});
  assert.equal(forumAuth.status,303);
  const basicHeaders={Authorization:`Basic ${btoa(`forum-synthetos:${forumSecret}`)}`,'Content-Type':'application/x-www-form-urlencoded'};
  const exchanged=await mf.dispatchFetch(`${origin}/token`,{method:'POST',headers:basicHeaders,body:new URLSearchParams({grant_type:'authorization_code',code:new URL(forumAuth.headers.get('Location')).searchParams.get('code'),code_verifier:verifier,redirect_uri:'https://forum.example.test/callback'}).toString()});
  assert.equal(exchanged.status,200);const forumToken=(await exchanged.json()).access_token;
  const introspect=token=>mf.dispatchFetch(`${origin}/introspect`,{method:'POST',headers:basicHeaders,body:new URLSearchParams({token}).toString()});
  assert.deepEqual(await(await introspect(result.sessionToken)).json(),{active:false});
  const active=await(await introspect(forumToken)).json();assert.equal(active.active,true);assert.equal(active.client_id,'forum-synthetos');
  assert.deepEqual(Object.keys(active).sort(),['active','auth_time','client_id','exp','iat','identities','sid','sub']);
  for(const identity of active.identities)assert.deepEqual(Object.keys(identity).sort(),['id','login','provider']);
  await db.prepare("UPDATE introspection_rate_limits SET attempts=599 WHERE client='forum-synthetos'").run();
  assert.equal((await introspect(forumToken)).status,200);
  const throttled=await introspect(forumToken);assert.equal(throttled.status,429);assert.equal(throttled.headers.get('Retry-After'),'60');
  await db.prepare("UPDATE introspection_rate_limits SET window_start=0 WHERE client='forum-synthetos'").run();
  await db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test' WHERE id=?").bind(Math.floor(Date.now()/1000),active.sid).run();
  assert.deepEqual(await(await introspect(forumToken)).json(),{active:false});
}
