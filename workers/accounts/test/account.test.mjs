import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, origin, cookie, sha } from './fixture.mjs';
import { Store } from '../src/store.ts';
import { AccountStore } from '../src/account-store.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';

const unescape = (s) => s.replaceAll('&amp;','&').replaceAll('&quot;','"').replaceAll('&#39;',"'").replaceAll('&lt;','<').replaceAll('&gt;','>');
function forms(html) {
  return [...html.matchAll(/<form method="post" action="([^"]+)">([\s\S]*?)<\/form>/g)].map((match) => ({path:match[1],
    fields:Object.fromEntries([...match[2].matchAll(/name="([^"]+)" value="([^"]*)"/g)].map(m=>[m[1],unescape(m[2])]))}));
}
async function setup() {
  const f=fixture();const signedIn=await f.callback(await f.start());f.sid=cookie(signedIn,'__Host-acct_sid');
  f.session=f.db.prepare("SELECT * FROM sessions WHERE client='accounts'").get();
  f.dashboard=async()=>{const r=await f.call('/account',{headers:{Cookie:f.sid}});assert.equal(r.status,200);const html=await r.text();return {response:r,html,forms:forms(html)};};
  f.post=(form,body={},headers={})=>f.call(form.path,{method:'POST',headers:{Cookie:f.sid,Origin:origin,'Sec-Fetch-Site':'same-origin','Content-Type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams({...form.fields,...body})});
  f.formFor=async(path)=>{const form=(await f.dashboard()).forms.find(x=>x.path===path);assert.ok(form);return form;};
  f.manage=async(purpose='step-up')=>{
    const path=purpose==='step-up'?'/account/step-up':'/account/identities/link';
    const response=await f.post(await f.formFor(path));
    if(response.status!==200)return {response};
    const html=await response.text();const authorization=new URL(unescape(html.match(/href="(https:\/\/github.com[^\"]+)"/)[1]));
    assert.equal(authorization.searchParams.get('prompt'),'select_account');
    f.expectedChallenge=authorization.searchParams.get('code_challenge');
    return {response,html,authorization,state:authorization.searchParams.get('state'),cookie:`${f.sid}; ${cookie(response,'__Host-acct_manage')}`};
  };
  f.verify=async()=>{const flow=await f.manage();const r=await f.callback(flow);assert.equal(r.status,303,await r.clone().text());return {flow,response:r};};
  return f;
}

test('account page escapes profile/identity/device metadata, lists all clients, and uses form headers without GitHub CSP permission',async()=>{
  const f=await setup();
  try {
    f.db.prepare("UPDATE users SET display_name=?").run('<img src=x onerror=alert(1)>');
    f.db.prepare('UPDATE identities SET login=?').run('<script>bad</script>');
    f.db.prepare('UPDATE sessions SET ua_summary=?,country=?').run('<svg onload=bad>','<iframe>');
    const {response,html,forms:all}=await f.dashboard();
    assert.match(html,/&lt;img/);assert.match(html,/&lt;script/);assert.match(html,/&lt;svg/);assert.match(html,/&lt;iframe/);
    assert.equal(/<(script|img|iframe|svg)\b/.test(html),false);
    assert.equal(response.headers.get('Referrer-Policy'),'same-origin');assert.match(response.headers.get('Content-Security-Policy'),/form-action 'self'$/);
    assert.equal(response.headers.get('Cache-Control'),'no-store');assert.ok(all.every(x=>x.fields.csrf));assert.equal(all.length,7);
    assert.match(html,/this session/);assert.match(html,/Last active/);assert.match(html,/not available yet/);
  } finally {f.close();}
});

test('every account mutation rejects the CSRF matrix, cross-action tokens and GET attempts',async()=>{
  for(const path of ['/account/sessions/revoke','/account/sessions/revoke-all','/account/step-up','/account/identities/link','/account/identities/unlink','/account/export','/account/delete']) {
    const f=await setup();
    try {
      const form=await f.formFor(path);const before=f.db.prepare('SELECT count(*) n FROM security_audit').get().n;
      for(const [body,headers] of [[{csrf:''},{}],[{csrf:'bad'},{}],[{}, {Origin:'https://sibling.example.test'}],[{},{Origin:''}],[{},{Origin:'null'}],
        [{},{'Sec-Fetch-Site':'same-site'}],[{},{'Content-Type':'application/json'}],[{},{Cookie:''}]]) {
        assert.ok((await f.post(form,body,headers)).status>=400,path);
      }
      const other=(await f.dashboard()).forms.find(x=>x.path!==path);
      assert.ok((await f.post(form,{csrf:other.fields.csrf})).status>=400,path);
      const missing={...form.fields};delete missing.csrf;
      assert.ok((await f.call(path,{method:'POST',headers:{Cookie:f.sid,Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(missing)})).status>=400);
      assert.equal((await f.call(path,{headers:{Cookie:f.sid}})).status,404);
      assert.equal(f.db.prepare('SELECT count(*) n FROM security_audit').get().n,before);
      assert.equal(f.db.prepare('SELECT count(*) n FROM management_requests').get().n,0);
      assert.equal(f.db.prepare('SELECT revoked_at FROM sessions').get().revoked_at,null);
    } finally {f.close();}
  }
});

test('same-subject step-up is browser/session bound, single use and valid strictly less than ten minutes',async()=>{
  const f=await setup();
  try {
    for(const path of ['/account/identities/link','/account/identities/unlink','/account/export','/account/delete']) assert.equal((await f.post(await f.formFor(path))).status,403);
    const flow=await f.manage();assert.equal(flow.response.headers.get('Referrer-Policy'),'no-referrer');assert.match(flow.response.headers.get('Content-Security-Policy'),/form-action 'self'$/);
    const stored=f.db.prepare('SELECT * FROM management_requests').get();assert.equal(stored.state_hash,sha(flow.state));assert.equal(stored.expires_at-stored.created_at,600);
    assert.equal((await f.callback({...flow,cookie:f.sid})).status,403);
    const response=await f.callback(flow);assert.equal(response.status,303);
    assert.equal(f.db.prepare('SELECT step_up_at FROM sessions').get().step_up_at,f.now);
    assert.equal((await f.callback(flow)).status,403);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='step_up.succeeded'").get().n,1);
    for(const path of ['/account/export','/account/delete']) assert.equal((await f.post(await f.formFor(path))).status,501);
    f.now+=599;await new AccountStore(f.env.IDENTITY).requireFresh(sha(f.sid.split('=')[1]),f.now);
    f.now+=1;for(const path of ['/account/identities/link','/account/identities/unlink','/account/export','/account/delete']) assert.equal((await f.post(await f.formFor(path))).status,403);
    assert.equal(f.db.prepare('SELECT status FROM users').get().status,'active');
  } finally {f.close();}
});

test('wrong-subject step-up audits and revokes the originating session without signing in or linking the other identity',async()=>{
  const f=await setup();
  try {
    const flow=await f.manage();f.profile={id:98765,login:'other',name:'Other',avatar_url:null};
    const response=await f.callback(flow);assert.equal(response.status,403);assert.match(cookie(response,'__Host-acct_sid'),/=$/);
    const row=f.db.prepare('SELECT * FROM sessions').get();assert.equal(row.revoked_at,f.now);assert.equal(row.revoke_reason,'step_up_subject_mismatch');assert.equal(row.step_up_at,null);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='step_up.subject_mismatch'").get().n,1);
    assert.equal(f.db.prepare('SELECT count(*) n FROM users').get().n,1);assert.equal(f.db.prepare('SELECT count(*) n FROM identities').get().n,1);
  } finally {f.close();}
});

test('step-up refuses expiry, cancellation, switched sessions and revocation during the provider round trip',async()=>{
  for(const scenario of ['expired','cancelled','switched','revoked','provider-timeout']) {
    const f=await setup();
    try {
      const flow=await f.manage();let patch={};
      if(scenario==='expired')f.now+=600;
      if(scenario==='cancelled')patch={error:'access_denied'};
      if(scenario==='switched'){
        const token=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'99999',login:'bob',displayName:'Bob',avatarUrl:null},sha(token),f.now,f.now);
        flow.cookie=flow.cookie.replace(f.sid,`__Host-acct_sid=${token}`);
      }
      if(scenario==='revoked')f.onProfile=async()=>{f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='test'").run(f.now);};
      if(scenario==='provider-timeout')f.onProfile=async()=>{f.now+=600;};
      const r=await f.callback(flow,patch);assert.ok(r.status>=400,scenario);
      assert.equal(f.db.prepare('SELECT count(*) n FROM sessions WHERE step_up_at IS NOT NULL').get().n,0);
    } finally {f.close();}
  }
});

test('session revocation is cross-client but never cross-user; sign out everywhere expires only the accounts cookie',async()=>{
  const f=await setup();
  try {
    const secondToken=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'12345',login:'same',displayName:'Same',avatarUrl:null},sha(secondToken),f.now,f.now);
    f.db.exec("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json) VALUES ('forum-test','Forum','binding','[]')");
    f.db.prepare("UPDATE sessions SET client='forum-test' WHERE token_hash=?").run(sha(secondToken));
    const otherToken=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'99999',login:'bob',displayName:'Bob',avatarUrl:null},sha(otherToken),f.now,f.now);
    const otherId=f.db.prepare('SELECT id FROM sessions WHERE token_hash=?').get(sha(otherToken)).id;
    await assert.rejects(new AccountStore(f.env.IDENTITY).revoke(sha(f.sid.split('=')[1]),otherId,f.now));
    const form=await f.formFor('/account/sessions/revoke');assert.equal((await f.post(form,{session:otherId})).status,403);
    const target=(await f.dashboard()).forms.find(x=>x.fields.session && x.fields.session!==f.session.id);
    assert.equal((await f.post(target)).status,303);assert.equal(f.db.prepare('SELECT revoked_at FROM sessions WHERE token_hash=?').get(sha(secondToken)).revoked_at,f.now);
    assert.equal(f.db.prepare('SELECT revoked_at FROM sessions WHERE token_hash=?').get(sha(otherToken)).revoked_at,null);
    const third=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'12345',login:'same',displayName:'Same',avatarUrl:null},sha(third),f.now,f.now);
    f.db.prepare("UPDATE sessions SET client='forum-test' WHERE token_hash=?").run(sha(third));
    const response=await f.post(await f.formFor('/account/sessions/revoke-all'));assert.equal(response.status,303);assert.equal(response.headers.has('Clear-Site-Data'),false);
    assert.equal(response.headers.getSetCookie().length,1);assert.match(response.headers.get('Set-Cookie'),/^__Host-acct_sid=;/);
    assert.equal(f.db.prepare('SELECT revoked_at FROM sessions WHERE token_hash=?').get(sha(otherToken)).revoked_at,null);
    assert.equal(f.db.prepare('SELECT revoked_at FROM sessions WHERE token_hash=?').get(sha(third)).revoked_at,f.now);
    assert.equal((await f.call('/account',{headers:{Cookie:f.sid}})).status,303);
  } finally {f.close();}
});

test('link requires fresh verification, refuses existing ownership, and unlink refuses the last identity and revokes sessions using the removed identity',async()=>{
  const f=await setup();
  try {
    await f.verify();assert.equal((await f.post(await f.formFor('/account/identities/unlink'))).status,403);
    const bob=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'99999',login:'bob',displayName:'Bob',avatarUrl:null},sha(bob),f.now,f.now);
    let flow=await f.manage('link');f.profile={id:99999,login:'bob',name:'Bob',avatar_url:null};assert.equal((await f.callback(flow)).status,403);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='identity.link_refused'").get().n,1);
    flow=await f.manage('link');f.profile={id:67890,login:'second',name:'Second',avatar_url:null,email:'discard@example.test'};assert.equal((await f.callback(flow)).status,303);
    assert.equal(f.db.prepare('SELECT email FROM identities WHERE provider_subject=?').get('67890').email,null);
    const bobIdentity=f.db.prepare("SELECT id FROM identities WHERE provider_subject='99999'").get().id;
    await assert.rejects(new AccountStore(f.env.IDENTITY).unlink(sha(f.sid.split('=')[1]),bobIdentity,f.now));
    const secondIdentity=f.db.prepare("SELECT id FROM identities WHERE provider_subject='67890'").get().id;
    const secondToken=randomToken();await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'67890',login:'second',displayName:'Second',avatarUrl:null},sha(secondToken),f.now,f.now);
    const unlink=(await f.dashboard()).forms.find(x=>x.fields.identity===secondIdentity);assert.equal((await f.post(unlink)).status,303);
    assert.equal(f.db.prepare('SELECT id FROM identities WHERE id=?').get(secondIdentity),undefined);
    assert.equal(f.db.prepare('SELECT revoke_reason FROM sessions WHERE token_hash=?').get(sha(secondToken)).revoke_reason,'identity_unlinked');
    assert.equal(f.db.prepare('SELECT revoked_at FROM sessions WHERE id=?').get(f.session.id).revoked_at,null);
    assert.equal((await f.post(await f.formFor('/account/identities/unlink'))).status,403);
  } finally {f.close();}
});

test('concurrent unlink cannot remove the last identity and management ciphertext is purpose/session bound',async()=>{
  const f=await setup();
  try {
    await f.verify();const flow=await f.manage('link');f.profile={id:67890,login:'second',name:'Second',avatar_url:null};assert.equal((await f.callback(flow)).status,303);
    const identities=f.db.prepare('SELECT id FROM identities ORDER BY id').all();
    const store=new AccountStore(f.env.IDENTITY);const hash=sha(f.sid.split('=')[1]);
    const attempts=await Promise.allSettled(identities.map(i=>store.unlink(hash,i.id,f.now)));
    assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.db.prepare('SELECT count(*) n FROM identities').get().n,1);
  } finally {f.close();}
  const g=await setup();
  try {
    const login=await g.start();const cipher=g.db.prepare('SELECT pkce_verifier_enc FROM auth_requests WHERE state_hash=?').get(sha(login.state)).pkce_verifier_enc;
    const flow=await g.manage();g.db.prepare('UPDATE management_requests SET pkce_verifier_enc=?').run(cipher);
    const calls=g.exchangeCalls;assert.ok((await g.callback(flow)).status>=400);assert.equal(g.exchangeCalls,calls);
    assert.equal(g.db.prepare('SELECT step_up_at FROM sessions').get().step_up_at,null);
  } finally {g.close();}
});

test('sign-in stores only coarse browser/OS and country metadata, never the raw user agent or IP',async()=>{
  const f=fixture();
  try {
    const flow=await f.start();const ua='Mozilla/5.0 (Windows NT 10.0) Chrome/150.0 distinctive-private-suffix';
    const response=await f.call(`/auth/github/callback?state=${flow.state}&code=fixture-code`,{headers:{Cookie:flow.cookie,'User-Agent':ua,'CF-IPCountry':'US','CF-Connecting-IP':'192.0.2.99'}});
    assert.equal(response.status,303);const row=f.db.prepare('SELECT * FROM sessions').get();
    assert.equal(row.ua_summary,'Chrome on Windows');assert.equal(row.country,'US');assert.equal(row.ip_hash,null);
    assert.equal(row.sign_in_identity_id,f.db.prepare('SELECT id FROM identities').get().id);
    assert.equal(JSON.stringify(row).includes(ua),false);assert.equal(JSON.stringify(row).includes('192.0.2.99'),false);
  } finally {f.close();}
});

test('login and step-up callback contexts cannot exchange states or relabel each other’s nonce cookies',async()=>{
  const f=await setup();
  try {
    const login=await f.start();const step=await f.manage();
    const loginNonce=login.cookie.split('=')[1];
    const managementNonce=step.cookie.split('; ').find(c=>c.startsWith('__Host-acct_manage=')).split('=')[1];
    const calls=f.exchangeCalls;
    for(const swapped of [
      {...step,cookie:`${f.sid}; ${login.cookie}`},
      {...step,cookie:`${f.sid}; __Host-acct_manage=${loginNonce}`},
      {...login,cookie:step.cookie},
      {...login,cookie:`${f.sid}; __Host-acct_oauth=${managementNonce}`},
    ]) assert.ok((await f.callback(swapped)).status>=400);
    assert.equal(f.exchangeCalls,calls,'cross-flow requests must fail before provider exchange');
    assert.equal(f.db.prepare('SELECT used_at FROM auth_requests WHERE state_hash=?').get(sha(login.state)).used_at,null);
    assert.equal(f.db.prepare('SELECT used_at FROM management_requests WHERE state_hash=?').get(sha(step.state)).used_at,null);
    assert.equal(f.db.prepare('SELECT step_up_at FROM sessions').get().step_up_at,null);
    assert.equal(f.db.prepare('SELECT count(*) n FROM sessions').get().n,1);
    // The single callback endpoint follows stored purpose, so valid contexts still work as intended.
    f.expectedChallenge=step.authorization.searchParams.get('code_challenge');
    assert.equal((await f.callback(step)).status,303);
    assert.equal(f.db.prepare('SELECT count(*) n FROM sessions').get().n,1,'step-up must never mint a login session');
    f.expectedChallenge=login.authorization.searchParams.get('code_challenge');
    assert.equal((await f.callback(login)).status,303);
    const count=f.db.prepare('SELECT count(*) n FROM sessions').get().n;
    const both=`${f.sid}; ${login.cookie}; __Host-acct_manage=${managementNonce}`;
    for(const flow of [login,step]) assert.ok((await f.callback({...flow,cookie:both})).status>=400);
    assert.equal(f.db.prepare('SELECT count(*) n FROM sessions').get().n,count);
  } finally {f.close();}
});

test('step-up and link POSTs set their own bound nonce and expose raw state only in the script-free interstitial link',async()=>{
  for(const purpose of ['step-up','link']) {
    const f=await setup();
    try {
      if(purpose==='link')await f.verify();
      const flow=await f.manage(purpose);assert.equal(flow.response.status,200);
      assert.equal(flow.response.headers.get('Cache-Control'),'no-store');
      assert.equal(flow.response.headers.get('Referrer-Policy'),'no-referrer');
      assert.match(flow.response.headers.get('Content-Security-Policy'),/script-src 'none'/);
      assert.match(flow.response.headers.get('Content-Security-Policy'),/form-action 'self'$/);
      assert.equal(flow.response.headers.has('Location'),false);
      assert.match(flow.response.headers.get('Set-Cookie'),/^__Host-acct_manage=.*Secure; HttpOnly; SameSite=Lax; Max-Age=600/);
      assert.equal(flow.html.split(flow.state).length-1,1);
      assert.ok(flow.html.match(/href="https:\/\/github.com[^\"]+"/)[0].includes(flow.state));
      assert.equal(/<(script|form)\b/i.test(flow.html),false);
      assert.equal(JSON.stringify([...flow.response.headers]).includes(flow.state),false);
      const row=f.db.prepare('SELECT * FROM management_requests WHERE state_hash=?').get(sha(flow.state));
      assert.equal(row.purpose,purpose==='step-up'?'step_up':'link');assert.equal(row.used_at,null);
      assert.equal(row.expires_at-row.created_at,600);assert.equal(row.session_id,f.session.id);
      const nonce=cookie(flow.response,'__Host-acct_manage').split('=')[1];
      assert.equal(row.browser_nonce_hash,sha(nonce));assert.notEqual(nonce,flow.state);
      assert.equal(JSON.stringify(row).includes(flow.state),false);
    } finally {f.close();}
  }
});

test('dashboard buttons reflect exact step-up lifetime and last-identity rules, with usable labels and UTC session metadata',async()=>{
  const f=await setup();try{
    f.db.prepare('UPDATE sessions SET ua_summary=NULL,country=NULL').run();
    const otherToken=randomToken();await new Store(f.env.IDENTITY,f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'12345',login:'fixture-user',displayName:'Fixture User',avatarUrl:null},sha(otherToken),f.now,f.now);
    const buttons=html=>[...html.matchAll(/<form method="post" action="([^"]+)">([\s\S]*?)<button type="submit"([^>]*)>([^<]+)<\/button><\/form>/g)].map(m=>({path:m[1],disabled:m[3].includes('disabled'),label:unescape(m[4])}));
    for(const at of [null,f.now-600,f.now-599,f.now,f.now+1]){
      f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(at,f.session.id);
      const {response,html}=await f.dashboard();assert.equal(response.headers.get('Content-Type'),'text/html; charset=utf-8');
      const fresh=at!==null&&at<=f.now&&at>f.now-600;const b=buttons(html);assert.equal(b.length,8);
      assert.equal(b.find(x=>x.path==='/account/step-up').disabled,false);assert.equal(b.find(x=>x.path==='/account/step-up').label,'Verify with GitHub');
      assert.equal(b.find(x=>x.path==='/account/identities/link').disabled,!fresh);assert.equal(b.find(x=>x.path==='/account/identities/link').label,'Link another GitHub account');
      assert.equal(b.find(x=>x.path==='/account/identities/unlink').disabled,true);assert.equal(b.find(x=>x.path==='/account/identities/unlink').label,'Unlink fixture-user');
      for(const [path,label] of [['/account/export','Request data export'],['/account/delete','Delete account']])assert.deepEqual(b.find(x=>x.path===path),{path,label,disabled:true});
      assert.equal(b.find(x=>x.path==='/account/sessions/revoke-all').label,'Sign out everywhere');assert.equal(b.find(x=>x.path==='/account/sessions/revoke-all').disabled,false);
      for(const x of b.filter(x=>x.path==='/account/sessions/revoke'))assert.deepEqual(x,{path:'/account/sessions/revoke',disabled:false,label:'Sign out this session'});
      assert.match(html,fresh?/Identity verified recently\. Sensitive account actions are available for ten minutes after verification\./:/Verify with a linked GitHub account before linking or unlinking an identity\./);
      assert.match(html,/2033-05-18 03:33:20 UTC/);assert.match(html,/Unknown device/);assert.match(html,/Not recorded/);
      assert.equal((html.match(/\(this session\)/g)||[]).length,1);assert.match(html,/<th scope="row">accounts<\/th>/);
    }
    f.db.prepare("INSERT INTO identities(id,user_id,provider,provider_subject,login,linked_at) VALUES ('idn_two',?,'github','67890','second',?)").run(f.session.user_id,f.now);
    for(const [at,disabled] of [[f.now,false],[f.now-600,true]]){
      f.db.prepare('UPDATE sessions SET step_up_at=? WHERE id=?').run(at,f.session.id);
      assert.ok(buttons((await f.dashboard()).html).filter(x=>x.path==='/account/identities/unlink').every(x=>x.disabled===disabled));
    }
  }finally{f.close();}
});
test('management outcomes render explicit explanations, navigation and cookie clearing',async()=>{
  const f=await setup();try{
    const unsigned=await f.call('/account');assert.equal(unsigned.status,303);assert.equal(unsigned.headers.get('Location'),'/login');assert.match(unsigned.headers.get('Set-Cookie'),/__Host-acct_sid=;.*Max-Age=0/);
    const flow=await f.manage();assert.equal(flow.response.headers.get('Content-Type'),'text/html; charset=utf-8');assert.match(flow.html,/Choose a GitHub account already linked to this Synthetos account to verify your identity\./);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='step_up.started'").get().n,1);
    const cancelled=await f.callback(flow,{error:'access_denied'});assert.equal(cancelled.status,400);assert.equal(cancelled.headers.get('Content-Type'),'text/html; charset=utf-8');assert.match(await cancelled.text(),/Verification was cancelled/);assert.match(cancelled.headers.get('Set-Cookie'),/__Host-acct_manage=;.*Max-Age=0/);
    const invalid=await f.callback(await f.manage(),{error:'other'});assert.equal(invalid.status,400);assert.equal(await invalid.text(),'request_refused');
    const verified=await f.verify();assert.equal(verified.response.headers.get('Location'),'/account');assert.match(verified.response.headers.get('Set-Cookie'),/__Host-acct_manage=;.*Max-Age=0/);
    for(const path of ['/account/export','/account/delete']){const r=await f.post(await f.formFor(path));assert.equal(r.status,501);assert.equal(r.headers.get('Content-Type'),'text/html; charset=utf-8');assert.match(await r.text(),/This feature is not available yet/);}
    const linked=await f.manage('link');assert.match(linked.html,/Choose the GitHub account you want to link\. It must not belong to another Synthetos account\./);assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='identity.link_started'").get().n,1);
    const missing=await f.call('/account/unknown',{headers:{Cookie:f.sid}});assert.equal(missing.status,404);assert.equal(await missing.text(),'Not found.');
    const fresh=await f.manage();f.profile={id:67890,login:'wrong',name:null,avatar_url:null};const wrong=await f.callback(fresh);assert.equal(wrong.status,403);assert.equal(wrong.headers.get('Content-Type'),'text/html; charset=utf-8');assert.match(await wrong.text(),/This session has been signed out/);
  }finally{f.close();}
});
test('single-session revocation clears only its own cookie and audits the exact operation',async()=>{
  const f=await setup();try{
    await new Store(f.env.IDENTITY,f.env.GITHUB_ALLOWED_IDS).signIn('github',{subject:'12345',login:'fixture-user',displayName:'Fixture User',avatarUrl:null},sha(randomToken()),f.now,f.now);
    const other=f.db.prepare('SELECT id FROM sessions WHERE id<>?').get(f.session.id).id;
    let form=(await f.dashboard()).forms.find(x=>x.fields.session===other);let response=await f.post(form);
    assert.equal(response.status,303);assert.equal(response.headers.get('Location'),'/account');assert.equal(response.headers.get('Set-Cookie'),null);
    assert.equal(f.db.prepare("SELECT count(*) n FROM security_audit WHERE event='session.revoked'").get().n,1);
    form=(await f.dashboard()).forms.find(x=>x.fields.session===f.session.id);response=await f.post(form);assert.match(response.headers.get('Set-Cookie'),/__Host-acct_sid=;.*Max-Age=0/);
  }finally{f.close();}
  const f2=await setup();try{const r=await f2.post(await f2.formFor('/account/sessions/revoke-all'));assert.equal(r.status,303);assert.equal(f2.db.prepare("SELECT count(*) n FROM security_audit WHERE event='sessions.revoked_all'").get().n,1);}finally{f2.close();}
});
test('management forms reject unknown and duplicate target parameters even with a valid CSRF proof',async()=>{
  const f=await setup();try{
    for(const path of ['/account/step-up','/account/sessions/revoke','/account/identities/unlink']){
      const form=await f.formFor(path);
      assert.equal((await f.post(form,{unexpected:'yes'})).status,400);
      const body=new URLSearchParams(form.fields);const target=path.endsWith('revoke')?'session':path.endsWith('unlink')?'identity':'csrf';body.append(target,form.fields[target]);
      assert.equal((await f.call(path,{method:'POST',headers:{Cookie:f.sid,Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body})).status,400);
    }
    const proof=await f.manage();f.onProfile=()=>{f.now-=1;};const result=await f.callback(proof);assert.equal(result.status,403);assert.equal(await result.text(),'verification_refused');
  }finally{f.close();}
});

test('management code bounds and callback method are enforced before provider exchange',async()=>{
  for(const [code,status,calls] of [['x'.repeat(1024),502,1],['x'.repeat(1025),400,0],['a b',400,0]]){
    const f=await setup();try{const flow=await f.manage();const before=f.exchangeCalls;const response=await f.callback(flow,{code});assert.equal(response.status,status);assert.equal(f.exchangeCalls-before,calls);}finally{f.close();}
  }
  const f=await setup();try{const flow=await f.manage();assert.equal((await f.call(`/auth/github/callback?state=${flow.state}&code=fixture-code`,{method:'POST',headers:{Cookie:flow.cookie}})).status,404);assert.equal(f.db.prepare('SELECT used_at FROM management_requests').get().used_at,null);}finally{f.close();}
});
