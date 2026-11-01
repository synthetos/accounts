import {test} from 'node:test';
import assert from 'node:assert/strict';
import {GitHubProvider} from '../../../packages/idp/src/index.ts';

const options={clientId:'app-id',clientSecret:'private-secret',redirectUri:'https://accounts.test/auth/github/callback'};
const profile={id:123,login:'fixture',name:'Fixture',avatar_url:'https://avatars.githubusercontent.com/u/123?v=4'};
function provider(value){return new GitHubProvider({...options,fetch:async()=>Response.json(value)});}
test('GitHub adapter validates callback configuration and produces the exact scope-free authorize request',()=>{
  for(const change of [{redirectUri:'http://accounts.test/auth/github/callback'},{redirectUri:'https://user@accounts.test/auth/github/callback'},
    {redirectUri:'https://:pass@accounts.test/auth/github/callback'},{redirectUri:options.redirectUri+'?query'},{redirectUri:options.redirectUri+'#fragment'},
    {redirectUri:'https://accounts.test/wrong'},{clientId:''},{clientSecret:''}])assert.throws(()=>new GitHubProvider({...options,...change}));
  const p=provider({});assert.equal(p.name,'github');
  const url=new URL(p.authorizeUrl('a&state','challenge'));
  assert.equal(url.origin,'https://github.com');assert.equal(url.pathname,'/login/oauth/authorize');
  assert.deepEqual(Object.fromEntries(url.searchParams),{client_id:'app-id',redirect_uri:options.redirectUri,state:'a&state',code_challenge:'challenge',code_challenge_method:'S256'});
  assert.equal(new URL(p.authorizeUrl('s','c',{selectAccount:false})).searchParams.has('prompt'),false);
  assert.equal(new URL(p.authorizeUrl('s','c',{selectAccount:true})).searchParams.get('prompt'),'select_account');
});
test('GitHub network requests have fixed destinations, bounded timeouts, manual redirects and exact transient credentials',async()=>{
  const originalTimeout=AbortSignal.timeout;const timeouts=[];
  AbortSignal.timeout=ms=>{timeouts.push(ms);return originalTimeout(ms);};
  try{
    let calls=0;const p=new GitHubProvider({...options,fetch:async(url,init)=>{
      assert.equal(init.redirect,'manual');assert.ok(init.signal instanceof AbortSignal);assert.equal(init.signal.aborted,false);
      if(calls++===0){assert.equal(url,'https://github.com/login/oauth/access_token');assert.equal(init.method,'POST');
        assert.deepEqual(init.headers,{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded'});
        assert.deepEqual(Object.fromEntries(init.body),{client_id:'app-id',client_secret:'private-secret',code:'code',redirect_uri:options.redirectUri,code_verifier:'verifier'});
        return Response.json({token_type:'bearer',access_token:'transient'});
      }
      assert.equal(url,'https://api.github.com/user');assert.deepEqual(init.headers,{Accept:'application/vnd.github+json',Authorization:'Bearer transient','User-Agent':'Synthetos-Accounts','X-GitHub-Api-Version':'2022-11-28'});
      return Response.json({...profile,email:'never-store@example.test',permissions:{admin:true}});
    }});
    assert.deepEqual(await p.profile(await p.exchange('code','verifier')),{subject:'123',login:'fixture',displayName:'Fixture',avatarUrl:profile.avatar_url});
    assert.deepEqual(timeouts,[10000,10000]);assert.equal(calls,2);
  }finally{AbortSignal.timeout=originalTimeout;}
});
test('provider JSON consumes chunked UTF-8 exactly up to 64 KiB and refuses malformed, oversized or non-object responses',async()=>{
  const json=JSON.stringify({...profile,name:'€'});const padded=json+' '.repeat(65536-Buffer.byteLength(json));
  const bytes=Buffer.from(padded);const euro=bytes.indexOf(Buffer.from('€'));
  const p=new GitHubProvider({...options,fetch:async()=>new Response(new ReadableStream({start(c){
    for(const b of [bytes.subarray(0,euro+1),bytes.subarray(euro+1,euro+2),bytes.subarray(euro+2)])c.enqueue(b);c.close();
  }}))});
  assert.equal((await p.profile('token')).displayName,'€');
  for(const make of [()=>new Response(padded+' '),()=>new Response(Uint8Array.from([0xff])),()=>new Response(null),()=>new Response('null'),()=>new Response('[]'),()=>new Response('"text"'),()=>new Response('{}',{status:500}),()=>new Response('{}',{status:302,headers:{Location:'https://evil.test'}})]){
    await assert.rejects(new GitHubProvider({...options,fetch:async()=>make()}).profile('token'),{message:'provider_unavailable'});
  }
});
test('provider tokens enforce string, type, length and whitespace boundaries before becoming bearer credentials',async()=>{
  for(const token of ['a','a'.repeat(4096)])assert.equal(await provider({token_type:'bearer',access_token:token}).exchange('code','verifier'),token);
  for(const token of ['',42,null,'a'.repeat(4097),'a b','a\tb','a\nb','a\rb','a\u0000b','a\u001fb'])await assert.rejects(provider({token_type:'bearer',access_token:token}).exchange('code','verifier'),{message:'provider_unavailable'});
  for(const value of [{token_type:'Bearer',access_token:'a'},{token_type:'bearer',access_token:'a',error:null},{access_token:'a'}])await assert.rejects(provider(value).exchange('c','v'));
});
test('profiles admit bounded stable numeric IDs and login/name fields while refusing unsafe avatar origins',async()=>{
  for(const id of [1,Number.MAX_SAFE_INTEGER])assert.equal((await provider({...profile,id}).profile('token')).subject,String(id));
  for(const id of [0,-1,1.1,Number.MAX_SAFE_INTEGER+1,'1',null])await assert.rejects(provider({...profile,id}).profile('token'));
  for(const login of ['a','A-09','a'.repeat(39)])assert.equal((await provider({...profile,login}).profile('token')).login,login);
  for(const login of ['',null,42,'a'.repeat(40),'a_b','!a','a!','a\n'])await assert.rejects(provider({...profile,login}).profile('token'));
  for(const name of [null,'','n'.repeat(256)])assert.equal((await provider({...profile,name}).profile('token')).displayName,name||profile.login);
  for(const name of [42,{},'n'.repeat(257)])await assert.rejects(provider({...profile,name}).profile('token'));
  for(const avatar_url of [null,42,'https://elsewhere.test/u/1','http://avatars.githubusercontent.com/u/1','https://u@avatars.githubusercontent.com/u/1','https://:p@avatars.githubusercontent.com/u/1','https://avatars.githubusercontent.com:444/u/1','https://avatars.githubusercontent.com.evil.test/u/1','https://avatars.githubusercontent.com/'+'a'.repeat(2048)])
    assert.equal((await provider({...profile,avatar_url}).profile('token')).avatarUrl,null);
  const prefix='https://avatars.githubusercontent.com/';const url=prefix+'a'.repeat(2048-prefix.length);
  assert.equal((await provider({...profile,avatar_url:url}).profile('token')).avatarUrl,url);
});
