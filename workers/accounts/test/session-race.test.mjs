import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, sha } from './fixture.mjs';
import { Store } from '../src/store.ts';
import { OidcStore } from '../src/oidc-store.ts';
import { randomToken } from '../../../packages/auth-core/src/index.ts';

async function sessionFixture(client) {
  const f=fixture();const hash=sha(randomToken());
  await new Store(f.env.IDENTITY,f.env.GITHUB_ALLOWED_IDS).signIn('github',
    {subject:'12345',login:'alice',displayName:'Alice',avatarUrl:null},hash,f.now,f.now);
  if(client!=='accounts') {
    f.db.exec("INSERT INTO oauth_clients(id,name,kind,redirect_uris_json,secret_hash) VALUES ('forum','Forum','confidential','[]','"+'0'.repeat(64)+"')");
    f.db.prepare("UPDATE sessions SET client='forum',idle_expires_at=?,abs_expires_at=?").run(f.now+43200,f.now+604800);
  }
  const adapter=f.env.IDENTITY.withSession('first-primary');
  let writes=0;let beforeUpdate=()=>{};
  // Interleave a real SQLite write between the session read and refresh. The
  // statement itself still executes against the database, including all guards.
  const wrapped={...adapter,prepare(sql){
    const statement=adapter.prepare(sql);
    const before=()=>{if(sql.startsWith('UPDATE sessions SET last_seen_at=')){writes++;beforeUpdate();}};
    return {bind(...values){statement.bind(...values);return this;},
      async first(){before();return statement.first();},async run(){before();return statement.run();},
      execute(){before();return statement.execute();}};
  }};
  const database={withSession(mode){assert.equal(mode,'first-primary');return wrapped;}};
  const store=client==='accounts'?new Store(database):new OidcStore(database);
  return Object.assign(f,{validate:()=>client==='accounts'?store.validate(hash,f.now):store.validate(hash,client,f.now),
    writes:()=>writes,interleave(action){beforeUpdate=action;}});
}

test('account and RP validation throttle idle writes at the exact five-minute boundary',async()=>{
  for(const client of ['accounts','forum']){
    const f=await sessionFixture(client);try{
      const initial=f.now;
      f.now=initial+299;assert.ok(await f.validate());assert.equal(f.writes(),0);
      assert.equal(f.db.prepare('SELECT last_seen_at FROM sessions').get().last_seen_at,initial);
      f.now=initial+300;assert.ok(await f.validate());assert.equal(f.writes(),1);
      const row=f.db.prepare('SELECT last_seen_at,idle_expires_at FROM sessions').get();
      assert.equal(row.last_seen_at,f.now);assert.equal(row.idle_expires_at,f.now+(client==='accounts'?14*86400:43200));
      f.now++;assert.ok(await f.validate());assert.equal(f.writes(),1);
    }finally{f.close();}
  }
});

test('revocation or account lock racing idle refresh is observed before validation returns',async()=>{
  for(const client of ['accounts','forum'])for(const change of ['revoke','lock']){
    const f=await sessionFixture(client);try{
      const initial=f.now;f.now+=300;
      f.interleave(()=>{
        if(change==='revoke')f.db.prepare("UPDATE sessions SET revoked_at=?,revoke_reason='race-test'").run(f.now);
        else f.db.exec("UPDATE users SET status='locked'");
      });
      assert.equal(await f.validate(),null,client+':'+change);
      assert.equal(f.db.prepare('SELECT last_seen_at FROM sessions').get().last_seen_at,initial);
    }finally{f.close();}
  }
});

test('an older in-flight validation cannot overwrite a concurrent newer idle refresh',async()=>{
  for(const client of ['accounts','forum']){
    const f=await sessionFixture(client);try{
      f.now+=300;const newer=f.now+1;const idle=newer+(client==='accounts'?14*86400:43200);
      f.interleave(()=>f.db.prepare('UPDATE sessions SET last_seen_at=?,idle_expires_at=?').run(newer,idle));
      assert.ok(await f.validate());
      const row=f.db.prepare('SELECT last_seen_at,idle_expires_at FROM sessions').get();
      assert.equal(row.last_seen_at,newer);assert.equal(row.idle_expires_at,idle);
    }finally{f.close();}
  }
});

test('rate limiting retains the original window and rejects the eleventh attempt before reset',async()=>{
  const f=fixture();try{
    const store=new Store(f.env.IDENTITY);const bucket=sha('fixture-bucket');const initial=f.now;
    for(let i=0;i<10;i++)await store.rateLimit(bucket,initial+i*20);
    const row=f.db.prepare('SELECT window_start,attempts FROM login_rate_limits').get();
    assert.equal(row.window_start,initial);assert.equal(row.attempts,10);
    await assert.rejects(store.rateLimit(bucket,initial+599),{status:429,message:'try_again_later'});
    await store.rateLimit(bucket,initial+600);
    assert.equal(f.db.prepare('SELECT attempts FROM login_rate_limits').get().attempts,1);
  }finally{f.close();}
});
