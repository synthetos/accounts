import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readBody, single, returnPath, escapeHtml, key, seal, unseal, keyedHash, userId } from '../src/security.ts';
import { coarseClient } from '../src/account.ts';

function streamed(chunks) {
  return new Request('https://accounts.test/', { method:'POST', duplex:'half',
    body:new ReadableStream({start(c){for(const chunk of chunks)c.enqueue(Uint8Array.from(chunk));c.close();}}) });
}
test('bounded UTF-8 body reader counts bytes across chunks and rejects incomplete or malformed characters',async()=>{
  assert.equal(await readBody(streamed([[65,0xe2],[0x82],[0xac,66]]),5),'A€B');
  await assert.rejects(readBody(streamed([[65,0xe2],[0x82],[0xac,66]]),4),{status:413,message:'request_too_large'});
  for(const bytes of [[0xff],[0xe2,0x82],[0xc0,0xaf]])await assert.rejects(readBody(streamed([bytes]),10));
  await assert.rejects(readBody(new Request('https://accounts.test/'),10),{status:400});
  assert.equal(await readBody(streamed([]),0),'');
});
test('form selectors and local return paths reject ambiguity, encoded delimiters and overlong targets',()=>{
  assert.equal(single(new URLSearchParams('x=one'),'x'),'one');
  for(const params of ['','x=','x=one&x=two'])assert.throws(()=>single(new URLSearchParams(params),'x'));
  const origin='https://accounts.test';
  for(const value of ['/','/account','/authorize/resume/abc123','/'+'a'.repeat(255)])assert.equal(returnPath(value,origin),value);
  for(const value of ['/'+'a'.repeat(256),'//evil.test','/\\evil','relative','/a?x=1','/a#b','/%2f','/A','/a\n','/a b'])assert.throws(()=>returnPath(value,origin));
  assert.equal(escapeHtml('&<>"\''),'&amp;&lt;&gt;&quot;&#39;');
});
test('sealed state uses fresh nonces and authenticates every ciphertext, binding and key byte',async()=>{
  const bytes=Buffer.alloc(32,7);const encoded=bytes.toString('base64url');
  const secret=await key(encoded,'AES-GCM');assert.equal(secret.extractable,false);assert.deepEqual(secret.usages,['encrypt','decrypt']);
  const one=await seal('verifier €',secret,'origin|state|nonce');const two=await seal('verifier €',secret,'origin|state|nonce');
  assert.notEqual(one,two);assert.equal(Buffer.from(one.split('.')[0],'base64url').length,12);
  assert.equal(await unseal(one,secret,'origin|state|nonce'),'verifier €');
  await assert.rejects(unseal(one,secret,'other|state|nonce'));
  await assert.rejects(unseal(one,await key(Buffer.alloc(32,8).toString('base64url'),'AES-GCM'),'origin|state|nonce'));
  const [iv,data]=one.split('.');const changed=Buffer.from(data,'base64url');changed[0]^=1;
  for(const input of [one+'.extra',`${Buffer.alloc(11).toString('base64url')}.${data}`,`${iv}.${changed.toString('base64url')}`,''])await assert.rejects(unseal(input,secret,'origin|state|nonce'));
  for(const length of [0,16,31,33])await assert.rejects(key(Buffer.alloc(length).toString('base64url'),'AES-GCM'));
  const hmac=await key(encoded,'HMAC');assert.equal(hmac.extractable,false);assert.deepEqual(hmac.usages,['sign','verify']);
  assert.equal(await keyedHash('edge-ip',hmac),createHmac('sha256',bytes).update('edge-ip').digest('base64url'));
});
test('user IDs preserve millisecond timestamp and 80 random bits in canonical ULID encoding',()=>{
  const now=2000000000;const values=Array.from({length:20},()=>userId(now));assert.equal(new Set(values).size,20);
  for(const id of values){assert.match(id,/^usr_[0-9A-HJKMNP-TV-Z]{26}$/);let n=0n;
    for(const character of id.slice(4))n=(n<<5n)|BigInt('0123456789ABCDEFGHJKMNPQRSTVWXYZ'.indexOf(character));
    assert.equal(n>>80n,BigInt(now)*1000n);
  }
});
test('device labels retain only coarse browser, platform and trusted country categories',()=>{
  const cases=[['Edg/123 Chrome/123 Windows','Edge on Windows'],['Chrome/1 Android','Chrome on Android'],['Safari/1 iPhone','Safari on iOS'],['Safari/1 iPad','Safari on iOS'],['Firefox/1 Linux','Firefox on Linux'],['Safari/1 Macintosh','Safari on macOS'],['Chrome/1 Mac OS','Chrome on macOS'],['private-marker','Other browser on unknown OS']];
  for(const [ua,device] of cases)assert.deepEqual(coarseClient(new Request('https://accounts.test/',{headers:{'User-Agent':ua,'CF-IPCountry':'US'}})),{device,country:'US'});
  for(const country of ['','XX','us','USA','1A','A1'])assert.equal(coarseClient(new Request('https://accounts.test/',{headers:{'CF-IPCountry':country}})).country,null);
  assert.deepEqual(coarseClient(new Request('https://accounts.test/')),{device:'Other browser on unknown OS',country:null});
});
