import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  AuthError, randomToken, hashToken, createPkce, pkceChallenge,
  hostCookie, clearHostCookie, readHostCookie,
  assertApiMutation, assertFormMutation, createFormToken, signIdToken, verifyIdToken,
} from '../src/index.ts';
import { base64url, decodeBase64url, decodeUtf8 } from '../src/encoding.ts';

const authError = (code) => (error) => error instanceof AuthError && error.code === code && error.message === code;
const origin = 'https://run.synthetos.com';
const token = Buffer.alloc(32, 0xa5).toString('base64url');
const request = (headers = {}, method = 'POST') => new Request(`${origin}/api/item`, {
  method, headers: { Origin: origin, 'Sec-Fetch-Site': 'same-origin',
    'X-Synthetos-Request': '1', 'Content-Type': 'application/json', ...headers },
});

test('tokens contain 256 random bits and match independent SHA-256 vectors', async () => {
  const values = Array.from({ length: 64 }, randomToken);
  assert.equal(new Set(values).size, 64);
  for (const value of values) {
    assert.match(value, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(Buffer.from(value, 'base64url').length, 32);
    assert.equal(await hashToken(value), createHash('sha256').update(value).digest('hex'));
  }
  assert.equal(await hashToken('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for (const value of ['', 'a'.repeat(4097)]) await assert.rejects(hashToken(value), authError('invalid_input'));
  assert.equal((await hashToken('a'.repeat(4096))).length, 64);
});

test('PKCE matches RFC 7636 appendix B, uses S256 and accepts verifier boundaries', async () => {
  assert.equal(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
    'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  const pair = await createPkce();
  assert.equal(pair.method, 'S256');
  assert.equal(pair.challenge, createHash('sha256').update(pair.verifier).digest('base64url'));
  for (const value of ['a'.repeat(43), 'b'.repeat(128), '.'.repeat(43), '~'.repeat(43)]) {
    assert.equal((await pkceChallenge(value)).length, 43);
  }
  for (const value of ['a'.repeat(42), 'a'.repeat(129), ' '.repeat(43), 'é'.repeat(43), 'a'.repeat(43) + '\n']) {
    await assert.rejects(pkceChallenge(value), authError('invalid_input'));
  }
});

test('canonical base64url round trips arbitrary bytes and rejects ambiguous encodings', () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.equal(base64url(bytes), Buffer.from(bytes).toString('base64url'));
  assert.deepEqual(decodeBase64url(base64url(bytes)), bytes);
  for (const value of ['', 'Zg=', 'Zg==', 'Zh', 'A', 'a b', '+/8', 'é', 'a'.repeat(65537)]) {
    assert.throws(() => decodeBase64url(value), authError('invalid_input'));
  }
});

test('base64url rejects each noncanonical spelling that atob otherwise accepts', () => {
  for (const [label, value, byte] of [
    ['space', 'Z g', 0x66],
    ['newline', 'Zg\n', 0x66],
    ['plus', '+w', 0xfb],
    ['slash', '/w', 0xff],
    ['padding', 'Zg==', 0x66],
    ['nonzero trailing bits', 'Zh', 0x66],
  ]) {
    // Prove rejection depends on canonical validation, not atob throwing first.
    assert.equal(atob(value), String.fromCharCode(byte), label);
    assert.throws(() => decodeBase64url(value), authError('invalid_input'), label);
    assert.deepEqual(decodeBase64url(Buffer.from([byte]).toString('base64url')), new Uint8Array([byte]));
  }
});

test('base64url enforces its size cap even on valid input, and UTF-8 decoding is strict', () => {
  assert.equal(decodeBase64url('AAAA'.repeat(16384)).length, 49152);
  assert.throws(() => decodeBase64url('AAAA'.repeat(16385)), authError('invalid_input'));
  assert.equal(decodeUtf8(new Uint8Array([0x68, 0xc3, 0xa9])), 'hé');
  assert.throws(() => decodeUtf8(new Uint8Array([0xc3, 0x28])), TypeError);
  assert.equal(new AuthError('invalid_input').name, 'AuthError');
});

test('host cookies have fixed attributes and browser-session cookies omit Max-Age', () => {
  assert.equal(hostCookie('__Host-run_sid', token, { sameSite: 'Strict', maxAge: 604800 }),
    `__Host-run_sid=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=604800`);
  assert.equal(hostCookie('__Host-acct_sid', token, { sameSite: 'Lax' }),
    `__Host-acct_sid=${token}; Path=/; Secure; HttpOnly; SameSite=Lax`);
  assert.equal(clearHostCookie('__Host-run_sid', 'Strict'),
    '__Host-run_sid=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0');
  assert.equal(hostCookie('__Host-x', token, { sameSite: 'Lax', maxAge: 0 }).endsWith('Max-Age=0'), true);
});

test('cookie helpers reject injection, weak tokens, invalid names and duplicate cookie values', () => {
  for (const name of ['sid', '__Secure-sid', '__Host-', '__Host-a;b', '__Host-a\r\nX: y', '__Host-a\n']) {
    assert.throws(() => hostCookie(name, token, { sameSite: 'Lax' }), authError('invalid_cookie'));
    assert.throws(() => clearHostCookie(name, 'Lax'), authError('invalid_cookie'));
    assert.throws(() => readHostCookie(null, name), authError('invalid_cookie'));
  }
  for (const value of ['', 'a', Buffer.alloc(31).toString('base64url'), Buffer.alloc(33).toString('base64url'), `${token}; Domain=x`]) {
    assert.throws(() => hostCookie('__Host-x', value, { sameSite: 'Lax' }), authError('invalid_cookie'));
    if (!value.includes(';')) assert.throws(() => readHostCookie(`__Host-x=${value}`, '__Host-x'), authError('invalid_cookie'));
  }
  for (const maxAge of [-1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => hostCookie('__Host-x', token, { sameSite: 'Lax', maxAge }), authError('invalid_cookie'));
  }
  assert.throws(() => hostCookie('__Host-x', token, { sameSite: 'None' }), authError('invalid_cookie'));
  assert.equal(readHostCookie(null, '__Host-x'), undefined);
  assert.equal(readHostCookie('else=value', '__Host-x'), undefined);
  assert.equal(readHostCookie(`__host-x=${token}`, '__Host-x'), undefined);
  assert.equal(readHostCookie(`else=1; __Host-x=${token}; tail=2`, '__Host-x'), token);
  assert.throws(() => readHostCookie(`__Host-x=${token}; __Host-x=${token}`, '__Host-x'), authError('invalid_cookie'));
});

test('API mutation guards allow only exact origin, method, header and requested media type', () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) assertApiMutation(request({}, method), origin);
  assertApiMutation(request({ 'Content-Type': 'APPLICATION/JSON; charset=utf-8' }), origin);
  assertApiMutation(request({ 'Content-Type': 'application/json ; charset=utf-8' }), origin);
  const noFetchMetadata = request(); noFetchMetadata.headers.delete('Sec-Fetch-Site');
  assertApiMutation(noFetchMetadata, origin);
  assertApiMutation(request({ 'Content-Type': 'application/octet-stream' }), origin, true);
  assert.throws(() => assertApiMutation(request({ 'Content-Type': 'text/plain' }), origin, true), authError('csrf_denied'));
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    assert.throws(() => assertApiMutation(request({}, method), origin), authError('csrf_denied'));
  }
  for (const headers of [
    { Origin: 'https://synthetos.com' }, { Origin: 'null' }, { Origin: `${origin}/` },
    { 'Sec-Fetch-Site': 'same-site' }, { 'Sec-Fetch-Site': 'cross-site' },
    { 'X-Synthetos-Request': '0' }, { 'X-Synthetos-Request': '1, 1' },
    { 'Content-Type': 'text/plain' }, { 'Content-Type': 'application/x-www-form-urlencoded' },
    { 'Content-Type': 'application/octet-stream' },
  ]) assert.throws(() => assertApiMutation(request(headers), origin), authError('csrf_denied'));
  for (const header of ['Origin', 'Content-Type', 'X-Synthetos-Request']) {
    const r = request(); r.headers.delete(header);
    assert.throws(() => assertApiMutation(r, origin), authError('csrf_denied'));
  }
  for (const invalidOrigin of ['http://run.synthetos.com', `${origin}/path`]) {
    assert.throws(() => assertApiMutation(request(), invalidOrigin), authError('invalid_input'));
  }
});

const hmacBytes = Buffer.alloc(32, 0x31);
const hmacKey = await crypto.subtle.importKey('raw', hmacBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const formRequest = (headers = {}, method = 'POST') => request({ 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, method);

test('form token matches independent HMAC and binds session, action and expiry', async () => {
  const issued = await createFormToken(hmacKey, 'session-1', '/logout', 1000);
  const mac = createHmac('sha256', hmacBytes).update(JSON.stringify(['synthetos:form:v1', 'session-1', '/logout', 1600])).digest('base64url');
  assert.equal(issued, `1600.${mac}`);
  const r = formRequest(); r.headers.delete('X-Synthetos-Request');
  await assertFormMutation(r, origin, hmacKey, 'session-1', '/logout', issued, 1000);
  await assertFormMutation(r, origin, hmacKey, 'session-1', '/logout', issued, 1599);
  for (const [session, action, now] of [['session-2', '/logout', 1000], ['session-1', '/delete', 1000], ['session-1', '/logout', 1600], ['session-1', '/logout', 999]]) {
    await assert.rejects(assertFormMutation(r, origin, hmacKey, session, action, issued, now), authError('csrf_denied'));
  }
  for (const bad of ['', '1600.a', `${issued}.extra`, `x.${mac}`, `1600\n.${mac}`, `01600.${mac}`, `1600.${Buffer.alloc(32).toString('base64url')}`, `9007199254740992.${mac}`]) {
    await assert.rejects(assertFormMutation(r, origin, hmacKey, 'session-1', '/logout', bad, 1000), authError('csrf_denied'));
  }
  for (const badRequest of [formRequest({ Origin: 'https://evil.synthetos.com' }), formRequest({}, 'PUT'), formRequest({ 'Content-Type': 'application/json' })]) {
    await assert.rejects(assertFormMutation(badRequest, origin, hmacKey, 'session-1', '/logout', issued, 1000), authError('csrf_denied'));
  }
  for (const now of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) await assert.rejects(createFormToken(hmacKey, 's', 'a', now), authError('invalid_input'));
  await assert.rejects(createFormToken(hmacKey, '', 'a', 1000), authError('invalid_input'));
  await assert.rejects(createFormToken(hmacKey, 's', '', 1000), authError('invalid_input'));
  const weakKey = await crypto.subtle.importKey('raw', new Uint8Array(16), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  await assert.rejects(createFormToken(weakKey, 's', 'a', 1000), authError('invalid_input'));
});

test('form tokens reject wrong algorithms and invalid caller clocks, including at validation', async () => {
  const r = formRequest();
  const issued = await createFormToken(hmacKey, 's', 'a', 0);
  await assertFormMutation(r, origin, hmacKey, 's', 'a', issued, 0);
  const maxNow = Number.MAX_SAFE_INTEGER - 600;
  const farFuture = await createFormToken(hmacKey, 's', 'a', maxNow);
  await assertFormMutation(r, origin, hmacKey, 's', 'a', farFuture, maxNow);
  for (const now of [-1, 1.5, NaN, Infinity]) {
    await assert.rejects(assertFormMutation(r, origin, hmacKey, 's', 'a', issued, now), authError('invalid_input'));
  }
  const wrongHash = await crypto.subtle.importKey('raw', hmacBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign', 'verify']);
  const wrongAlgorithm = await crypto.subtle.importKey('raw', hmacBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  for (const key of [wrongHash, wrongAlgorithm]) {
    await assert.rejects(createFormToken(key, 's', 'a', 0), authError('invalid_input'));
    await assert.rejects(assertFormMutation(r, origin, key, 's', 'a', issued, 0), authError('invalid_input'));
  }
});

const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const privateKey = createPrivateKey({ key: await crypto.subtle.exportKey('jwk', keys.privateKey), format: 'jwk' });
const publicKey = createPublicKey(privateKey);
const claims = { iss: 'https://accounts.synthetos.com', sub: 'usr_test', aud: 'run', iat: 1000, exp: 1060, nonce: 'browser-nonce' };
const options = { issuer: claims.iss, audience: 'run', kid: 'key-1', now: 1000, nonce: 'browser-nonce', maxLifetimeSeconds: 60, clockToleranceSeconds: 0 };
function externallySigned(payload, header = { alg: 'ES256', typ: 'JWT', kid: 'key-1' }) {
  const data = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  const signature = sign('sha256', Buffer.from(data), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${data}.${signature.toString('base64url')}`;
}

test('ES256 works against independent node:crypto signing and verification', async () => {
  const signed = await signIdToken(claims, keys.privateKey, 'key-1');
  const [header, payload, signature] = signed.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), { alg: 'ES256', typ: 'JWT', kid: 'key-1' });
  assert.equal(verify('sha256', Buffer.from(`${header}.${payload}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')), true);
  assert.deepEqual(await verifyIdToken(externallySigned(claims), keys.publicKey, options), claims);
  assert.deepEqual(await verifyIdToken(signed, keys.publicKey, options), claims);
  await verifyIdToken(externallySigned({ ...claims, nbf: 1000 }), keys.publicKey, options);
  await verifyIdToken(signed, keys.publicKey, { ...options, now: 1059 });
  await verifyIdToken(externallySigned({ ...claims, nonce: undefined }), keys.publicKey, { ...options, nonce: undefined });
});

test('signing refuses invalid claims before minting any token', async () => {
  for (const invalid of [null, [], true, 'claims', 12, Object.assign([], claims),
    { ...claims, iss: '' }, { ...claims, aud: '' }, { ...claims, aud: ['run'] }, { ...claims, aud: ['run', 'forum'] }, { ...claims, sub: 12 },
    { ...claims, iat: -1 }, { ...claims, exp: 999 }, { ...claims, exp: claims.iat },
    { ...claims, exp: '1060' }, { ...claims, iat: 1.5 },
    { ...claims, nbf: -1 }, { ...claims, nbf: '1000' },
    { ...claims, nonce: '' }, { ...claims, nonce: 1 }, { ...claims, nonce: ['x'] }]) {
    await assert.rejects(signIdToken(invalid, keys.privateKey, 'key-1'), authError('invalid_token'));
  }
  const zero = { ...claims, iat: 0, exp: 60, nbf: 0 };
  const signed = await signIdToken(zero, keys.privateKey, 'key-1');
  assert.deepEqual(await verifyIdToken(signed, keys.publicKey, { ...options, now: 0 }), zero);
  const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign', 'verify']);
  const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  for (const key of [p384.privateKey, ecdh.privateKey]) {
    await assert.rejects(signIdToken(claims, key, 'key-1'), authError('invalid_token'));
  }
});

test('JWT clock tolerance permits bounded issuer skew without extending expiry or lifetime', async () => {
  for (const tolerance of [0, 30, 60]) {
    const tolerantOptions = { ...options, clockToleranceSeconds: tolerance };
    for (const field of ['iat', 'nbf']) {
      for (const offset of [-1, 0, ...(tolerance ? [1, tolerance] : [])]) {
        const payload = { ...claims, exp: 1120, [field]: options.now + offset };
        await verifyIdToken(externallySigned(payload), keys.publicKey,
          { ...tolerantOptions, maxLifetimeSeconds: 121 });
      }
      await assert.rejects(verifyIdToken(externallySigned({ ...claims, exp: 1120, [field]: options.now + tolerance + 1 }),
        keys.publicKey, { ...tolerantOptions, maxLifetimeSeconds: 121 }), authError('invalid_token'));
    }
    for (const payload of [{ ...claims, iat: 999, exp: 1000 }, { ...claims, exp: 1061 }]) {
      await assert.rejects(verifyIdToken(externallySigned(payload), keys.publicKey, tolerantOptions), authError('invalid_token'));
    }
  }
  for (const clockToleranceSeconds of [undefined, -1, 0.5, 61, NaN, Infinity, '30']) {
    await assert.rejects(verifyIdToken(externallySigned(claims), keys.publicKey,
      { ...options, clockToleranceSeconds }), authError('invalid_input'));
  }
});

test('verification validates nonce shape even when nonce matching was not requested', async () => {
  for (const nonce of ['', 12, ['x']]) {
    await assert.rejects(verifyIdToken(externallySigned({ ...claims, nonce }), keys.publicKey,
      { ...options, nonce: undefined }), authError('invalid_token'));
  }
});

test('JWT size limit rejects authentic oversized tokens, not only malformed input', async () => {
  const header = { alg: 'ES256', typ: 'JWT', kid: 'key-12' };
  let boundary;
  for (let n = 12000; n < 12300; n++) {
    const candidate = externallySigned({ ...claims, padding: 'x'.repeat(n) }, header);
    if (candidate.length === 16384) { boundary = candidate; break; }
  }
  assert.ok(boundary, 'fixture must exercise the exact allowed boundary');
  await verifyIdToken(boundary, keys.publicKey, { ...options, kid: 'key-12' });
  const oversized = externallySigned({ ...claims, padding: 'x'.repeat(13000) });
  await assert.rejects(verifyIdToken(oversized, keys.publicKey, options), authError('invalid_token'));
});

for (const [label, patch] of Object.entries({
  issuer: { iss: 'https://evil.test' }, audience: { aud: 'forum' }, multiAudience: { aud: ['run', 'forum'] },
  emptySubject: { sub: '' }, numericSubject: { sub: 1 }, nonce: { nonce: 'other' }, missingNonce: { nonce: undefined },
  expired: { exp: 1000 }, future: { iat: 1001 }, longLifetime: { exp: 1061 }, notBefore: { nbf: 1001 },
  negativeNbf: { nbf: -1 }, floatTime: { iat: 999.5 }, negativeTime: { iat: -1 }, stringTime: { exp: '1060' },
  noExpiry: { exp: undefined }, emptyNonce: { nonce: '' },
})) test(`JWT refuses independently signed invalid claims: ${label}`, async () => {
  await assert.rejects(verifyIdToken(externallySigned({ ...claims, ...patch }), keys.publicKey, options), authError('invalid_token'));
});

test('JWT rejects algorithm confusion, alternate type, unknown key, remote-key headers and malformed tokens', async () => {
  for (const header of [null, [], { alg: 'none', typ: 'JWT', kid: 'key-1' },
    { alg: 'HS256', typ: 'JWT', kid: 'key-1' }, { alg: 'ES256', typ: 'at+jwt', kid: 'key-1' },
    { alg: 'ES256', typ: 'JWT', kid: 'other' }, { alg: 'ES256', typ: 'JWT', kid: 'key-1', crit: [] },
    { alg: 'ES256', typ: 'JWT', kid: 'key-1', jku: 'https://evil.test/keys' }]) {
    await assert.rejects(verifyIdToken(externallySigned(claims, header), keys.publicKey, options), authError('invalid_token'));
  }
  for (const payload of [null, [], {}, 'claims']) {
    await assert.rejects(verifyIdToken(externallySigned(payload), keys.publicKey, options), authError('invalid_token'));
  }
  const good = externallySigned(claims);
  for (const bad of ['', 'a.b', `${good}.extra`, 'not-json.bad.sig', 'a'.repeat(16385), good.replace(/.$/, '!'),
    `${good.split('.').slice(0, 2).join('.')}.${Buffer.alloc(64).toString('base64url')}`]) {
    await assert.rejects(verifyIdToken(bad, keys.publicKey, options), authError('invalid_token'));
  }
  const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  await assert.rejects(verifyIdToken(good, other.publicKey, options), authError('invalid_token'));
  await assert.rejects(verifyIdToken(good, keys.privateKey, options), authError('invalid_token'));
  await assert.rejects(verifyIdToken(good, keys.publicKey, { ...options, now: 1060 }), authError('invalid_token'));
  for (const patch of [{ now: -1 }, { now: 1.1 }, { maxLifetimeSeconds: 0 }, { kid: '' }, { audience: '' }, { issuer: '' }]) {
    await assert.rejects(verifyIdToken(good, keys.publicKey, { ...options, ...patch }), authError('invalid_input'));
  }
  await assert.rejects(signIdToken(claims, keys.publicKey, 'key-1'), authError('invalid_token'));
  await assert.rejects(signIdToken(claims, keys.privateKey, ''), authError('invalid_input'));
});
