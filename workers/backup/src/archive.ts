import { checksumText, verifyChecksum } from './format.ts';
import type { Bucket } from './types.ts';
const MAX_BYTES = 16 * 1024 * 1024;
export async function hash(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
export async function compress(sql: string): Promise<Uint8Array> {
  if (!sql.trim() || new TextEncoder().encode(sql).length > MAX_BYTES) throw new Error('Invalid dump size');
  return new Uint8Array(await new Response(new Blob([sql]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
}
export async function decompress(bytes: Uint8Array): Promise<string> {
  const reader = new Blob([new Uint8Array(bytes).buffer]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let length = 0, text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > MAX_BYTES) throw new Error('Archive exceeds restore limit');
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { await reader.cancel(); }
}
export async function download(bucket: Bucket, key: string): Promise<string> {
  const [object, checksum] = await Promise.all([bucket.get(key), bucket.get(`${key}.sha256`)]);
  if (!object || !checksum) throw new Error('Archive pair missing');
  const bytes = new Uint8Array(await object.arrayBuffer());
  verifyChecksum(await hash(bytes), await checksum.text(), key.slice(key.lastIndexOf('/') + 1));
  return decompress(bytes);
}
export async function upload(bucket: Bucket, key: string, sql: string): Promise<number> {
  if (await bucket.head(key) || await bucket.head(`${key}.sha256`)) throw new Error('Archive key exists');
  const bytes = await compress(sql), checksum = checksumText(await hash(bytes), key);
  const options = { onlyIf: new Headers({ 'If-None-Match': '*' }) };
  if (await bucket.put(key, bytes, options) === null || await bucket.put(`${key}.sha256`, checksum, options) === null) throw new Error('Archive key collision');
  if (await download(bucket, key) !== sql) throw new Error('Archive read-back mismatch');
  return bytes.length;
}
