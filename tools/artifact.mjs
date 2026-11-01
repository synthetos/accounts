import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export function manifest(root, prefix = '') {
  const result = {};
  for (const entry of readdirSync(join(root, prefix), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) throw new Error('Artifact symlinks are forbidden');
    if (entry.isDirectory()) Object.assign(result, manifest(root, path));
    else if (entry.isFile()) result[path] = createHash('sha256').update(readFileSync(join(root, path))).digest('hex');
    else throw new Error('Unexpected artifact entry');
  }
  return result;
}

export function compare(left, right) {
  if (JSON.stringify(manifest(left)) !== JSON.stringify(manifest(right))) throw new Error('Builds differ');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , mode, first, second] = process.argv;
  if (mode === 'compare' && first && second) compare(first, second);
  else if (mode === 'manifest' && first) console.log(JSON.stringify(manifest(first), null, 2));
  else throw new Error('Usage: artifact.mjs compare DIR DIR | manifest DIR');
}
