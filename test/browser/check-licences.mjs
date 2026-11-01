import { readFileSync } from 'node:fs';
import { checkPackage } from '../../tools/licence/policy.ts';
const packages = JSON.parse(readFileSync(0, 'utf8'));
const expected = { 'python:playwright':'1.55.0', 'python:pyee':'13.0.1', 'python:greenlet':'3.2.5', 'python:typing_extensions':'4.16.0' };
if (packages.length !== Object.keys(expected).length || new Set(packages.map(p => p.name)).size !== packages.length) throw new Error('Unexpected browser dependency set');
for (const pkg of packages) {
  if (pkg.version !== expected[pkg.name] || pkg.scope !== 'dev') throw new Error('Unexpected browser dependency version or scope');
  const failure = checkPackage(pkg);
  if (failure) throw new Error(`${pkg.name}: ${failure.reason}`);
}
console.log('Browser licence gate: 4 pinned dev-only packages allowed');
