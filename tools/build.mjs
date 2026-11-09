import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

const output = resolve(process.argv[2] ?? 'dist');
const compiler = resolve(process.argv[3] ?? 'node_modules/typescript/bin/tsc');
// Only delete this repository's designated output, never an arbitrary argument.
if (output !== resolve('dist')) throw new Error('Build output must be ./dist');
rmSync(output, { recursive: true, force: true });
const result = spawnSync(process.execPath, [compiler, '-p', 'tsconfig.build.json'], { stdio: 'inherit' });
if (result.status !== 0) process.exit(result.status ?? 1);
cpSync('workers/accounts/wrangler.json', `${output}/wrangler.json`);
if (existsSync('migrations')) cpSync('migrations', `${output}/migrations`, { recursive: true });
// A1-07: the reviewed per-environment relying-party registrations, applied by the deploy jobs.
if (existsSync('clients')) cpSync('clients', `${output}/clients`, { recursive: true });
mkdirSync(output, { recursive: true });
