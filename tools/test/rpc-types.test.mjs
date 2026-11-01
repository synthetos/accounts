import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
test('RPC contract accepts code/device context and rejects raw identity or client arguments at compile time', () => {
  execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '--ignoreConfig', '--noEmit', '--strict', '--target', 'ES2022',
    '--module', 'ESNext', '--moduleResolution', 'bundler', '--allowImportingTsExtensions', '--lib', 'ES2022,DOM', '--types',
    './workers/accounts/src/runtime.d.ts', 'test/types/rpc.ts'], { stdio: 'pipe' });
});
