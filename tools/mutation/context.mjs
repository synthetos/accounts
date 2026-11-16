import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The command runner cannot report tests. Any test/helper/config/dependency change
// invalidates ALL results; Stryker itself diffs the mutable source files.
export function contextFiles(files) {
  return [...new Set(files)].filter(file => !/^(packages\/(auth-core|idp)|workers\/accounts)\/src\/.*(?<!\.d)\.ts$/.test(file)).sort();
}
export function contextHash(cwd) {
  const files = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', 'packages', 'workers', 'tools/mutation', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'tsconfig.json', 'stryker.config.json'], { cwd, encoding: 'utf8' }).split('\0').filter(Boolean);
  const hash = createHash('sha256').update(`v1\0${process.version}\0${process.platform}\0${process.arch}\0`);
  for (const file of contextFiles(files)) {
    hash.update(file).update('\0');
    try { hash.update(readFileSync(join(cwd, file))); }
    catch (error) { if (error.code !== 'ENOENT') throw error; hash.update('<deleted>'); }
    hash.update('\0');
  }
  return hash.digest('hex');
}
