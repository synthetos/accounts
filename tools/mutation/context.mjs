import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The command runner cannot report tests. Any test/helper/config/dependency change
// invalidates ALL results; Stryker itself diffs the mutable source files.
export function contextFiles(files) {
  return [...new Set(files)]
    .filter(file => !/(^|\/)(node_modules|dist|reports|\.git)(\/|$)/.test(file))
    .filter(file => !/^(packages\/(auth-core|idp)|workers\/accounts)\/src\/.*(?<!\.d)\.ts$/.test(file)).sort();
}
export function contextHash(cwd) {
  // Inventory the entire repository: tests can read migrations or import helpers
  // outside their own package. Include untracked inputs and tracked deletions too.
  const files = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd, encoding: 'utf8' }).split('\0').filter(Boolean);
  const hash = createHash('sha256').update(`v2\0${process.version}\0${process.platform}\0${process.arch}\0`);
  for (const file of contextFiles(files)) {
    hash.update(file).update('\0');
    try { hash.update(readFileSync(join(cwd, file))); }
    catch (error) { if (error.code !== 'ENOENT') throw error; hash.update('<deleted>'); }
    hash.update('\0');
  }
  return hash.digest('hex');
}
