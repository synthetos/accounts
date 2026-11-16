import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { contextHash } from './context.mjs';
import { summarize, issueBody } from './summary.mjs';

export function runMutation(mode, { cwd = process.cwd(), execute = spawnSync, env = process.env } = {}) {
  if (!['full', 'quick'].includes(mode)) throw new Error('usage: node tools/mutation/run.mjs full|quick');
  const reportPath = join(cwd, 'reports/release-mutation.json');
  const incremental = join(cwd, 'reports/stryker-incremental.json');
  const context = join(cwd, 'reports/mutation-context.txt');
  const fingerprint = contextHash(cwd);
  const reusable = existsSync(incremental) && existsSync(context) && readFileSync(context, 'utf8') === fingerprint;
  const force = mode === 'full' || !reusable;
  mkdirSync(join(cwd, 'reports'), { recursive: true });
  for (const file of [reportPath, context, join(cwd, 'reports/mutation-issue.md')]) rmSync(file, { force: true });
  if (force) rmSync(incremental, { force: true });
  console.log(force ? 'Mutation: full run (requested, cold cache, or changed test/config inputs).' : 'Mutation: reuse unchanged results; changed mutants are retested.');
  const args = [join(cwd, 'node_modules/@stryker-mutator/core/bin/stryker.js'), 'run', '--incremental', ...(force ? ['--force'] : [])];
  const result = execute(process.execPath, args, { cwd, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (!existsSync(reportPath)) throw new Error('Mutation run did not produce a fresh report');
  const summary = summarize(JSON.parse(readFileSync(reportPath, 'utf8')));
  const runUrl = env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `https://github.com/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : 'reports/release-mutation.json';
  writeFileSync(join(cwd, 'reports/mutation-issue.md'), issueBody(summary, runUrl));
  const complete = result.status === 0 || (result.status === 1 && summary.below);
  if (complete && existsSync(incremental)) writeFileSync(context, fingerprint);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `below=${summary.below}\ncacheable=${complete && existsSync(incremental)}\n`);
  console.log(JSON.stringify(summary.groups, null, 2));
  return summary.below ? 1 : (result.status ?? 1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = runMutation(process.argv[2]); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
