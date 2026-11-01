/**
 * Licence gate (ROADMAP P0-02). Run with `pnpm licence`.
 *
 *   node tools/licence/cli.ts
 *   node tools/licence/cli.ts --prod-json prod.json --all-json all.json
 *
 * Without arguments it asks pnpm for `licenses list --json --prod` and
 * `licenses list --json`. Exit status: 0 allowed, 1 policy violation,
 * 2 the gate could not run (it never passes when it saw nothing).
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { checkReports, type PnpmLicenceReport } from './policy.ts';

function pnpmJson(args: readonly string[]): PnpmLicenceReport {
  // Under `pnpm run`, npm_execpath is the pnpm entry script that is running
  // us (Corepack included); otherwise fall back to pnpm on PATH.
  const execPath = process.env['npm_execpath'];
  const output =
    execPath !== undefined && /pnpm/i.test(execPath) && /\.(c|m)?js$/.test(execPath)
      ? execFileSync(process.execPath, [execPath, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
      : execFileSync('pnpm', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(output) as PnpmLicenceReport;
}

function readJson(path: string): PnpmLicenceReport {
  return JSON.parse(readFileSync(path, 'utf8')) as PnpmLicenceReport;
}

function argValue(argv: readonly string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  return index === -1 ? undefined : argv[index + 1];
}

function main(argv: readonly string[]): number {
  let prod: PnpmLicenceReport;
  let all: PnpmLicenceReport;
  try {
    const prodPath = argValue(argv, '--prod-json');
    const allPath = argValue(argv, '--all-json');
    if ((prodPath === undefined) !== (allPath === undefined)) {
      throw new Error('pass both --prod-json and --all-json, or neither');
    }
    prod = prodPath === undefined ? pnpmJson(['licenses', 'list', '--json', '--prod']) : readJson(prodPath);
    all = allPath === undefined ? pnpmJson(['licenses', 'list', '--json']) : readJson(allPath);
    const { checked, violations } = checkReports(prod, all);
    if (violations.length > 0) {
      process.stderr.write(`licence gate: ${violations.length} violation(s)\n`);
      for (const v of violations) {
        process.stderr.write(`  ${v.pkg.scope.padEnd(10)} ${v.pkg.name}@${v.pkg.version}: ${v.reason}\n`);
      }
      return 1;
    }
    const prodCount = checked.filter((p) => p.scope === 'production').length;
    process.stdout.write(
      `licence gate: ${checked.length} packages allowed (${prodCount} production, ${checked.length - prodCount} dev)\n`,
    );
    return 0;
  } catch (error) {
    process.stderr.write(`licence gate: could not run: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
