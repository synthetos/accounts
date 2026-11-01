/**
 * The licence policy for synthetos/accounts (ROADMAP P0-02, RUN_PLAN §6.1,
 * TOOLS_PLAN §3.3).
 *
 * - Production dependencies (anything `pnpm licenses list --prod` reports):
 *   MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or OFL-1.1. No
 *   exceptions.
 * - Dev-only dependencies: the production list plus MPL-2.0, plus the
 *   reviewed per-package exceptions in `exceptions.ts`.
 * - GPL and AGPL family licences (and the source-available SSPL and BUSL)
 *   are never allowed, not even by exception.
 * - Unknown, missing or unparseable licences fail.
 */
import { DEV_LICENCE_EXCEPTIONS, type LicenceException } from './exceptions.ts';
import { isSatisfiedBy, licenceIds } from './spdx.ts';

export const PRODUCTION_LICENCES: ReadonlySet<string> = new Set([
  'MIT',
  'ISC',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'Apache-2.0',
  'OFL-1.1',
]);

export const DEV_ONLY_LICENCES: ReadonlySet<string> = new Set(['MPL-2.0']);

const DEV_LICENCES: ReadonlySet<string> = new Set([...PRODUCTION_LICENCES, ...DEV_ONLY_LICENCES]);

/** Licence identifiers that no exception can ever allow. LGPL is not matched. */
const NEVER_ALLOWED = /^(GPL|AGPL|SSPL|BUSL)(-|$| )/i;

/** True if the identifier is in the GPL/AGPL (or SSPL/BUSL) family. */
export function isNeverAllowed(id: string): boolean {
  return NEVER_ALLOWED.test(id);
}

export type Scope = 'production' | 'dev';

/** One installed package as the gate sees it. */
export interface PackageLicence {
  readonly name: string;
  readonly version: string;
  /** The licence string pnpm reports (an SPDX expression, or something else). */
  readonly licence: string;
  readonly scope: Scope;
}

export interface Violation {
  readonly pkg: PackageLicence;
  readonly reason: string;
}

/** The decision for one package: `undefined` when allowed, otherwise why not. */
export function checkPackage(
  pkg: PackageLicence,
  exceptions: readonly LicenceException[] = DEV_LICENCE_EXCEPTIONS,
): Violation | undefined {
  const ids = licenceIds(pkg.licence);
  if (ids === undefined) {
    return { pkg, reason: `licence "${pkg.licence}" is missing or not a valid SPDX expression` };
  }

  if (pkg.scope === 'production') {
    if (isSatisfiedBy(pkg.licence, PRODUCTION_LICENCES)) return undefined;
    return {
      pkg,
      reason: `production dependency licence "${pkg.licence}" is not one of ${[...PRODUCTION_LICENCES].join(', ')}`,
    };
  }

  if (isSatisfiedBy(pkg.licence, DEV_LICENCES)) return undefined;
  const forbidden = ids.filter(isNeverAllowed);
  const hasOnlyForbiddenRoute = !isSatisfiedBy(
    pkg.licence,
    new Set(ids.filter((id) => !isNeverAllowed(id))),
  );
  if (forbidden.length > 0 && hasOnlyForbiddenRoute) {
    return { pkg, reason: `licence "${pkg.licence}" is GPL/AGPL-family; it is never allowed, even for dev tooling` };
  }
  const exception = exceptions.find((e) => e.name === pkg.name && e.licence === pkg.licence);
  if (exception !== undefined) return undefined;
  return {
    pkg,
    reason:
      `dev dependency licence "${pkg.licence}" is not one of ${[...DEV_LICENCES].join(', ')} ` +
      'and has no reviewed exception in tools/licence/exceptions.ts',
  };
}

/**
 * Checks that an exception list respects the policy itself: dev only (by
 * construction), never GPL/AGPL-family, a parseable licence and a reason.
 * Returns the problems found (empty when the list is valid).
 */
export function validateExceptions(exceptions: readonly LicenceException[]): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const e of exceptions) {
    const ids = licenceIds(e.licence);
    if (ids === undefined) problems.push(`${e.name}: licence "${e.licence}" does not parse`);
    else if (ids.some(isNeverAllowed)) problems.push(`${e.name}: "${e.licence}" can never be excepted`);
    if (e.reason.trim().length < 20) problems.push(`${e.name}: the reason must explain the review`);
    if (seen.has(e.name)) problems.push(`${e.name}: listed twice`);
    seen.add(e.name);
  }
  return problems;
}

/** The shape of `pnpm licenses list --json`: licence → packages. */
export type PnpmLicenceReport = Record<
  string,
  ReadonlyArray<{ readonly name: string; readonly versions: readonly string[]; readonly license?: string }>
>;

function flatten(report: PnpmLicenceReport): Array<{ name: string; version: string; licence: string }> {
  const out: Array<{ name: string; version: string; licence: string }> = [];
  for (const [key, packages] of Object.entries(report)) {
    for (const p of packages) {
      for (const version of p.versions) out.push({ name: p.name, version, licence: p.license ?? key });
    }
  }
  return out;
}

/**
 * Classifies every package in the full report as production (present in the
 * `--prod` report) or dev, and checks each one. Throws if the full report is
 * empty, because an empty report means the gate saw nothing (fail closed).
 */
export function checkReports(
  prodReport: PnpmLicenceReport,
  allReport: PnpmLicenceReport,
  exceptions: readonly LicenceException[] = DEV_LICENCE_EXCEPTIONS,
): { checked: PackageLicence[]; violations: Violation[] } {
  const exceptionProblems = validateExceptions(exceptions);
  if (exceptionProblems.length > 0) {
    throw new Error(`invalid licence exception list:\n  ${exceptionProblems.join('\n  ')}`);
  }
  const all = flatten(allReport);
  if (all.length === 0) throw new Error('pnpm reported no installed packages; run `pnpm install` first');
  const prodKeys = new Set(flatten(prodReport).map((p) => `${p.name}@${p.version}`));
  for (const key of prodKeys) {
    if (!all.some((p) => `${p.name}@${p.version}` === key)) {
      throw new Error(`production package ${key} is missing from the full report; the reports disagree`);
    }
  }
  const checked = all.map<PackageLicence>((p) => ({
    ...p,
    scope: prodKeys.has(`${p.name}@${p.version}`) ? 'production' : 'dev',
  }));
  const violations = checked
    .map((p) => checkPackage(p, exceptions))
    .filter((v): v is Violation => v !== undefined);
  return { checked, violations };
}
