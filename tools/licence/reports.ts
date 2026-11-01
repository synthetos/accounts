import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { PnpmLicenceReport } from './policy.ts';

/** A textual empty pnpm report is valid only for our genuinely empty runtime dependency graph. */
export function noRuntimeDependencies(root: string): boolean {
  const manifests = [join(root, 'package.json')];
  for (const group of ['packages', 'workers']) {
    const dir = join(root, group);
    if (!existsSync(dir)) continue;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name, 'package.json');
      if (entry.isDirectory() && existsSync(path)) manifests.push(path);
    }
  }
  return manifests.every((path) => {
    const value = JSON.parse(readFileSync(path, 'utf8')) as Record<string, Record<string, string> | undefined>;
    return ['dependencies', 'optionalDependencies', 'peerDependencies'].every((field) => Object.keys(value[field] ?? {}).length === 0);
  });
}

export function parsePnpmReport(text: string, emptyProductionAllowed: boolean): PnpmLicenceReport {
  if (emptyProductionAllowed && text.trim() === 'No licenses in packages found') return {};
  return JSON.parse(text) as PnpmLicenceReport;
}
