import { readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import type { PnpmLicenceReport } from './policy.ts';

/** A textual empty pnpm report is valid only for our genuinely empty runtime dependency graph. */
export function noRuntimeDependencies(root: string, workspaceListJson: string): boolean {
  // pnpm resolves its own workspace globs, including exclusions and future folders.
  const entries: unknown = JSON.parse(workspaceListJson);
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('missing pnpm workspace inventory');
  const directories = new Set([root]);
  for (const entry of entries) {
    if (typeof entry !== 'object' || entry === null || typeof entry.path !== 'string' || !isAbsolute(entry.path)) {
      throw new Error('invalid pnpm workspace path');
    }
    directories.add(entry.path);
  }
  return [...directories].every((directory) => {
    const value = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
    return ['dependencies', 'optionalDependencies', 'peerDependencies'].every((field) => Object.keys(value[field] ?? {}).length === 0);
  });
}

export function parsePnpmReport(text: string, emptyProductionAllowed: boolean): PnpmLicenceReport {
  if (emptyProductionAllowed && text.trim() === 'No licenses in packages found') return {};
  return JSON.parse(text) as PnpmLicenceReport;
}
