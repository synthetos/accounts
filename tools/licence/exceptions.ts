/**
 * Reviewed, dev-only licence exceptions (ROADMAP P0-02).
 *
 * An exception names one package and the exact licence string pnpm reports
 * for it. It never applies to a production dependency, and GPL/AGPL-family
 * licences can never be excepted (enforced by `policy.ts` and its tests). If
 * a package's licence changes, its exception stops matching and the gate
 * fails until it is reviewed again.
 *
 * Changing this list needs owner review (it is part of the supply-chain
 * policy, RUN_PLAN §6.1, §6.2).
 */
export interface LicenceException {
  readonly name: string;
  readonly licence: string;
  readonly reason: string;
}

/**
 * libvips, LGPL-3.0-or-later, is the native image library of `sharp`. It
 * reaches the tree only through wrangler → miniflare (the local Workers
 * simulator's image binding). It is a dynamically loaded dev-machine binary,
 * never bundled, never deployed and never distributed with run. Each
 * platform installs its own prebuilt package, so every platform CI or a
 * developer may use is listed by name.
 */
const SHARP_LIBVIPS_REASON =
  'Native libvips binary loaded by sharp inside wrangler/miniflare (local Workers simulator). ' +
  'Dev tooling only; never bundled, deployed or distributed.';

const SHARP_LIBVIPS_PLATFORMS = [
  'darwin-arm64',
  'darwin-x64',
  'linux-arm',
  'linux-arm64',
  'linux-x64',
  'linuxmusl-arm64',
  'linuxmusl-x64',
] as const;

export const DEV_LICENCE_EXCEPTIONS: readonly LicenceException[] = [
  {
    name: 'tslib',
    licence: '0BSD',
    reason: 'Microsoft TypeScript helpers used by Stryker and rxjs in mutation tests only. Inspected package LICENSE.txt; never included in the TypeScript-only production build.',
  },
  {
    name: 'caniuse-lite',
    licence: 'CC-BY-4.0',
    reason: 'Browser compatibility data used by Babel/browserslist inside Stryker instrumentation only. Package attribution/licence retained in the test install; no data is copied into the production artifact.',
  },
  ...SHARP_LIBVIPS_PLATFORMS.map((platform) => ({
    name: `@img/sharp-libvips-${platform}`,
    licence: 'LGPL-3.0-or-later',
    reason: SHARP_LIBVIPS_REASON,
  })),
  {
    name: 'minimatch',
    licence: 'BlueOak-1.0.0',
    reason:
      'Permissive, OSI-approved licence (Blue Oak Model License 1.0.0). Glob matcher used by dev tooling ' +
      '(ESLint, Vitest); not in any production bundle.',
  },
  {
    name: '@speed-highlight/core',
    licence: 'CC0-1.0',
    reason:
      'Public-domain dedication. Syntax highlighter in the error pages of wrangler/miniflare (via youch); ' +
      'dev tooling only.',
  },
];
