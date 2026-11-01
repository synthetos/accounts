module.exports = {
  forbidden: [
    { name: 'runtime-builtin-only-in-entrypoints', severity: 'error',
      from: { pathNot: '^workers/accounts/src/entrypoints\\.ts$' }, to: { path: '^cloudflare:workers$' } },
    {
      name: 'idp-cannot-reach-worker', severity: 'error',
      from: { path: '^packages/idp/src/' },
      to: { path: '^workers/', reachable: true },
    },
    {
      name: 'auth-core-is-standalone', severity: 'error',
      from: { path: '^packages/auth-core/src/' },
      to: { pathNot: '^packages/auth-core/src/', reachable: true },
    },
    {
      name: 'no-unresolved-imports', severity: 'error',
      // workerd provides this exact built-in; all other unresolved imports still fail.
      from: {}, to: { couldNotResolve: true, pathNot: '^cloudflare:workers$' },
    },
    {
      name: 'no-outside-repo', severity: 'error',
      from: {}, to: { path: '^\\.\\./' },
    },
  ],
  options: {
    tsPreCompilationDeps: true,
    tsConfig: { fileName: 'tsconfig.json' },
    doNotFollow: { path: 'node_modules' },
  },
};
