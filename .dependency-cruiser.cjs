module.exports = {
  forbidden: [
    {
      name: 'auth-core-is-standalone', severity: 'error',
      from: { path: '^packages/auth-core/src/' },
      to: { pathNot: '^packages/auth-core/src/', reachable: true },
    },
    {
      name: 'no-unresolved-imports', severity: 'error',
      from: {}, to: { couldNotResolve: true },
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
