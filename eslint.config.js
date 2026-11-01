import tseslint from 'typescript-eslint';
export default tseslint.config(
  { ignores: ['**/node_modules/**', '**/dist/**', '**/.stryker-tmp/**', '**/.wrangler/**', '**/reports/**'] },
  { linterOptions: { noInlineConfig: true } },
  ...tseslint.configs.recommended,
  { rules: { 'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error' } },
  {
    files: ['packages/auth-core/src/**'],
    rules: {
      'no-restricted-globals': ['error', 'fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'Math'],
      'no-restricted-properties': [
        'error',
        { property: 'fetch', message: 'auth-core is pure WebCrypto; no network APIs.' },
        { property: 'XMLHttpRequest' }, { property: 'WebSocket' }, { property: 'EventSource' },
        { property: 'sendBeacon' }, { property: 'importScripts' }, { object: 'Math', property: 'random' },
      ],
    },
  },
);
