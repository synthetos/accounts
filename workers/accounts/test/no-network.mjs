// Preload in every native test process, including Stryker's children. A mutant may
// remove an injected provider fetch; it must still never contact a real service.
Object.defineProperty(globalThis, 'fetch', {
  configurable: false,
  writable: false,
  value: async () => { throw new Error('Network is forbidden in unit and mutation tests'); },
});
