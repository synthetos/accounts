import { createApp } from './app.ts';

// The default export is HTTP only; RunEntrypoint is the sole named RPC capability.
export default createApp();

export { RunEntrypoint } from './entrypoints.ts';
