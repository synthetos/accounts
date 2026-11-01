// Minimal platform surface, not a runtime dependency. Local workerd tests exercise the real class.
declare module 'cloudflare:workers' {
  export class WorkerEntrypoint<Env = unknown> { protected env: Env; }
}
