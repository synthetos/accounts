export function workerConfig(environment: string, source: string | Record<string, string>, scratch: string, account?: string): Record<string, unknown>;
export function checkBackupConfig(config: unknown, environment?: string): boolean;
