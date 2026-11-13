import type { Bucket, Database } from './types.ts';
import { backupScheduled } from './scheduled.ts';
import { SOURCES } from './sources.ts';
interface Env { [binding: string]: unknown; SCRATCH: Database; BACKUPS: Bucket; BACKUP_ENV: 'production' | 'staging' }
export default {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(event: { scheduledTime: number }, env: Env): Promise<void> {
    const sources = SOURCES.map(source => ({ name: source.database + (env.BACKUP_ENV === 'staging' ? '-staging' : ''), database: env[source.binding] as Database }));
    await backupScheduled('accounts', env.BACKUP_ENV, sources, env.SCRATCH, env.BACKUPS, new Date(event.scheduledTime), record => console.log(JSON.stringify(record)));
  },
};
