import type { Bucket, Database } from './types.ts';
import { archiveKey } from './format.ts';
import { dumpDatabase } from './dump.ts';
import { download, upload } from './archive.ts';
import { restoreScratch } from './restore.ts';
export interface BackupSource { name: string; database: Database }
export async function backupScheduled(repo: string, environment: string, sources: BackupSource[], scratch: Database, bucket: Bucket, date: Date, log: (record: Record<string, unknown>) => void): Promise<void> {
  for (const source of sources) {
    const started = Date.now();
    const key = archiveKey(repo, source.name, environment, date);
    let stage = 'dump';
    try {
      if (source.database === scratch) throw new Error('Scratch must not be a source');
      const dump = await dumpDatabase(source.database);
      stage = 'upload';
      const bytes = await upload(bucket, key, dump.sql);
      const monthly = date.getUTCDate() === 1;
      if (monthly) {
        stage = 'restore';
        await restoreScratch(scratch, await download(bucket, key), dump.counts);
      }
      log({ database: source.name, key, bytes, rows: dump.counts, elapsedMs: Date.now() - started, consistency: dump.paged ? 'paged-rowid-not-atomic' : 'single-batch', restore: monthly ? 'passed-and-emptied' : 'not-due', status: 'ok' });
    } catch {
      log({ database: source.name, key, elapsedMs: Date.now() - started, stage, status: 'failed' });
      // D1 errors can quote SQL/rows. Never surface the underlying exception in Worker logs.
      throw new Error('Database backup failed; see structured stage summary');
    }
  }
}
