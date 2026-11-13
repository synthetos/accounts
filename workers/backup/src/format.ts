export function archiveKey(repo: string, database: string, environment: string, date: Date): string {
  if (!['accounts', 'run'].includes(repo) || !/^[a-z][a-z0-9-]+$/.test(database) || !['staging', 'production'].includes(environment)) throw new Error('Invalid backup scope');
  const iso = date.toISOString();
  return `${environment === 'staging' ? 'staging/' : ''}${repo}/${database}/${iso.slice(0, 10)}/${database}-${iso.slice(0, 16).replaceAll(':', '')}Z.sql.gz`;
}
export function quoteIdentifier(value: string): string {
  if (typeof value !== 'string' || value.includes('\0')) throw new Error('Invalid table name');
  return `"${value.replaceAll('"', '""')}"`;
}
export function verifyChecksum(hash: string, checksum: string, basename: string): void {
  if (!/^[a-z0-9T.Z-]+\.sql\.gz$/.test(basename)) throw new Error('Invalid archive filename');
  const match = /^([0-9a-f]{64})  ([^\n]+)\n$/.exec(checksum);
  if (!match || match[2] !== basename || hash !== match[1]) throw new Error('Backup checksum mismatch');
}
export function checksumText(hash: string, key: string): string {
  return `${hash}  ${key.slice(key.lastIndexOf('/') + 1)}\n`;
}
