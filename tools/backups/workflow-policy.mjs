// Owner backup decision, 2026-11-13: exact protected main-branch backup and manual restore jobs.
import { createHash } from 'node:crypto';
const reviewed = {
  "database-backups.yml": "88e0c0dca884b97b4a56c82e488d03415292cae60b2b65e5fa719876e3a1ee1f",
  "database-restore.yml": "97eba365e36b4bd5919291433e2205d3e96a77d0265d78f1045d8dd8183b03ac"
};
export function reviewedBackupWorkflow(name, source) {
  return createHash('sha256').update(source).digest('hex') === reviewed[name];
}
