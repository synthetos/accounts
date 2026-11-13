// Accounts owns provisioning. Existing buckets are never deleted; public/domain configuration fails closed.
import { BUCKET, assertPrivate } from './api.mjs';
export const LIFECYCLE = { rules: [
  ...['accounts/', 'run/'].map(prefix => ({ id: `production-${prefix.slice(0, -1)}-30-days`, enabled: true, conditions: { prefix }, deleteObjectsTransition: { condition: { type: 'Age', maxAge: 30 * 86400 } } })),
  { id: 'staging-7-days', enabled: true, conditions: { prefix: 'staging/' }, deleteObjectsTransition: { condition: { type: 'Age', maxAge: 7 * 86400 } } },
] };
const canonical = value => JSON.stringify((value?.rules ?? []).map(rule => ({
  id: rule.id, enabled: rule.enabled, prefix: rule.conditions?.prefix,
  type: rule.deleteObjectsTransition?.condition?.type, maxAge: rule.deleteObjectsTransition?.condition?.maxAge,
})).sort((a, b) => a.id.localeCompare(b.id)));
export async function provisionBucket(api) {
  const base = `r2/buckets/${BUCKET}`;
  if (await api(base, 'GET', undefined, true) === null) await api('r2/buckets', 'POST', { name: BUCKET });
  await assertPrivate(api);
  const current = (await api(`${base}/lifecycle`)).result;
  if (canonical(current) !== canonical(LIFECYCLE)) await api(`${base}/lifecycle`, 'PUT', LIFECYCLE);
  const verified = (await api(`${base}/lifecycle`)).result;
  if (canonical(verified) !== canonical(LIFECYCLE)) throw new Error('Backup lifecycle did not read back');
}
