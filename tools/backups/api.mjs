// CI-only Cloudflare calls. Never include response bodies (which may contain rows or credentials) in errors.
export const BUCKET = 'synthetos-db-backups';
export function cloudflare(account, token, permission, fetcher = fetch) {
  if (!/^[0-9a-f]{32}$/.test(account)) throw new Error('Invalid CLOUDFLARE_ACCOUNT_ID');
  if (!token) throw new Error(`Missing credential: ${permission}`);
  return async (path, method = 'GET', body, allowMissing = false) => {
    const response = await fetcher(`https://api.cloudflare.com/client/v4/accounts/${account}/${path}`, {
      method, redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (allowMissing && response.status === 404) return null;
    if (response.status === 401 || response.status === 403) throw new Error(`Credential requires ${permission}`);
    if (!response.ok) throw new Error(`Cloudflare request failed (${response.status})`);
    const answer = await response.json();
    if (answer?.success !== true) throw new Error('Cloudflare request refused');
    return answer;
  };
}
export async function databaseId(api, name, create = false, allowAbsent = false) {
  if (!/^[a-z][a-z0-9-]+$/.test(name)) throw new Error('Invalid database name');
  let id;
  for (let page = 1; page <= 10000; page++) {
    const answer = await api(`d1/database?per_page=100&page=${page}`);
    if (!Array.isArray(answer.result)) throw new Error('Invalid D1 list');
    for (const row of answer.result.filter(row => row.name === name)) {
      if (id !== undefined) throw new Error('Ambiguous database name');
      id = row.uuid;
    }
    const pages = answer.result_info?.total_pages ?? 1;
    if (!Number.isInteger(pages) || pages < 1 || pages > 10000) throw new Error('Invalid D1 pagination');
    if (page >= pages) break;
  }
  if (id === undefined && !create && allowAbsent) return null;
  if (id === undefined && create) id = (await api('d1/database', 'POST', { name })).result?.uuid;
  if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id)) throw new Error(`Database ${name} is missing or invalid`);
  return id;
}
export async function assertPrivate(api) {
  const base = `r2/buckets/${BUCKET}/domains`;
  const managed = (await api(`${base}/managed`)).result;
  const custom = (await api(`${base}/custom`)).result;
  if (managed?.enabled !== false || !Array.isArray(custom?.domains) || custom.domains.length !== 0) throw new Error('Backup bucket must be private, with no custom domains');
}
