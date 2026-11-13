// CI-only D1 provisioning. Never migrates or deploys; only the public database id is printed.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export async function provisionDatabase(account, token, fetcher = fetch) {
  if (!/^[0-9a-f]{32}$/.test(account)) throw new Error('CLOUDFLARE_ACCOUNT_ID is invalid');
  if (!token) throw new Error('CLOUDFLARE_D1_API_TOKEN needs D1: Edit');
  const base = `https://api.cloudflare.com/client/v4/accounts/${account}/d1/database`;
  async function api(suffix, method = 'GET', body) {
    const response = await fetcher(base + suffix, { method, redirect: 'error', signal: AbortSignal.timeout(15000), headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (response.status === 401 || response.status === 403) throw new Error('CLOUDFLARE_D1_API_TOKEN needs D1: Edit');
    if (!response.ok) throw new Error(`D1 provisioning failed (${response.status})`);
    const answer = await response.json();
    if (answer?.success !== true) throw new Error('D1 provisioning refused');
    return answer;
  }
  let id;
  for (let page = 1; ; page++) {
    const answer = await api(`?per_page=100&page=${page}`);
    if (!Array.isArray(answer.result)) throw new Error('Invalid D1 list');
    const matches = answer.result.filter(row => row.name === 'identity');
    if (matches.length > 1 || (matches.length > 0 && id !== undefined)) throw new Error('Ambiguous D1 database name');
    if (matches.length === 1) {
      if (typeof matches[0].uuid !== 'string' || !UUID.test(matches[0].uuid)) throw new Error('Invalid D1 database id');
      id = matches[0].uuid;
    }
    const pages = answer.result_info?.total_pages ?? 1;
    if (!Number.isInteger(pages) || pages < 1 || pages > 10000) throw new Error('Invalid D1 pagination');
    if (page >= pages) break;
  }
  if (id === undefined) id = (await api('', 'POST', { name: 'identity' })).result?.uuid;
  if (typeof id !== 'string' || !UUID.test(id)) throw new Error('Invalid D1 database id');
  return id;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.stdout.write(`identity database id: ${await provisionDatabase(process.env.CLOUDFLARE_ACCOUNT_ID ?? '', process.env.CLOUDFLARE_D1_API_TOKEN ?? '')}\nSubmit this id in a reviewed PR; nothing has been deployed.\n`); }
  catch { process.stderr.write('Identity provisioning failed. Check CLOUDFLARE_D1_API_TOKEN (D1: Edit) and the account.\n'); process.exitCode = 1; }
}
