// Undo a staging deploy whose later checks failed: delete the accounts-staging Worker (and with it its custom domain)
// through the Cloudflare API. `wrangler delete` also lists KV namespaces, which the deploy token may not read.
//
//   node tools/undo-staging.mjs
//
// Needs CLOUDFLARE_API_TOKEN (Workers Scripts Edit) and CLOUDFLARE_ACCOUNT_ID. Exit 0 deleted or already gone, 1 failed.
// Dependency-free (node: only).

export const STAGING_SCRIPT = 'accounts-staging';

/** Delete the staging Worker with `fetchFn` injected (tests) or the global fetch (CI); returns the problems found. */
export async function undoStaging(env, fetchFn = fetch) {
  const missing = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'].filter((k) => (env[k] ?? '') === '');
  if (missing.length > 0) return missing.map((k) => `${k} is not set for this step`);
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CLOUDFLARE_ACCOUNT_ID)}/workers/scripts/${STAGING_SCRIPT}?force=true`;
  const res = await fetchFn(url, { method: 'DELETE', headers: { authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` }, signal: AbortSignal.timeout(15_000) });
  if (res.status === 404) return [];
  const body = await res.json().catch(() => null);
  return res.ok && body?.success === true ? [] : [`Cloudflare API ${res.status}: could not delete ${STAGING_SCRIPT}`];
}

async function main() {
  const problems = await undoStaging(process.env);
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`undo staging: ${p}\n`);
    return 1;
  }
  process.stdout.write(`undo staging: ${STAGING_SCRIPT} deleted\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = await main();
