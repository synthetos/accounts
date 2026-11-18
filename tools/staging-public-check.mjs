// Staging accounts is public (run OD-40, docs/ops/owner-decisions.md and docs/ops/access.md in synthetos/run; it
// superseded D31). As run's deploy does (run tools/gates/src/smoke): the Cloudflare API must list NO self-hosted
// Access application covering the whole staging host, and an anonymous request must reach the Worker rather than
// a `*.cloudflareaccess.com` login. The run sign-in dialog and the accounts allowlist gate staging, as production.
//
//   node tools/staging-public-check.mjs --pre-deploy    before anything is migrated or deployed: refuses while an
//                                                      application still covers the host (named, so the owner can
//                                                      delete it in Zero Trust); a host that does not resolve yet
//                                                      passes the probe only after the API check passed
//   node tools/staging-public-check.mjs --post-deploy   after the deploy; waits up to 6 minutes while the new custom
//                                                      domain is unreachable, then "unreachable" fails
//
// Needs CLOUDFLARE_API_TOKEN (with Access: Apps and Policies Read) and CLOUDFLARE_ACCOUNT_ID in the step's env.
// Exit 0 pass, 1 a finding, 2 bad usage. Dependency-free (node: only).

export const STAGING_HOST = 'staging.accounts.synthetos.com';
const TIMEOUT_MS = 15_000;

/** True when an Access domain entry covers the whole of `host` (no path, `/` or `/*`, or a `*.` wildcard over it). */
export function coversHost(entry, host) {
  if (typeof entry !== 'string') return false;
  const [name, ...rest] = entry.trim().toLowerCase().split('/');
  const path = rest.join('/');
  if (!(path === '' || path === '*')) return false;
  if (name === host) return true;
  return name !== undefined && name.startsWith('*.') && host.endsWith(name.slice(1)) && host.length > name.length - 1;
}

function domainsOf(app) {
  const out = [app.domain];
  if (Array.isArray(app.self_hosted_domains)) out.push(...app.self_hosted_domains);
  if (Array.isArray(app.destinations)) out.push(...app.destinations.map((d) => (typeof d === 'object' && d !== null ? d.uri : undefined)));
  return out;
}

/** The findings from the Access application list for `host`: one per self-hosted application that still covers it. */
export function checkNoAccessApplications(host, apps) {
  if (!Array.isArray(apps)) return ['the Cloudflare Access application list could not be read'];
  const covering = apps.filter((a) => typeof a === 'object' && a !== null && a.type === 'self_hosted' && domainsOf(a).some((d) => coversHost(d, host)));
  return covering.map((app) => {
    const label = typeof app.name === 'string' ? app.name : String(app.id ?? '?');
    return `the Cloudflare Access application '${label}' still covers ${host}: staging accounts is public since OD-40; delete it in Zero Trust → Access → Applications, then re-run the deploy`;
  });
}

/** The hostname a redirect points at, lower-cased; '' when there is none or it does not parse. */
function redirectHost(outcome, url) {
  if (![301, 302, 303, 307, 308].includes(outcome.status) || outcome.location === null) return '';
  try {
    return new URL(outcome.location, url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** The findings from an anonymous request's outcome: it must reach the Worker (any answer below 500 that is not an Access login). */
export function checkPublicGate(url, outcome, allowUnreachable) {
  if (outcome === 'unreachable') return allowUnreachable ? [] : [`${url} is unreachable`];
  if (redirectHost(outcome, url).endsWith('.cloudflareaccess.com')) {
    return [`${url} sent an anonymous request to ${outcome.location}: staging accounts is still behind Cloudflare Access (OD-40 removed it; delete the application in Zero Trust → Access → Applications)`];
  }
  if (outcome.status >= 500) return [`${url} answered ${outcome.status} to an anonymous request`];
  return [];
}

async function cloudflare(fetchFn, token, path) {
  const res = await fetchFn(`https://api.cloudflare.com/client/v4${path}`, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const body = await res.json().catch(() => null);
  return { ok: res.ok && body?.success === true, status: res.status, body };
}

/** The API check, with `fetchFn` injected (tests) or the global fetch (CI). */
export async function accessApps(env, fetchFn = fetch) {
  const token = env.CLOUDFLARE_API_TOKEN ?? '';
  const account = env.CLOUDFLARE_ACCOUNT_ID ?? '';
  const missing = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'].filter((k) => (env[k] ?? '') === '');
  if (missing.length > 0) return missing.map((k) => `${k} is not set for this step: nothing was checked, so this fails`);
  const base = `/accounts/${encodeURIComponent(account)}/access/apps`;
  const apps = [];
  for (let page = 1; page <= 20; page += 1) {
    const r = await cloudflare(fetchFn, token, `${base}?per_page=100&page=${page}`);
    if (!r.ok || !Array.isArray(r.body?.result)) return [`Cloudflare API ${r.status}: could not list Access applications`];
    apps.push(...r.body.result);
    const pages = r.body.result_info?.total_pages;
    if (typeof pages !== 'number' || page >= pages) break;
  }
  return checkNoAccessApplications(STAGING_HOST, apps);
}

export async function probe(url, fetchFn = fetch) {
  try {
    const res = await fetchFn(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
    await res.body?.cancel();
    return { status: res.status, location: res.headers.get('location') };
  } catch {
    return 'unreachable';
  }
}

/** Every finding for `mode` ('pre' or 'post'). */
export async function publicFindings(mode, env, fetchFn = fetch) {
  const api = await accessApps(env, fetchFn);
  const findings = [...api];
  const paths = mode === 'pre' ? ['/'] : ['/', '/login'];
  for (const path of paths) {
    const url = `https://${STAGING_HOST}${path}`;
    findings.push(...checkPublicGate(url, await probe(url, fetchFn), mode === 'pre' && api.length === 0));
  }
  return findings;
}

/** True when every finding is only an unreachable host (a new custom domain's DNS and certificate are still coming up). */
export function onlyUnreachable(findings) {
  return findings.length > 0 && findings.every((f) => f.endsWith(' is unreachable'));
}

/**
 * Post-deploy findings, waiting while the freshly attached custom domain is still unreachable. Any other finding
 * (an Access login, a 5xx, an API finding) returns at once.
 */
export async function postDeployFindings(env, fetchFn = fetch, { attempts = 24, delayMs = 15_000, wait = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let findings = [];
  for (let i = 1; i <= attempts; i += 1) {
    findings = await publicFindings('post', env, fetchFn);
    if (!onlyUnreachable(findings)) return findings;
    if (i < attempts) await wait(delayMs);
  }
  return findings;
}

async function main(argv) {
  if (argv.length !== 1 || (argv[0] !== '--pre-deploy' && argv[0] !== '--post-deploy')) {
    process.stderr.write('usage: node tools/staging-public-check.mjs --pre-deploy|--post-deploy\n');
    return 2;
  }
  const findings = argv[0] === '--pre-deploy' ? await publicFindings('pre', process.env) : await postDeployFindings(process.env);
  if (findings.length > 0) {
    process.stderr.write(`staging public check (${STAGING_HOST}): FAILED\n`);
    for (const f of findings) process.stderr.write(`  ${f}\n`);
    return 1;
  }
  process.stdout.write(`staging public check (${STAGING_HOST}): public, no Cloudflare Access in front\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = await main(process.argv.slice(2));
