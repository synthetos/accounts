// Staging must be behind Cloudflare Access (D31, run docs/ops/access.md), checked positively, as run's deploy does
// (run tools/gates/src/smoke): the Cloudflare API must show a self-hosted Access application covering the whole
// staging host with no Bypass policy and no policy that includes Everyone; and an anonymous request must be sent
// to the Access login.
//
//   node tools/access-check.mjs --pre-deploy    before anything is migrated or deployed (a host that does not
//                                              resolve yet passes the probe only after the API check passed)
//   node tools/access-check.mjs --post-deploy   after the deploy; waits up to 6 minutes while the new custom domain
//                                              is unreachable, then "unreachable" fails
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

/** The findings from the Access application list for `host`; `policiesOf(app)` returns an app's policies. */
export function checkAccessApplications(host, apps, policiesOf) {
  if (!Array.isArray(apps)) return ['the Cloudflare Access application list could not be read'];
  const covering = apps.filter((a) => typeof a === 'object' && a !== null && a.type === 'self_hosted' && domainsOf(a).some((d) => coversHost(d, host)));
  if (covering.length === 0) return [`no Cloudflare Access application covers the whole of ${host}: staging accounts would be public`];
  const findings = [];
  for (const app of covering) {
    const policies = policiesOf(app);
    if (!Array.isArray(policies)) {
      findings.push(`the policies of the Access application for ${host} could not be read`);
      continue;
    }
    for (const p of policies) {
      const name = typeof p?.name === 'string' ? p.name : '?';
      if (p?.decision === 'bypass') findings.push(`Access policy '${name}' for ${host} is a Bypass`);
      const include = Array.isArray(p?.include) ? p.include : [];
      if (include.some((r) => typeof r === 'object' && r !== null && 'everyone' in r)) findings.push(`Access policy '${name}' for ${host} includes Everyone`);
    }
  }
  return findings;
}

/** The findings from an anonymous request's outcome: it must be a redirect to the Access login. */
export function checkAccessGate(url, outcome, allowUnreachable) {
  if (outcome === 'unreachable') return allowUnreachable ? [] : [`${url} is unreachable`];
  let host = '';
  try {
    host = new URL(outcome.location ?? '', url).hostname;
  } catch {
    host = '';
  }
  if ([301, 302, 303, 307, 308].includes(outcome.status) && host.endsWith('.cloudflareaccess.com')) return [];
  return [`${url} answered ${outcome.status}${outcome.location === null ? '' : ` -> ${outcome.location}`} to an anonymous request: staging accounts is NOT behind Cloudflare Access`];
}

async function cloudflare(fetchFn, token, path) {
  const res = await fetchFn(`https://api.cloudflare.com/client/v4${path}`, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const body = await res.json().catch(() => null);
  return { ok: res.ok && body?.success === true, status: res.status, body };
}

/** The positive API check, with `fetchFn` injected (tests) or the global fetch (CI). */
export async function accessApi(env, fetchFn = fetch) {
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
  const policies = new Map();
  for (const app of apps) {
    if (Array.isArray(app?.policies) || typeof app?.id !== 'string') continue;
    const r = await cloudflare(fetchFn, token, `${base}/${encodeURIComponent(app.id)}/policies?per_page=100`);
    policies.set(app.id, r.ok ? r.body?.result : undefined);
  }
  return checkAccessApplications(STAGING_HOST, apps, (app) => (Array.isArray(app.policies) ? app.policies : policies.get(app.id)));
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
export async function accessFindings(mode, env, fetchFn = fetch) {
  const api = await accessApi(env, fetchFn);
  const findings = [...api];
  const paths = mode === 'pre' ? ['/'] : ['/', '/login'];
  for (const path of paths) {
    const url = `https://${STAGING_HOST}${path}`;
    findings.push(...checkAccessGate(url, await probe(url, fetchFn), mode === 'pre' && api.length === 0));
  }
  return findings;
}

/** True when every finding is only an unreachable host (a new custom domain's DNS and certificate are still coming up). */
export function onlyUnreachable(findings) {
  return findings.length > 0 && findings.every((f) => f.endsWith(' is unreachable'));
}

/**
 * Post-deploy findings, waiting while the freshly attached custom domain is still unreachable. Any other finding
 * (a public answer, an API finding) returns at once.
 */
export async function postDeployFindings(env, fetchFn = fetch, { attempts = 24, delayMs = 15_000, wait = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let findings = [];
  for (let i = 1; i <= attempts; i += 1) {
    findings = await accessFindings('post', env, fetchFn);
    if (!onlyUnreachable(findings)) return findings;
    if (i < attempts) await wait(delayMs);
  }
  return findings;
}

async function main(argv) {
  if (argv.length !== 1 || (argv[0] !== '--pre-deploy' && argv[0] !== '--post-deploy')) {
    process.stderr.write('usage: node tools/access-check.mjs --pre-deploy|--post-deploy\n');
    return 2;
  }
  const findings = argv[0] === '--pre-deploy' ? await accessFindings('pre', process.env) : await postDeployFindings(process.env);
  if (findings.length > 0) {
    process.stderr.write(`access check (${STAGING_HOST}): FAILED\n`);
    for (const f of findings) process.stderr.write(`  ${f}\n`);
    return 1;
  }
  process.stdout.write(`access check (${STAGING_HOST}): behind Cloudflare Access\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = await main(process.argv.slice(2));
