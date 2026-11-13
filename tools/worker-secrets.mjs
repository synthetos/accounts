// Set a Worker's missing secrets through the Cloudflare API, from CI only (D39). Generated keys are made on the runner
// and sent straight to Cloudflare: they are never printed, logged or stored anywhere else. Secrets the Worker already
// has are left alone, so a rerun never ends sessions. Only secret names are ever printed.
//
//   node tools/worker-secrets.mjs <script-name>
//
// Needs CLOUDFLARE_API_TOKEN (Workers Scripts Edit) and CLOUDFLARE_ACCOUNT_ID. Values given from outside (the GitHub
// App client secret) come from the step's env under the secret's own name; GitHub refuses secret names starting
// GITHUB_, so the workflow maps the environment secret APP_CLIENT_SECRET to GITHUB_CLIENT_SECRET. Exit 0 all set, 1 a problem, 2 bad usage.
// Dependency-free (node: only).

import { generateKeyPairSync, randomBytes } from 'node:crypto';

/** A 32-byte random key, base64url without padding (the runbook's `openssl rand 32 | base64 | tr ...`). */
export const randomKey = () => randomBytes(32).toString('base64url');

/** A fresh P-256 private key as a JWK string, for signing ID tokens. */
export const signingJwk = () => JSON.stringify(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }));

/** Staging generates missing keys; production takes every value from its protected environment. */
export const PLANS = {
  // Production values come only from the protected production environment, never staging or a fallback.
  accounts: Object.fromEntries(['GITHUB_CLIENT_SECRET', 'OAUTH_STATE_KEY', 'FORM_KEY', 'RATE_KEY', 'GITHUB_WEBHOOK_SECRET', 'ID_TOKEN_PRIVATE_JWK'].map(name => [name, { fromEnv: true }])),
  run: Object.fromEntries(['RUN_STATE_KEY', 'RUN_RATE_KEY'].map(name => [name, { fromEnv: true }])),
  'accounts-staging': {
    GITHUB_CLIENT_SECRET: { fromEnv: true },
    OAUTH_STATE_KEY: { generate: randomKey },
    FORM_KEY: { generate: randomKey },
    RATE_KEY: { generate: randomKey },
    GITHUB_WEBHOOK_SECRET: { generate: randomKey },
    ID_TOKEN_PRIVATE_JWK: { generate: signingJwk },
  },
  // run's sign-in keys (run workers/run/src/authConfig.ts), each a canonical base64url 32-byte key.
  'run-staging': {
    RUN_STATE_KEY: { generate: randomKey },
    RUN_RATE_KEY: { generate: randomKey },
  },
};

async function api(fetchFn, token, url, init = {}) {
  const res = await fetchFn(url, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, signal: AbortSignal.timeout(15_000) });
  const body = await res.json().catch(() => null);
  return { ok: res.ok && body?.success === true, status: res.status, body };
}

/** Set every missing secret of `script`; returns { set, kept, problems } (names only). */
export async function setMissingSecrets(script, env, fetchFn = fetch) {
  const plan = PLANS[script];
  if (plan === undefined) return { set: [], kept: [], problems: [`no secret plan for ${script}`] };
  const missing = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'].filter((k) => (env[k] ?? '') === '');
  if (missing.length > 0) return { set: [], kept: [], problems: missing.map((k) => `${k} is not set for this step`) };
  const token = env.CLOUDFLARE_API_TOKEN;
  const base = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CLOUDFLARE_ACCOUNT_ID)}/workers/scripts/${encodeURIComponent(script)}/secrets`;
  const listed = await api(fetchFn, token, base);
  if (!listed.ok || !Array.isArray(listed.body?.result)) return { set: [], kept: [], problems: [`Cloudflare API ${listed.status}: could not list the secrets of ${script} (is it deployed?)`] };
  const have = new Set(listed.body.result.map((s) => s?.name));
  const set = [];
  const kept = [];
  const problems = [];
  for (const [name, how] of Object.entries(plan)) {
    if (have.has(name)) {
      kept.push(name);
      continue;
    }
    const text = how.fromEnv ? (env[name] ?? '') : how.generate();
    if (text === '') {
      problems.push(`${name} is missing: set it as a GitHub environment secret first (APP_CLIENT_SECRET for GITHUB_CLIENT_SECRET)`);
      continue;
    }
    const put = await api(fetchFn, token, base, { method: 'PUT', body: JSON.stringify({ name, text, type: 'secret_text' }) });
    if (put.ok) set.push(name);
    else problems.push(`Cloudflare API ${put.status}: could not set ${name}`);
  }
  return { set, kept, problems };
}

async function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write('usage: node tools/worker-secrets.mjs <script-name>\n');
    return 2;
  }
  const { set, kept, problems } = await setMissingSecrets(argv[0], process.env);
  if (set.length > 0) process.stdout.write(`set: ${set.join(', ')}\n`);
  if (kept.length > 0) process.stdout.write(`already there, left alone: ${kept.join(', ')}\n`);
  for (const p of problems) process.stderr.write(`problem: ${p}\n`);
  return problems.length > 0 ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = await main(process.argv.slice(2));
