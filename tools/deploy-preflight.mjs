// Deploy preflight for accounts (A1-07). The deploy jobs run it on the verified artifact's configuration
// before any migration, client registration or deploy:
//
//   node tools/deploy-preflight.mjs payload/wrangler.json <staging|production>
//
// It refuses (exit 1) unless the environment being deployed is fully and consistently configured:
// - its custom-domain route is exactly its host, and workers.dev, preview URLs and invocation logs are off;
// - its IDENTITY D1 database has a real id (not the repository placeholder);
// - AUTH_ENABLED is "true", ACCOUNT_ORIGIN is https://<its host>;
// - GITHUB_APP_ID and GITHUB_CLIENT_ID are real values (staging never reuses production's app);
// - GITHUB_ALLOWED_IDS is a non-empty JSON array of canonical numeric GitHub ids (D37 staff beta).
// Secrets are never in the file, so this check cannot see them; the Worker fails closed (503) without them.
// Exit 2: bad usage or an unreadable file. Dependency-free (node: only).
import { readFileSync } from 'node:fs';

export const HOSTS = { production: 'accounts.synthetos.com', staging: 'staging.accounts.synthetos.com' };
export const DATABASE_NAMES = { production: 'identity', staging: 'identity-staging' };
const PRODUCTION_APP_ID = '5562809';
const FORUM_APP_ID = '5559540';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The findings for deploying `env` from `config` (the parsed wrangler.json); empty means go. */
export function preflightFindings(config, env) {
  const findings = [];
  if (!isObject(config)) return ['the configuration is not a JSON object'];
  const scope = env === 'production' ? config : config.env?.staging;
  if (!isObject(scope)) return [`env.${env} is missing`];
  const where = env === 'production' ? '' : 'env.staging.';
  if (scope.workers_dev !== false) findings.push(`${where}workers_dev must be false`);
  if (scope.preview_urls !== false) findings.push(`${where}preview_urls must be false`);
  if (scope.observability?.enabled !== false) findings.push(`${where}observability.enabled must be false`);
  const routes = JSON.stringify(scope.routes);
  if (routes !== JSON.stringify([{ pattern: HOSTS[env], custom_domain: true }])) findings.push(`${where}routes must be exactly the custom domain ${HOSTS[env]}`);
  const db = Array.isArray(scope.d1_databases) && scope.d1_databases.length === 1 ? scope.d1_databases[0] : null;
  if (!isObject(db) || db.binding !== 'IDENTITY' || db.database_name !== DATABASE_NAMES[env] || db.migrations_dir !== 'migrations') {
    findings.push(`${where}d1_databases must be exactly one IDENTITY database named ${DATABASE_NAMES[env]} with migrations_dir "migrations"`);
  } else if (!UUID.test(String(db.database_id))) {
    findings.push(`${where}d1_databases[0].database_id is not a D1 database id (still the placeholder?): create ${DATABASE_NAMES[env]} and put in its id`);
  }
  const vars = isObject(scope.vars) ? scope.vars : {};
  if (vars.AUTH_ENABLED !== 'true') findings.push(`${where}vars.AUTH_ENABLED must be "true"`);
  if (vars.ACCOUNT_ORIGIN !== `https://${HOSTS[env]}`) findings.push(`${where}vars.ACCOUNT_ORIGIN must be https://${HOSTS[env]}`);
  const appId = String(vars.GITHUB_APP_ID ?? '');
  if (!/^[1-9][0-9]*$/.test(appId) || appId === FORUM_APP_ID) findings.push(`${where}vars.GITHUB_APP_ID must be the sign-in app's numeric id (still the placeholder?)`);
  if (env === 'staging' && appId === PRODUCTION_APP_ID) findings.push('env.staging.vars.GITHUB_APP_ID must be the separate staging app, never production\'s');
  if (env === 'production' && appId !== PRODUCTION_APP_ID) findings.push(`vars.GITHUB_APP_ID must be the registered production app ${PRODUCTION_APP_ID}`);
  const clientId = String(vars.GITHUB_CLIENT_ID ?? '');
  if (!/^Iv[0-9A-Za-z.]{8,40}$/.test(clientId)) findings.push(`${where}vars.GITHUB_CLIENT_ID must be the sign-in app's client id (still the placeholder?)`);
  if (env === 'staging' && clientId === config.vars?.GITHUB_CLIENT_ID) findings.push('env.staging.vars.GITHUB_CLIENT_ID must be the staging app\'s, never production\'s');
  let allowed = null;
  try {
    allowed = JSON.parse(String(vars.GITHUB_ALLOWED_IDS ?? ''));
  } catch {
    allowed = null;
  }
  if (!Array.isArray(allowed) || allowed.length === 0 || !allowed.every((id) => typeof id === 'string' && /^[1-9][0-9]{0,15}$/.test(id))) {
    findings.push(`${where}vars.GITHUB_ALLOWED_IDS must be a non-empty JSON array of numeric GitHub id strings (D37)`);
  }
  return findings;
}

function main(argv) {
  const [file, env] = argv;
  if (argv.length !== 2 || (env !== 'staging' && env !== 'production')) {
    process.stderr.write('usage: node tools/deploy-preflight.mjs <wrangler.json> <staging|production>\n');
    return 2;
  }
  let config;
  try {
    config = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    process.stderr.write(`deploy preflight: could not read ${file}: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  const findings = preflightFindings(config, env);
  if (findings.length > 0) {
    process.stderr.write(`deploy preflight (${env}): refused, nothing was migrated or deployed\n`);
    for (const f of findings) process.stderr.write(`  ${f}\n`);
    return 1;
  }
  process.stdout.write(`deploy preflight (${env}): configuration accepted\n`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = main(process.argv.slice(2));
