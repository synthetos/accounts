import type { ProviderProfile } from '../../../packages/idp/src/index.ts';
import { check, readBody } from './security.ts';

/** Public profile lookup: no OAuth credentials or caller-controlled URL. Identity uses GitHub's immutable id. */
export async function githubPerson(login: string, fetcher: typeof fetch = fetch): Promise<ProviderProfile> {
  const response = await fetcher(`https://api.github.com/users/${encodeURIComponent(login)}`, {
    redirect: 'manual', signal: AbortSignal.timeout(10_000),
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Synthetos-Accounts', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  check(response.status !== 404, 404, 'GitHub user not found.');
  check(response.ok, 502, 'GitHub lookup unavailable. Try again later.');
  const data = JSON.parse(await readBody(response, 65_536)) as Record<string, unknown>;
  check(data && Number.isSafeInteger(data['id']) && Number(data['id']) > 0 && data['type'] === 'User' &&
    typeof data['login'] === 'string' && /^[a-zA-Z0-9-]{1,39}$/.test(data['login']), 502, 'Invalid GitHub profile.');
  return { subject: String(data['id']), login: data['login'],
    displayName: typeof data['name'] === 'string' && data['name'].length <= 256 ? data['name'] : data['login'], avatarUrl: null };
}
