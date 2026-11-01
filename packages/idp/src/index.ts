export interface ProviderProfile {
  readonly subject: string;
  readonly login: string;
  readonly displayName: string;
  readonly avatarUrl: string | null;
}

/** Provider credentials are transient: never return them to a browser or persistence. */
export interface IdentityProvider {
  readonly name: string;
  authorizeUrl(state: string, challenge: string, options?: { selectAccount: boolean }): string;
  exchange(code: string, verifier: string): Promise<string>;
  profile(credential: string): Promise<ProviderProfile>;
}

export interface GitHubOptions {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly fetch?: typeof fetch;
}

export class ProviderError extends Error {
  constructor() { super('provider_unavailable'); }
}

async function json(response: Response): Promise<Record<string, unknown>> {
  // workerd supports manual redirects; reject every non-2xx response without following it.
  if (!response.ok || response.body === null) throw new ProviderError();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 65_536) throw new ProviderError();
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ProviderError();
  return value as Record<string, unknown>;
}

/** GitHub App user authorization: fixed endpoints, S256, no scopes or refresh-token request. */
export class GitHubProvider implements IdentityProvider {
  readonly name = 'github';
  private readonly options: GitHubOptions;
  constructor(options: GitHubOptions) {
    const callback = new URL(options.redirectUri);
    if (callback.protocol !== 'https:' || callback.username || callback.password || callback.search || callback.hash ||
      callback.pathname !== '/auth/github/callback' || !options.clientId || !options.clientSecret) throw new ProviderError();
    this.options = options;
  }
  authorizeUrl(state: string, challenge: string, options?: { selectAccount: boolean }): string {
    const url = new URL('https://github.com/login/oauth/authorize');
    url.search = new URLSearchParams({ client_id: this.options.clientId, redirect_uri: this.options.redirectUri,
      state, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
    if (options?.selectAccount) url.searchParams.set('prompt', 'select_account');
    return url.href;
  }
  async exchange(code: string, verifier: string): Promise<string> {
    try {
      const value = await json(await (this.options.fetch ?? fetch)('https://github.com/login/oauth/access_token', {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10_000),
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: this.options.clientId, client_secret: this.options.clientSecret,
          code, redirect_uri: this.options.redirectUri, code_verifier: verifier }),
      }));
      if (value['error'] !== undefined || value['token_type'] !== 'bearer' || typeof value['access_token'] !== 'string' ||
        value['access_token'].length === 0 || value['access_token'].length > 4096 || /[\s\x00-\x1f]/.test(value['access_token'])) throw new ProviderError();
      return value['access_token'];
    } catch { throw new ProviderError(); }
  }
  async profile(credential: string): Promise<ProviderProfile> {
    try {
      const value = await json(await (this.options.fetch ?? fetch)('https://api.github.com/user', {
        redirect: 'manual', signal: AbortSignal.timeout(10_000), headers: {
          Accept: 'application/vnd.github+json', Authorization: `Bearer ${credential}`,
          'User-Agent': 'Synthetos-Accounts', 'X-GitHub-Api-Version': '2022-11-28',
        },
      }));
      if (!Number.isSafeInteger(value['id']) || (value['id'] as number) <= 0 || typeof value['login'] !== 'string' ||
        !/^[a-zA-Z0-9-]{1,39}$/.test(value['login']) || !(value['name'] === null ||
          (typeof value['name'] === 'string' && value['name'].length <= 256))) throw new ProviderError();
      let avatarUrl: string | null = null;
      if (typeof value['avatar_url'] === 'string' && value['avatar_url'].length <= 2048) {
        const avatar = new URL(value['avatar_url']);
        if (avatar.protocol === 'https:' && avatar.hostname === 'avatars.githubusercontent.com' && !avatar.username && !avatar.password && !avatar.port) avatarUrl = avatar.href;
      }
      // Intentionally do not copy email, permissions, tokens or any other provider fields.
      return { subject: String(value['id']), login: value['login'], displayName: value['name'] || value['login'], avatarUrl };
    } catch { throw new ProviderError(); }
  }
}
