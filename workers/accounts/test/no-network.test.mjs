import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GitHubProvider } from '../../../packages/idp/src/index.ts';

test('native tests block real fetch, including the provider fallback without an injected fetch', async () => {
  await assert.rejects(fetch('https://network-must-not-run.invalid/'), /Network is forbidden/);
  const provider = new GitHubProvider({ clientId:'fixture', clientSecret:'fixture', redirectUri:'https://accounts.test/auth/github/callback' });
  await assert.rejects(provider.exchange('fixture-code','fixture-verifier'), {message:'provider_unavailable'});
  await assert.rejects(provider.profile('fixture-token'), {message:'provider_unavailable'});
});
