import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const title = 'Mutation score below 90';

/** Runs only in the separate main-only reporter job; the mutation job has no write token. */
export async function updateIssue({ repository, token, body, fetcher = fetch }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository ?? '') || !token) throw new Error('Missing issue reporter repository/token');
  const request = async (path, method = 'GET', payload) => {
    const response = await fetcher(`https://api.github.com/repos/${repository}${path}`, {
      method, redirect: 'error', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    });
    if (!response.ok) throw new Error(`Issue API failed (${response.status})`);
    return response.json();
  };
  for (let page = 1; ; page++) {
    const issues = await request(`/issues?state=all&per_page=100&page=${page}`);
    const found = issues.find(issue => !issue.pull_request && issue.title === title);
    if (found) return request(`/issues/${found.number}`, 'PATCH', { body, state: 'open' });
    if (issues.length < 100) break;
  }
  return request('/issues', 'POST', { title, body });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await updateIssue({ repository: process.env.GITHUB_REPOSITORY, token: process.env.GH_TOKEN, body: readFileSync('reports/mutation-issue.md', 'utf8') });
}
