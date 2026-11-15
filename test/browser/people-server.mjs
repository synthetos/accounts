// Loopback-only UI fixture. Every identity and all GitHub lookups are synthetic.
import { createServer } from 'node:http';
import { adminFixture } from '../../workers/accounts/test/roles-fixture.mjs';
import { createApp } from '../../workers/accounts/src/app.ts';
import { Store } from '../../workers/accounts/src/store.ts';
import { origin, sha } from '../../workers/accounts/test/fixture.mjs';
import { randomToken } from '../../packages/auth-core/src/index.ts';

const f = await adminFixture();
const samples = [
  ['45678', 'alex-maker', 'Alex Chen', 'tester'], ['56789', 'jamie-workshop', 'Jamie Morgan', 'member'],
  ['67890', 'sam-moderator', 'Sam Rivera', 'moderator'],
];
for (const [subject, login, displayName, role] of samples) {
  await f.roles.change(f.hash, subject, role, `Approved ${role} access`, f.now,
    { subject, login, displayName, avatarUrl: null });
}
f.db.exec("UPDATE identities SET login='owner-fixture' WHERE provider_subject='12345'");
f.db.exec("UPDATE users SET display_name='Account Owner' WHERE id=(SELECT user_id FROM identities WHERE provider_subject='12345')");
const moderator = randomToken();
await new Store(f.env.IDENTITY, f.env.GITHUB_ALLOWED_IDS).signIn('github',
  { subject: '67890', login: 'sam-moderator', displayName: 'Sam Rivera', avatarUrl: null }, sha(moderator), f.now, f.now);
const app = createApp({ now: () => f.now, lookupPerson: async login =>
  ({ subject: '89012', login, displayName: 'Taylor Quinn', avatarUrl: null }) });
const server = createServer(async (request, reply) => {
  try {
    if (request.url === '/fixture-session') {
      reply.setHeader('Content-Type', 'application/json');
      reply.end(JSON.stringify({ admin: f.sid.split('=')[1], moderator })); return;
    }
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const init = { method: request.method, headers: request.headers };
    if (chunks.length) init.body = Buffer.concat(chunks);
    const result = await app.fetch(new Request(origin + request.url, init), f.env);
    reply.writeHead(result.status, Object.fromEntries(result.headers)); reply.end(await result.text());
  } catch { reply.writeHead(500); reply.end('Fixture failed'); }
});
server.listen(Number(process.env.PORT ?? 18985), '127.0.0.1');
process.on('SIGTERM', () => server.close(() => { f.close(); process.exit(0); }));
