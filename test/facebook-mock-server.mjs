import { createServer } from 'node:http';

const port = Number(process.env.MMS_FACEBOOK_MOCK_PORT || 3999);
const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
  if (req.method === 'POST' && url.pathname === '/oauth/access_token') {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const form = new URLSearchParams(raw); const code = form.get('code') || '';
    if (code === 'token-error') { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: { message: 'mock rejected code' } })); }
    res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ access_token: `mock-token:${code}` }));
  }
  if (req.method === 'GET' && url.pathname === '/me') {
    const code = String(req.headers.authorization || '').replace('Bearer mock-token:', '');
    const suffix = process.env.MMS_FACEBOOK_TEST_SUFFIX || 'default';
    const profiles = {
      'new-email': { id: `facebook-new-${suffix}`, name: 'Aina Facebook', email: `facebook-${suffix}@example.mg` },
      conflict: { id: `facebook-conflict-${suffix}`, name: 'Email Existant', email: `conflict-${suffix}@example.mg` },
      'no-email': { id: `facebook-no-email-${suffix}`, name: 'Solo Facebook' },
    };
    const profile = profiles[code];
    if (!profile) { res.writeHead(500, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: { message: 'unknown mock code' } })); }
    res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(profile));
  }
  res.writeHead(404); res.end();
});
server.listen(port, '127.0.0.1', () => console.log(`Mock Meta prêt sur ${port}`));
process.on('SIGTERM', () => server.close());
