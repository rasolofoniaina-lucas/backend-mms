import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomInt } from 'node:crypto';
import pg from 'pg';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3011';
const databaseUrl = process.env.DATABASE_URL;
const accessSecret = process.env.ACCESS_TOKEN_SECRET || '';
const suffix = process.env.MMS_FACEBOOK_TEST_SUFFIX || String(randomInt(10000, 90000));
const pool = databaseUrl ? new pg.Pool({ connectionString: databaseUrl }) : null;

function cookies(response) {
  const values = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [response.headers.get('set-cookie') || ''];
  return values.filter(Boolean).map(value => value.split(';')[0]);
}
async function request(path, { method = 'GET', body, cookie, redirect = 'manual' } = {}) {
  const response = await fetch(`${base}${path}`, { method, redirect, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: Array.isArray(cookie) ? cookie.join('; ') : cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const type = response.headers.get('content-type') || '';
  return { status: response.status, location: response.headers.get('location'), cookies: cookies(response), data: type.includes('json') ? await response.json() : null };
}
async function begin() {
  const started = await request('/api/auth/facebook');
  assert.equal(started.status, 302); assert.ok(started.location); assert.ok(started.cookies.some(value => value.startsWith('mms_facebook_state=')));
  const location = new URL(started.location); const state = location.searchParams.get('state'); assert.ok(state);
  return { state, cookie: started.cookies.find(value => value.startsWith('mms_facebook_state=')) };
}
async function callback(code) {
  const started = await begin();
  return request(`/api/auth/facebook/callback?state=${encodeURIComponent(started.state)}&code=${encodeURIComponent(code)}`, { cookie: started.cookie });
}

test('Facebook OAuth local simulé, identités et protections', async t => {
  assert.ok(pool, 'DATABASE_URL requis pour ce test');
  await t.test('URL OAuth et state lié au navigateur', async () => {
    const started = await begin(); const url = new URL((await request('/api/auth/facebook')).location);
    assert.equal(url.searchParams.get('client_id'), 'test-facebook-app');
    assert.equal(url.searchParams.get('scope'), 'public_profile,email');
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.notEqual(url.searchParams.get('state'), started.state);
  });
  await t.test('callback direct, state absent, invalide et expiré sont refusés', async () => {
    assert.equal((await request('/api/auth/facebook/callback?code=new-email')).location, '/login?facebook=invalid-state');
    const started = await begin();
    assert.equal((await request('/api/auth/facebook/callback?state=wrong&code=new-email', { cookie: started.cookie })).location, '/login?facebook=invalid-state');
    const state = 'expired-state'; const expires = Date.now() - 1000;
    const signature = createHmac('sha256', accessSecret).update(`facebook-state:${state}:${expires}`).digest('base64url');
    assert.equal((await request(`/api/auth/facebook/callback?state=${state}&code=new-email`, { cookie: `mms_facebook_state=${state}.${expires}.${signature}` })).location, '/login?facebook=invalid-state');
  });
  await t.test('annulation, code manquant et erreur OAuth reviennent proprement au login', async () => {
    let started = await begin();
    assert.equal((await request(`/api/auth/facebook/callback?state=${started.state}&error=access_denied`, { cookie: started.cookie })).location, '/login?facebook=cancelled');
    started = await begin();
    assert.equal((await request(`/api/auth/facebook/callback?state=${started.state}`, { cookie: started.cookie })).location, '/login?facebook=error');
    assert.equal((await callback('token-error')).location, '/login?facebook=error');
  });
  let createdUserId = '';
  await t.test('nouvelle identité avec email crée un client sans credential local', async () => {
    const returned = await callback('new-email');
    assert.equal(returned.location, '/register?facebook=complete');
    const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const pending = await request('/api/auth/facebook/pending', { cookie: pendingCookie });
    assert.deepEqual(pending.data, { firstName: 'Aina', lastName: 'Facebook', email: `facebook-${suffix}@example.mg`, emailProvided: true });
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Aina', lastName: 'Facebook', phone: `+261371${suffix.slice(-6).padStart(6, '0')}`, email: 'ignored@example.mg' } });
    assert.equal(completed.status, 201); assert.ok(completed.data.accessToken); createdUserId = completed.data.user.user.id;
    const row = await pool.query(`SELECT u.id AS user_id,u.role,c.email,ui.provider_subject,cc.user_id AS credential_user_id
      FROM users u JOIN customers c ON c.user_id=u.id JOIN user_identities ui ON ui.user_id=u.id AND ui.provider='facebook'
      LEFT JOIN customer_credentials cc ON cc.user_id=u.id WHERE c.id=$1`, [createdUserId]);
    assert.equal(row.rows[0].role, 'customer'); assert.equal(row.rows[0].email, `facebook-${suffix}@example.mg`);
    assert.equal(row.rows[0].provider_subject, `facebook-new-${suffix}`); assert.equal(row.rows[0].credential_user_id, null);
    const pendingRows = await pool.query('SELECT provider_subject,email FROM external_auth_registrations WHERE provider_subject=$1', [`facebook-new-${suffix}`]);
    assert.equal(Object.values(pendingRows.rows[0]).some(value => String(value).includes('mock-token')), false);
  });
  await t.test('identité Facebook existante ouvre une session MMS normale', async () => {
    const returned = await callback('new-email'); assert.equal(returned.location, '/login?facebook=success');
    const refreshCookie = returned.cookies.find(value => value.startsWith('mms_refresh=')); assert.ok(refreshCookie);
    const refreshed = await request('/api/auth/refresh', { method: 'POST', cookie: refreshCookie, body: {} });
    assert.equal(refreshed.status, 200); assert.equal(refreshed.data.user.user.id, createdUserId);
  });
  await t.test('email identique ne fusionne jamais automatiquement les comptes', async () => {
    const email = `conflict-${suffix}@example.mg`; const phone = `+261372${suffix.slice(-6).padStart(6, '0')}`;
    const registered = await request('/api/auth/customer-register', { method: 'POST', body: { firstName: 'Compte', lastName: 'Local', phone, email, password: 'password123' } });
    assert.equal(registered.status, 201);
    const returned = await callback('conflict'); assert.equal(returned.location, '/login?facebook=FACEBOOK_ACCOUNT_LINK_REQUIRED');
    const identities = await pool.query(`SELECT count(*)::int AS count FROM user_identities WHERE provider='facebook' AND provider_subject=$1`, [`facebook-conflict-${suffix}`]);
    assert.equal(identities.rows[0].count, 0);
  });
  await t.test('profil sans email exige et conserve une vraie adresse fournie par le client', async () => {
    const returned = await callback('no-email'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const pending = await request('/api/auth/facebook/pending', { cookie: pendingCookie }); assert.equal(pending.data.email, null); assert.equal(pending.data.emailProvided, false);
    const email = `no-email-${suffix}@example.mg`; const phone = `+261373${suffix.slice(-6).padStart(6, '0')}`;
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Solo', lastName: 'Facebook', phone, email } });
    assert.equal(completed.status, 201);
    const row = await pool.query('SELECT c.email,u.role FROM customers c JOIN users u ON u.id=c.user_id WHERE c.id=$1', [completed.data.user.user.id]);
    assert.deepEqual(row.rows[0], { email, role: 'customer' });
  });
});

test.after(async () => { await pool?.end(); });
