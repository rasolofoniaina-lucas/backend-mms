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
  const register = async (phone, email, password = 'password123') => {
    const result = await request('/api/auth/customer-register', { method: 'POST', body: { firstName: 'Compte', lastName: 'Local', phone, email, password } });
    assert.equal(result.status, 201); return result;
  };
  await t.test('téléphone existant ne crée aucun user puis le bon mot de passe lie Facebook', async () => {
    const phone = `+2613301${suffix.padStart(5, '0')}`; const email = `existing-${suffix}@example.mg`;
    await register(phone, email);
    const owner = await pool.query('SELECT id FROM users WHERE phone_e164=$1', [phone]); const before = await pool.query('SELECT count(*)::int AS count FROM users');
    const returned = await callback('existing-phone'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Ignore', lastName: 'Ignore', phone, email: 'ignored@example.mg' } });
    assert.equal(completed.status, 409); assert.equal(completed.data.code, 'FACEBOOK_EXISTING_ACCOUNT');
    const afterConflict = await pool.query('SELECT count(*)::int AS count FROM users'); assert.equal(afterConflict.rows[0].count, before.rows[0].count);
    const linked = await request('/api/auth/facebook/link-existing', { method: 'POST', cookie: pendingCookie, body: { phone, password: 'password123' } });
    assert.equal(linked.status, 200); assert.ok(linked.data.accessToken);
    const identity = await pool.query(`SELECT user_id FROM user_identities WHERE provider='facebook' AND provider_subject=$1`, [`facebook-existing-${suffix}`]);
    assert.equal(identity.rows[0].user_id, owner.rows[0].id);
    const afterLink = await pool.query('SELECT count(*)::int AS count FROM users'); assert.equal(afterLink.rows[0].count, before.rows[0].count);
  });
  await t.test('mauvais mot de passe ne lie jamais Facebook', async () => {
    const phone = `+2613302${suffix.padStart(5, '0')}`; const email = `wrong-${suffix}@example.mg`;
    await register(phone, email);
    const returned = await callback('wrong-password'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Compte', lastName: 'Local', phone, email } });
    assert.equal(completed.data.code, 'FACEBOOK_EXISTING_ACCOUNT');
    const linked = await request('/api/auth/facebook/link-existing', { method: 'POST', cookie: pendingCookie, body: { phone, password: 'incorrect-password' } });
    assert.equal(linked.status, 401); assert.equal(linked.data.error, 'Identifiant ou mot de passe incorrect.');
    const identity = await pool.query(`SELECT count(*)::int AS count FROM user_identities WHERE provider='facebook' AND provider_subject=$1`, [`facebook-wrong-${suffix}`]);
    assert.equal(identity.rows[0].count, 0);
  });
  await t.test('identité Facebook liée ailleurs est refusée sans déplacement', async () => {
    const targetPhone = `+2613303${suffix.padStart(5, '0')}`; const otherPhone = `+2613304${suffix.padStart(5, '0')}`;
    await register(targetPhone, `linked-${suffix}@example.mg`); await register(otherPhone, `linked-other-${suffix}@example.mg`);
    const returned = await callback('already-linked'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Compte', lastName: 'Cible', phone: targetPhone, email: `linked-${suffix}@example.mg` } });
    assert.equal(completed.data.code, 'FACEBOOK_EXISTING_ACCOUNT');
    const other = await pool.query('SELECT id FROM users WHERE phone_e164=$1', [otherPhone]);
    await pool.query(`INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES(gen_random_uuid(),$1,'facebook',$2)`, [other.rows[0].id, `facebook-linked-${suffix}`]);
    const linked = await request('/api/auth/facebook/link-existing', { method: 'POST', cookie: pendingCookie, body: { phone: targetPhone, password: 'password123' } });
    assert.equal(linked.status, 409); assert.equal(linked.data.code, 'FACEBOOK_ALREADY_LINKED');
    const identity = await pool.query(`SELECT user_id FROM user_identities WHERE provider='facebook' AND provider_subject=$1`, [`facebook-linked-${suffix}`]);
    assert.equal(identity.rows[0].user_id, other.rows[0].id);
  });
  await t.test('email User A et téléphone User B sont refusés sans fusion', async () => {
    const phoneA = `+2613305${suffix.padStart(5, '0')}`; const phoneB = `+2613306${suffix.padStart(5, '0')}`;
    await register(phoneA, `cross-email-${suffix}@example.mg`); await register(phoneB, `cross-phone-${suffix}@example.mg`);
    const returned = await callback('cross-account'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const before = await pool.query('SELECT count(*)::int AS count FROM users');
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Conflit', lastName: 'Croise', phone: phoneB, email: `cross-email-${suffix}@example.mg` } });
    assert.equal(completed.status, 409); assert.equal(completed.data.code, 'FACEBOOK_IDENTITY_CONFLICT');
    const identity = await pool.query(`SELECT count(*)::int AS count FROM user_identities WHERE provider='facebook' AND provider_subject=$1`, [`facebook-cross-${suffix}`]);
    const after = await pool.query('SELECT count(*)::int AS count FROM users'); assert.equal(identity.rows[0].count, 0); assert.equal(after.rows[0].count, before.rows[0].count);
  });
  await t.test('booking claim est consommé par le compte existant après authentification', async () => {
    const phone = `+2613307${suffix.padStart(5, '0')}`; const email = `booking-existing-${suffix}@example.mg`;
    await register(phone, email); const before = await pool.query('SELECT count(*)::int AS count FROM users');
    const booking = await request('/api/bookings/complete', { method: 'POST', body: { kind: 'Urgence', address: 'Analakely, Antananarivo', problem: 'La moto ne démarre plus depuis ce matin.', firstName: 'Aina', lastName: 'Booking', email: `anonymous-${suffix}@example.mg`, contactPhone: phone, immobilized: true, vehicle: { name: 'Yamaha', displacementCc: 125, year: 2024, model: '', plate: '' } } });
    assert.equal(booking.status, 201); assert.ok(booking.data.bookingClaim);
    const returned = await callback('booking-existing'); const pendingCookie = returned.cookies.find(value => value.startsWith('mms_facebook_pending=')); assert.ok(pendingCookie);
    const completed = await request('/api/auth/facebook/complete', { method: 'POST', cookie: pendingCookie, body: { firstName: 'Aina', lastName: 'Booking', phone, email } });
    assert.equal(completed.data.code, 'FACEBOOK_EXISTING_ACCOUNT');
    const linked = await request('/api/auth/facebook/link-existing', { method: 'POST', cookie: pendingCookie, body: { phone, password: 'password123', claimToken: booking.data.bookingClaim } });
    assert.equal(linked.status, 200); assert.ok(linked.data.user.tickets.some(ticket => ticket.reference === booking.data.ticket.reference));
    const claimHash = createHmac('sha256', accessSecret).update(`booking:${booking.data.bookingClaim}`).digest('hex');
    const claim = await pool.query('SELECT consumed_at FROM booking_claims WHERE token_hash=$1', [claimHash]); assert.ok(claim.rows[0].consumed_at);
    const after = await pool.query('SELECT count(*)::int AS count FROM users'); assert.equal(after.rows[0].count, before.rows[0].count);
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
