import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomInt } from 'node:crypto';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:8080';
const container = process.env.MMS_API_CONTAINER || 'mms-api-1';
const suffix = randomInt(10000, 90000);
const phoneA = `+2613412${suffix}`;
const phoneB = `+2613412${suffix + 1}`;
const phoneNew = `+2613412${suffix + 2}`;

async function api(path, { method = 'GET', body, token, cookie } = {}) {
  const response = await fetch(`${base}/api${path}`, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(cookie ? { Cookie: cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, data: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
function testOtp(challengeId) {
  assert.match(challengeId, /^[0-9a-f-]{36}$/);
  assert.match(container, /^[a-zA-Z0-9_.-]+$/);
  const command = ['exec', container, 'cat', `/tmp/mms-test-otp-${challengeId}`];
  const host = process.env.MMS_OTP_SSH_HOST;
  return execFileSync(host ? 'ssh' : 'docker', host ? [
    '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
    host, `docker ${command.join(' ')}`,
  ] : command, { encoding: 'utf8', timeout: 20_000 }).trim();
}
async function register(phone, firstName) {
  const requested = await api('/auth/register/request-otp', { method: 'POST', body: { firstName, lastName: 'Recette', phone, termsAccepted: true, privacyAccepted: true } });
  assert.equal(requested.status, 200);
  const verified = await api('/auth/register/verify-otp', { method: 'POST', body: { challengeId: requested.data.challengeId, code: testOtp(requested.data.challengeId) } });
  assert.equal(verified.status, 201);
  assert.ok(verified.data.accessToken); assert.ok(verified.cookie);
  return verified;
}

test('parcours OTP, sessions et isolation des clients via Nginx', async t => {
  await t.test('health 200 et auth/me anonyme 401', async () => {
    assert.equal((await api('/health')).status, 200);
    assert.equal((await api('/auth/me')).status, 401);
  });
  const a = await register(phoneA, 'Alice');
  await t.test('inscription A et session immédiate', async () => {
    assert.equal((await api('/auth/me', { token: a.data.accessToken })).status, 200);
    assert.equal(a.data.user.user.phone, phoneA);
  });
  const b = await register(phoneB, 'Bob');
  await t.test('inscription B indépendante', async () => {
    assert.notEqual(a.data.user.user.id, b.data.user.user.id);
    assert.equal((await api('/auth/me', { token: b.data.accessToken })).status, 200);
  });
  const vehicle = await api(`/customers/${b.data.user.user.id}/vehicles`, { method: 'POST', token: b.data.accessToken, body: { name: 'Honda', displacementCc: 125, year: 2023, model: 'Test', plate: '' } });
  assert.equal(vehicle.status, 201);
  await t.test('B peut personnaliser sa moto', async () => {
    const changedVehicle = await api(`/customers/${b.data.user.user.id}/vehicles/${vehicle.data.id}`, { method: 'PATCH', token: b.data.accessToken, body: { name: 'Honda', displacementCc: 150, year: 2024, model: 'Test', plate: '' } });
    assert.equal(changedVehicle.status, 200);
    assert.equal(changedVehicle.data.displacementCc, 150);
  });
  await t.test('photo privée visible uniquement par B', async () => {
    const path = `/api/customers/${b.data.user.user.id}/vehicles/${vehicle.data.id}/photo`;
    const uploaded = await fetch(`${base}${path}`, { method: 'PUT', headers: { Authorization: `Bearer ${b.data.accessToken}`, 'Content-Type': 'image/png' }, body: Buffer.from('iVBORw0KGgo=', 'base64') });
    assert.equal(uploaded.status, 200);
    const own = await fetch(`${base}${path}`, { headers: { Authorization: `Bearer ${b.data.accessToken}` } });
    const other = await fetch(`${base}${path}`, { headers: { Authorization: `Bearer ${a.data.accessToken}` } });
    assert.equal(own.status, 200);
    assert.equal(other.status, 403);
  });
  const appointment = await api(`/customers/${b.data.user.user.id}/appointments`, { method: 'POST', token: b.data.accessToken, body: { vehicleId: vehicle.data.id, problem: 'Panne moteur de test', diagnosis: '', kind: 'Urgence', address: 'Adresse de test', contactPhone: phoneB, immobilized: true } });
  assert.equal(appointment.status, 201);
  await t.test('A ne lit ni ne modifie les données B', async () => {
    const prefix = `/customers/${b.data.user.user.id}`;
    assert.equal((await api(prefix, { token: a.data.accessToken })).status, 403);
    assert.equal((await api(prefix, { method: 'PATCH', token: a.data.accessToken, body: { name: 'Intrus' } })).status, 403);
    assert.equal((await api(`${prefix}/vehicles/${vehicle.data.id}/photo`, { token: a.data.accessToken })).status, 403);
    assert.equal((await api(`${prefix}/vehicles/${vehicle.data.id}`, { method: 'PATCH', token: a.data.accessToken, body: { name: 'Intrus', displacementCc: 125, year: 2023 } })).status, 403);
    assert.equal((await api(`${prefix}/appointments/${appointment.data.id}/cancel`, { method: 'PATCH', token: a.data.accessToken, body: {} })).status, 403);
    assert.equal((await api(prefix, { token: b.data.accessToken })).status, 200);
  });
  await t.test('B voit et annule son rendez-vous', async () => {
    const prefix = `/customers/${b.data.user.user.id}`;
    const details = await api(prefix, { token: b.data.accessToken });
    assert.equal(details.status, 200);
    assert.ok(details.data.appointments.some(item => item.id === appointment.data.id));
    assert.equal((await api(`${prefix}/appointments/${appointment.data.id}/cancel`, { method: 'PATCH', token: b.data.accessToken, body: {} })).status, 200);
  });
  const refreshed = await api('/auth/refresh', { method: 'POST', body: {}, cookie: a.cookie });
  await t.test('refresh cookie restaure une session', async () => {
    assert.equal(refreshed.status, 200);
    assert.equal((await api('/auth/me', { token: refreshed.data.accessToken })).status, 200);
    assert.equal((await api('/auth/me', { token: a.data.accessToken })).status, 401);
  });
  const changed = await api('/auth/phone-change/request-otp', { method: 'POST', token: refreshed.data.accessToken, body: { phone: phoneNew } });
  assert.equal(changed.status, 200);
  const phoneVerified = await api('/auth/phone-change/verify-otp', { method: 'POST', token: refreshed.data.accessToken, body: { challengeId: changed.data.challengeId, code: testOtp(changed.data.challengeId) } });
  await t.test('changement de numéro confirmé et anciennes sessions révoquées', async () => {
    assert.equal(phoneVerified.status, 200);
    assert.equal(phoneVerified.data.user.user.phone, phoneNew);
    assert.equal((await api('/auth/me', { token: refreshed.data.accessToken })).status, 401);
    assert.equal((await api('/auth/me', { token: phoneVerified.data.accessToken })).status, 200);
  });
  const loggedOut = await api('/auth/logout', { method: 'POST', body: {}, cookie: phoneVerified.cookie });
  await t.test('logout invalide le token et le cookie', async () => {
    assert.equal(loggedOut.status, 200);
    assert.equal((await api('/auth/me', { token: phoneVerified.data.accessToken })).status, 401);
    assert.equal((await api('/auth/refresh', { method: 'POST', body: {}, cookie: phoneVerified.cookie })).status, 401);
  });
  const loginRequest = await api('/auth/login/request-otp', { method: 'POST', body: { phone: phoneNew } });
  assert.equal(loginRequest.status, 200);
  const login = await api('/auth/login/verify-otp', { method: 'POST', body: { challengeId: loginRequest.data.challengeId, code: testOtp(loginRequest.data.challengeId) } });
  await t.test('connexion OTP puis déconnexion de tous les appareils', async () => {
    assert.equal(login.status, 200);
    assert.equal((await api('/auth/me', { token: login.data.accessToken })).status, 200);
    assert.equal((await api('/auth/logout-all', { method: 'POST', token: login.data.accessToken, body: {} })).status, 200);
    assert.equal((await api('/auth/me', { token: login.data.accessToken })).status, 401);
  });
});
