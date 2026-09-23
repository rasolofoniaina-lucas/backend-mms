import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomInt, randomUUID } from 'node:crypto';
import { runCustomerPasswordResetTests } from './customer-password-reset.integration.test.mjs';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:8080';
const container = process.env.MMS_API_CONTAINER || 'mms-api-1';
const suffix = randomInt(10000, 90000);
const phone = `+2613713${suffix}`;
const customerAdminPhone = `+2613713${suffix + 1}`;
const identity = randomUUID().slice(0, 8);
const adminUsername = `admin_${identity}`;
const managerUsername = `chef_${identity}`;
const mechanicAUsername = `meca_${identity}`;
const mechanicBUsername = `atelier_${identity}`;

async function api(path, { method = 'GET', body, token, cookie } = {}) {
  const response = await fetch(`${base}/api${path}`, { method, headers: {
    ...(body ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(cookie ? { Cookie: cookie } : {}),
  }, body: body ? JSON.stringify(body) : undefined });
  return { status: response.status, data: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
function otp(challengeId) {
  assert.match(challengeId, /^[0-9a-f-]{36}$/);
  return execFileSync('docker', ['exec', container, 'cat', `/tmp/mms-test-otp-${challengeId}`], { encoding: 'utf8' }).trim();
}
function bootstrap() {
  const output = execFileSync('docker', ['exec','-i',container,'npm','run','admin:create'], {
    input: `Recette\nAdmin\n${adminUsername}\n\n`, encoding: 'utf8',
  });
  const password = output.match(/Mot de passe temporaire \(affiché une seule fois\) : ([A-Za-z0-9]+)/)?.[1];
  assert.ok(password, 'Le bootstrap doit remettre un mot de passe temporaire une seule fois');
  return password;
}
async function activate(username, temporary) {
  const first = await api('/staff/login', { method: 'POST', body: { username, password: temporary } });
  assert.equal(first.status, 200);
  assert.equal(first.data.user.mustChangePassword, true);
  assert.equal((await api('/staff/tickets', { token: first.data.accessToken })).status, 403);
  const permanent = `Mms-${randomUUID()}-V1`;
  const changed = await api('/staff/change-password', { method: 'POST', token: first.data.accessToken, body: { currentPassword: temporary, newPassword: permanent } });
  assert.equal(changed.status, 200);
  assert.equal((await api('/staff/me', { token: first.data.accessToken })).status, 401);
  assert.equal((await api('/staff/login', { method: 'POST', body: { username, password: temporary } })).status, 401);
  const login = await api('/staff/login', { method: 'POST', body: { username: username.toUpperCase(), password: permanent } });
  assert.equal(login.status, 200);
  assert.equal(login.data.user.mustChangePassword, false);
  return { ...login, permanent };
}

test('Phase A : auth staff, RBAC, tickets et historique local', async t => {
  const bootstrapPassword = bootstrap();
  const admin = await activate(adminUsername, bootstrapPassword);
  await t.test('bootstrap admin et changement obligatoire', async () => {
    assert.equal(admin.data.user.role, 'admin');
    assert.equal((await api('/admin/users', { token: admin.data.accessToken })).status, 200);
    assert.equal((await api('/staff/tickets', { token: admin.data.accessToken })).status, 403);
    const refreshed = await api('/auth/refresh', { method: 'POST', body: {}, cookie: admin.cookie });
    assert.equal(refreshed.status, 200);
    assert.equal(refreshed.data.user.role, 'admin');
    admin.data.accessToken = refreshed.data.accessToken;
  });
  async function createStaff(username, role, email = '') {
    const result = await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Recette', lastName: role, username, email, role } });
    assert.equal(result.status, 201);
    assert.ok(result.data.temporaryPassword);
    return result.data;
  }
  const chefCreated = await createStaff(managerUsername, 'workshop_manager');
  const aCreated = await createStaff(mechanicAUsername, 'mechanic');
  const bCreated = await createStaff(mechanicBUsername, 'mechanic', `atelier.${identity}@mms.mg`);
  assert.equal(aCreated.email, null);
  assert.equal((await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Doublon', lastName: 'Recette', username: mechanicAUsername.toUpperCase(), role: 'mechanic' } })).status, 409);
  assert.equal((await api('/staff/login', { method: 'POST', body: { username: `absent_${identity}`, password: 'wrong-password' } })).status, 401);
  assert.equal((await api('/staff/login', { method: 'POST', body: { username: mechanicAUsername, password: 'wrong-password' } })).status, 401);
  const chef = await activate(managerUsername, chefCreated.temporaryPassword);
  const mecaA = await activate(mechanicAUsername, aCreated.temporaryPassword);
  const mecaB = await activate(mechanicBUsername, bCreated.temporaryPassword);
  await runCustomerPasswordResetTests(t, { admin, manager: chef, mechanic: mecaA, mechanicUser: aCreated });
  await t.test('rôles staff et frontières admin', async () => {
    assert.equal((await api('/admin/users', { token: chef.data.accessToken })).status, 403);
    assert.equal((await api('/admin/users', { token: mecaA.data.accessToken })).status, 403);
    assert.equal((await api('/staff/mechanics', { token: chef.data.accessToken })).status, 200);
    assert.equal((await api('/staff/mechanics', { token: mecaA.data.accessToken })).status, 403);
  });
  const request = await api('/auth/register/request-otp', { method: 'POST', body: { firstName: 'Client', lastName: 'Recette', phone, termsAccepted: true, privacyAccepted: true } });
  assert.equal(request.status, 200);
  const client = await api('/auth/register/verify-otp', { method: 'POST', body: { challengeId: request.data.challengeId, code: otp(request.data.challengeId) } });
  assert.equal(client.status, 201);
  const clientId = client.data.user.user.id;
  await t.test('demandes de récupération : lecture admin/chef et isolation des autres rôles', async () => {
    const created = await api('/auth/recovery-request', { method: 'POST', body: { identifier: phone } });
    assert.equal(created.status, 200);
    const adminList = await api('/staff/access-requests', { token: admin.data.accessToken });
    const managerList = await api('/staff/access-requests', { token: chef.data.accessToken });
    assert.equal(adminList.status, 200); assert.equal(managerList.status, 200);
    const entry = adminList.data.find(item => item.phoneMasked === '037 ** *** **');
    assert.ok(entry); assert.equal(entry.status, 'pending'); assert.equal(entry.customer, 'Client Recette');
    assert.deepEqual(Object.keys(entry).sort(), ['createdAt','customer','emailMasked','id','phoneMasked','status','userId'].sort());
    assert.match(entry.userId, /^[0-9a-f-]{36}$/);
    assert.notEqual(entry.userId, clientId);
    assert.equal(entry.emailMasked, null); assert.equal(JSON.stringify(adminList.data).includes(phone), false);
    assert.deepEqual(managerList.data, adminList.data);
    assert.equal((await api('/staff/access-requests', { token: mecaA.data.accessToken })).status, 403);
    assert.equal((await api('/staff/access-requests', { token: client.data.accessToken })).status, 403);
    assert.equal((await api('/staff/access-requests')).status, 401);
  });
  const vehicle = await api(`/customers/${clientId}/vehicles`, { method: 'POST', token: client.data.accessToken, body: { name: 'Yamaha', model: 'YZ250F', displacementCc: 250, year: 2024, plate: '' } });
  assert.equal(vehicle.status, 201);
  const appointment = await api(`/customers/${clientId}/appointments`, { method: 'POST', token: client.data.accessToken, body: { vehicleId: vehicle.data.id, problem: 'Panne moteur pour la recette Phase A', diagnosis: '', kind: 'Urgence', address: 'Atelier de recette local', contactPhone: phone, immobilized: true } });
  assert.equal(appointment.status, 201);
  const ticket = appointment.data.ticket;
  await t.test('ticket lié, référence et isolation client', async () => {
    assert.match(ticket.reference, /^MMS-\d{4}-\d{6,}$/);
    assert.equal(ticket.appointmentId, appointment.data.id);
    assert.equal(ticket.status, 'new');
    assert.equal((await api(`/customers/${clientId}/tickets/${ticket.reference}`, { token: client.data.accessToken })).status, 200);
    assert.equal((await api('/staff/tickets', { token: client.data.accessToken })).status, 403);
    assert.equal((await api('/admin/users', { token: client.data.accessToken })).status, 403);
  });
  await t.test('chef qualifie puis assigne A, B reste exclu', async () => {
    assert.ok((await api('/staff/tickets', { token: chef.data.accessToken })).data.some(row => row.reference === ticket.reference));
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: chef.data.accessToken, body: { status: 'triage' } })).status, 200);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/assign`, { method: 'PATCH', token: mecaA.data.accessToken, body: { mechanicUserId: aCreated.id } })).status, 403);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/assign`, { method: 'PATCH', token: chef.data.accessToken, body: { mechanicUserId: aCreated.id } })).status, 200);
    assert.equal((await api(`/staff/tickets/${ticket.reference}`, { token: mecaB.data.accessToken })).status, 404);
    assert.ok((await api('/staff/tickets', { token: mecaA.data.accessToken })).data.some(row => row.reference === ticket.reference));
    assert.ok(!(await api('/staff/tickets', { token: mecaB.data.accessToken })).data.some(row => row.reference === ticket.reference));
  });
  await t.test('A traite, transitions invalides refusées, client voit terminé', async () => {
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: mecaA.data.accessToken, body: { status: 'completed' } })).status, 409);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: mecaA.data.accessToken, body: { status: 'in_progress' } })).status, 200);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: mecaA.data.accessToken, body: { status: 'waiting_customer' } })).status, 200);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: mecaA.data.accessToken, body: { status: 'in_progress' } })).status, 200);
    assert.equal((await api(`/staff/tickets/${ticket.reference}/status`, { method: 'PATCH', token: mecaA.data.accessToken, body: { status: 'completed' } })).status, 200);
    const detail = await api(`/customers/${clientId}/tickets/${ticket.reference}`, { token: client.data.accessToken });
    assert.equal(detail.data.status, 'completed');
    assert.ok(detail.data.events.length >= 7);
    assert.equal(detail.data.customerPhone, undefined);
  });
  await t.test('création concurrente : références uniques', async () => {
    const payload = { vehicleId: vehicle.data.id, problem: 'Demande concurrente de recette MMS', diagnosis: '', kind: 'Urgence', address: 'Adresse de recette locale', contactPhone: phone, immobilized: true };
    const both = await Promise.all([api(`/customers/${clientId}/appointments`, { method: 'POST', token: client.data.accessToken, body: payload }), api(`/customers/${clientId}/appointments`, { method: 'POST', token: client.data.accessToken, body: payload })]);
    assert.deepEqual(both.map(x => x.status), [201,201]);
    assert.notEqual(both[0].data.ticket.reference, both[1].data.ticket.reference);
  });
  await t.test('admin crée client non vérifié, disable et reset staff', async () => {
    const manual = await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Manuel', lastName: 'Recette', phone: customerAdminPhone, role: 'customer' } });
    assert.equal(manual.status, 201); assert.equal(manual.data.phoneVerified, false);
    const listed = await api('/admin/users', { token: admin.data.accessToken });
    assert.equal(listed.data.find(row => row.id === manual.data.id).phoneVerifiedAt, null);
    assert.equal((await api(`/admin/users/${bCreated.id}/status`, { method: 'PATCH', token: admin.data.accessToken, body: { status: 'disabled' } })).status, 200);
    assert.equal((await api('/staff/me', { token: mecaB.data.accessToken })).status, 401);
    assert.equal((await api('/staff/login', { method: 'POST', body: { username: mechanicBUsername, password: mecaB.permanent } })).status, 401);
    assert.equal((await api(`/admin/users/${bCreated.id}/status`, { method: 'PATCH', token: admin.data.accessToken, body: { status: 'active' } })).status, 200);
    const reset = await api(`/admin/users/${aCreated.id}/reset-password`, { method: 'POST', token: admin.data.accessToken, body: {} });
    assert.equal(reset.status, 200); assert.ok(reset.data.temporaryPassword);
    assert.equal((await api('/staff/me', { token: mecaA.data.accessToken })).status, 401);
    assert.equal((await api('/staff/login', { method: 'POST', body: { username: mechanicAUsername, password: mecaA.permanent } })).status, 401);
  });
  t.diagnostic(`RECETTE_LOCALE usernames=${adminUsername},${managerUsername},${mechanicAUsername},${mechanicBUsername} clients=${phone},${customerAdminPhone} ticket=${ticket.reference} moto=${vehicle.data.id} rendez_vous=${appointment.data.id}`);
});
