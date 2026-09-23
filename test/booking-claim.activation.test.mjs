import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const db = process.env.MMS_TEST_DB_CONTAINER || 'mms-b1-test-db-1';
const suffix = String(Date.now()).slice(-6);
async function api(path, { method = 'GET', body, token, ip = '203.0.113.10' } = {}) {
  const response = await fetch(`${base}/api${path}`, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), 'X-Real-IP': ip }, body: body ? JSON.stringify(body) : undefined });
  return { status: response.status, data: await response.json() };
}
function sql(query) { return execFileSync('docker', ['exec','-i',db,'psql','-U','mms_test','-d','mms_test','-At','-c',query], { encoding: 'utf8' }).trim(); }
function anonymous(index, overrides = {}) { return { kind: 'Urgence', address: 'Analakely, Antananarivo', problem: 'La moto ne démarre plus depuis ce matin.', firstName: 'Aina', lastName: `B2${index}`, email: `b2-${suffix}-${index}@example.mg`, contactPhone: `+26138${suffix.slice(0,4)}${String(index).padStart(3,'0')}`, immobilized: true, vehicle: { name: 'Honda', model: 'CB', plate: '', displacementCc: 125, year: 2024 }, ...overrides }; }
async function book(index, overrides = {}) { return api('/bookings/complete', { method: 'POST', body: anonymous(index, overrides), ip: `203.0.113.${index}` }); }
async function register(input) { return api('/auth/customer-register', { method: 'POST', body: { firstName: input.firstName, lastName: input.lastName, phone: input.contactPhone, email: input.email, password: 'password123', claimToken: input.claimToken }, ip: '203.0.113.200' }); }

test('B2 activation et consommation transactionnelle des booking claims', async t => {
  await t.test('nouveau compte : claim lie customer, ticket et moto sans duplication', async () => {
    const booking = await book(1); assert.equal(booking.status, 201);
    const created = await register({ ...anonymous(1), claimToken: booking.data.bookingClaim }); assert.equal(created.status, 201);
    const customerId = created.data.user.user.id;
    assert.equal(sql(`SELECT count(*) FROM customers c JOIN tickets t ON t.customer_id=c.id JOIN vehicles v ON v.customer_id=c.id WHERE c.id='${customerId}' AND t.id='${booking.data.ticket.id}'`), '1');
    assert.equal(sql(`SELECT count(*) FROM booking_claims WHERE ticket_id='${booking.data.ticket.id}' AND consumed_at IS NOT NULL`), '1');
  });
  await t.test('claim réutilisé, invalide et expiré sont refusés', async () => {
    const booking = await book(2); const account = await register({ ...anonymous(2), claimToken: booking.data.bookingClaim }); assert.equal(account.status, 201);
    assert.equal((await api('/bookings/claim', { method: 'POST', token: account.data.accessToken, body: { claimToken: booking.data.bookingClaim } })).status, 409);
    assert.equal((await api('/bookings/claim', { method: 'POST', token: account.data.accessToken, body: { claimToken: 'not-a-real-claim' } })).status, 400);
    const expired = await book(3); sql(`UPDATE booking_claims SET expires_at=now()-interval '1 minute' WHERE ticket_id='${expired.data.ticket.id}'`);
    assert.equal((await register({ ...anonymous(3), claimToken: expired.data.bookingClaim })).status, 409);
  });
  await t.test('compte existant : login email ou téléphone rattache uniquement le claim', async () => {
    const existing = { firstName: 'Compte', lastName: 'Existant', contactPhone: '+261341234567', email: `existing-${suffix}@example.mg` };
    const account = await register(existing); assert.equal(account.status, 201);
    const booking = await book(4);
    const loginEmail = await api('/auth/customer-login', { method: 'POST', body: { identifier: existing.email, password: 'password123' }, ip: '203.0.113.201' }); assert.equal(loginEmail.status, 200);
    assert.equal((await api('/bookings/claim', { method: 'POST', token: loginEmail.data.accessToken, body: { claimToken: booking.data.bookingClaim } })).status, 200);
    const profile = await api('/auth/me', { token: loginEmail.data.accessToken }); assert.ok(profile.data.tickets.some(ticket => ticket.id === booking.data.ticket.id));
    const loginPhone = await api('/auth/customer-login', { method: 'POST', body: { identifier: '0341234567', password: 'password123' }, ip: '203.0.113.202' }); assert.equal(loginPhone.status, 200);
  });
  await t.test('collision et historique : aucun merge automatique', async () => {
    const first = await register({ firstName: 'A', lastName: 'A', contactPhone: '+261331234567', email: `a-${suffix}@example.mg` }); assert.equal(first.status, 201);
    assert.equal((await register({ firstName: 'B', lastName: 'B', contactPhone: '+261371234567', email: `a-${suffix}@example.mg` })).status, 409);
    const old = await book(5, { contactPhone: '+261321234567', email: `old-${suffix}@example.mg` }); const fresh = await book(6, { contactPhone: '+261321234567', email: `old-${suffix}@example.mg` });
    const linked = await register({ ...anonymous(6, { contactPhone: '+261321234567', email: `old-${suffix}@example.mg` }), claimToken: fresh.data.bookingClaim }); assert.equal(linked.status, 201);
    assert.equal(sql(`SELECT count(*) FROM tickets t JOIN customers c ON c.id=t.customer_id WHERE c.user_id=(SELECT user_id FROM customers WHERE id='${linked.data.user.user.id}') AND t.id='${old.data.ticket.id}'`), '0');
  });
});
