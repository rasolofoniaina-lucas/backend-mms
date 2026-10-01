import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const db = process.env.MMS_TEST_DB_CONTAINER || 'mms-b1-test-db-1';
const suffix = String(Date.now()).slice(-6);

function dateFor(weekday) {
  const date = new Date(); const delta = (weekday - date.getDay() + 7) % 7 || 7;
  // Local calendar date: toISOString() is UTC and shifts the day between 00:00 and 03:00 in Antananarivo.
  date.setDate(date.getDate() + delta); return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}
const monday = dateFor(1), tuesday = dateFor(2), wednesday = dateFor(3), thursday = dateFor(4), friday = dateFor(5), saturday = dateFor(6), sunday = dateFor(0);
async function api(path, { method = 'GET', body, ip = '198.51.100.10' } = {}) {
  const response = await fetch(`${base}/api${path}`, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), 'X-Real-IP': ip }, body: body ? JSON.stringify(body) : undefined });
  return { status: response.status, data: await response.json() };
}
function sql(query) {
  return execFileSync('docker', ['exec', '-i', db, 'psql', '-U', 'mms_test', '-d', 'mms_test', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query], { encoding: 'utf8' }).trim();
}
function booking(kind, index, overrides = {}) {
  const phone = `+26137${suffix.slice(0, 4)}${String(index).padStart(3, '0')}`;
  return { kind, date: kind === 'Urgence' ? undefined : monday, time: kind === 'Urgence' ? undefined : '08:00', address: kind === 'En atelier' ? '' : 'Analakely, Antananarivo', problem: 'La moto ne démarre plus depuis ce matin.', firstName: 'Test', lastName: `B1${index}`, email: `b1-${suffix}-${index}@example.mg`, contactPhone: phone, immobilized: kind === 'Urgence' ? true : undefined, vehicle: { name: 'Yamaha', model: 'MT-07', plate: '', displacementCc: 689, year: 2023 }, ...overrides };
}
async function create(kind, index, options = {}) { return api('/bookings/complete', { method: 'POST', body: booking(kind, index, options.overrides), ip: options.ip }); }

test('B1 booking anonyme, claims, concurrence, anti-abus et agenda', async t => {
  let atelier;
  await t.test('B1-01 atelier anonyme crée toutes les ressources attendues', async () => {
    atelier = await create('En atelier', 1); assert.equal(atelier.status, 201); assert.ok(atelier.data.bookingClaim);
    // The API intentionally does not expose customerId; assert the resource graph through ticket/claim joins instead.
    assert.equal(sql(`SELECT count(*) FROM tickets t JOIN vehicles v ON v.id=t.vehicle_id JOIN appointments a ON a.id=t.appointment_id JOIN ticket_events e ON e.ticket_id=t.id JOIN booking_claims c ON c.ticket_id=t.id WHERE t.id='${atelier.data.ticket.id}'`), '1');
  });
  await t.test('B1-02 domicile anonyme crée un rendez-vous avec adresse', async () => {
    const result = await create('À domicile', 2, { overrides: { date: tuesday, address: 'Lot II A 12, Antananarivo' } }); assert.equal(result.status, 201);
    assert.equal(sql(`SELECT address FROM appointments WHERE id='${result.data.appointmentId}'`), 'Lot II A 12, Antananarivo');
  });
  await t.test('B1-03 urgence anonyme ne crée pas de rendez-vous', async () => {
    const result = await create('Urgence', 3); assert.equal(result.status, 201); assert.equal(result.data.appointmentId, null);
    assert.equal(sql(`SELECT appointment_id IS NULL FROM tickets WHERE id='${result.data.ticket.id}'`), 't');
  });
  await t.test('B1-04 rollback ne laisse aucun état partiel si le slot est invalide', async () => {
    const failed = await create('En atelier', 4, { overrides: { time: '23:00' } }); assert.equal(failed.status, 409);
    assert.equal(sql(`SELECT count(*) FROM customers WHERE email='b1-${suffix}-4@example.mg'`), '0');
  });
  await t.test('B1-05 références ticket uniques et B1-06 customer sans user', async () => {
    const second = await create('En atelier', 5, { overrides: { date: wednesday } }); assert.equal(second.status, 201); assert.notEqual(atelier.data.ticket.reference, second.data.ticket.reference);
    assert.equal(sql(`SELECT c.user_id IS NULL FROM customers c JOIN tickets t ON t.customer_id=c.id WHERE t.id='${second.data.ticket.id}'`), 't');
  });
  await t.test('CLAIM-01..04 : brut renvoyé, HMAC seul, expiration 24h, consommation B2 absente', async () => {
    assert.match(atelier.data.bookingClaim, /^[A-Za-z0-9_-]{40,}$/);
    assert.equal(sql(`SELECT count(*) FROM booking_claims WHERE token_hash='${atelier.data.bookingClaim}'`), '0');
    assert.equal(sql(`SELECT count(*) FROM booking_claims WHERE ticket_id='${atelier.data.ticket.id}' AND token_hash <> '' AND expires_at BETWEEN now()+interval '23 hours 59 minutes' AND now()+interval '24 hours 1 minute'`), '1');
    assert.equal(sql(`SELECT count(*) FROM booking_claims WHERE ticket_id='${atelier.data.ticket.id}' AND consumed_at IS NULL`), '1');
  });
  await t.test('concurrence : un seul rendez-vous sur le même slot', async () => {
    const a = create('En atelier', 20, { overrides: { date: thursday }, ip: '198.51.100.20' });
    const b = create('En atelier', 21, { overrides: { date: thursday }, ip: '198.51.100.21' });
    const results = await Promise.all([a, b]); assert.deepEqual(results.map(x => x.status).sort(), [201, 409]);
    assert.equal(sql(`SELECT count(*) FROM appointments WHERE appointment_date='${thursday}' AND appointment_time='08:00'`), '1');
  });
  await t.test('rate limit téléphone normalisé et e-mail normalisé', async () => {
    const phone = '+261341234567'; const normalized = ['0341234567', phone, phone, phone];
    const phoneResults = [];
    for (let i = 0; i < normalized.length; i++) phoneResults.push(await create('Urgence', 30 + i, { ip: '198.51.100.30', overrides: { contactPhone: normalized[i], email: `phone-${i}@example.mg` } }));
    assert.deepEqual(phoneResults.map(x => x.status), [201, 201, 201, 429]);
    const emailResults = [];
    for (const [i, value] of ['Test@example.com', 'test@example.com', 'TEST@example.com', 'test@example.com'].entries()) emailResults.push(await create('Urgence', 40 + i, { ip: '198.51.100.40', overrides: { contactPhone: `+2613812345${i}7`, email: value } }));
    assert.deepEqual(emailResults.map(x => x.status), [201, 201, 201, 429]);
  });
  await t.test('rate limit IP bloque le sixième booking mais pas availability', async () => {
    const results = [];
    for (let i = 0; i < 6; i++) results.push(await create('Urgence', 50 + i, { ip: '198.51.100.50' }));
    assert.deepEqual(results.map(x => x.status), [201, 201, 201, 201, 201, 429]);
    assert.equal((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${monday}`, { ip: '198.51.100.50' })).status, 200);
  });
  await t.test('isolation historique : mêmes coordonnées, aucun rattachement automatique', async () => {
    const first = await create('Urgence', 70, { ip: '198.51.100.70', overrides: { contactPhone: '+261331234567', email: 'history@example.com' } });
    const second = await create('Urgence', 71, { ip: '198.51.100.71', overrides: { contactPhone: '+261331234567', email: 'history@example.com' } });
    assert.equal(first.status, 201); assert.equal(second.status, 201);
    assert.equal(sql(`SELECT count(DISTINCT customer_id) FROM tickets WHERE id IN ('${first.data.ticket.id}','${second.data.ticket.id}')`), '2');
  });
  await t.test('agenda : horaires, exception, blocage, réservation et capacité 1', async () => {
    assert.ok((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${monday}`)).data.slots.includes('08:00'));
    assert.ok((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${monday}`)).data.slots.includes('16:00'));
    assert.equal((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${saturday}`)).data.slots.at(-1), '12:00');
    assert.deepEqual((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${sunday}`)).data.slots, []);
    sql(`INSERT INTO workshop_schedule_exceptions(day,is_open,reason) VALUES('${friday}',false,'test')`);
    assert.deepEqual((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${friday}`)).data.slots, []);
    sql(`INSERT INTO blocked_slots(id,slot_date,slot_time,reason) VALUES('${randomUUID()}','${tuesday}','09:00','test')`);
    assert.ok((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${tuesday}`)).data.occupied.includes('09:00'));
    assert.ok((await api(`/availability?kind=${encodeURIComponent('En atelier')}&date=${monday}`)).data.occupied.includes('08:00'));
  });
});
