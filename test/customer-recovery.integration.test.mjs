import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const db = process.env.MMS_TEST_DB_CONTAINER || 'mms-b1-test-db-1';
const suffix = randomUUID().slice(0, 8);
const message = 'Votre demande a bien été prise en compte. Si un espace MMS correspond à ces informations, notre équipe pourra vous contacter.';

async function api(path, body, ip) {
  const response = await fetch(`${base}/api${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Real-IP': ip }, body: JSON.stringify(body) });
  return { status: response.status, data: await response.json() };
}
function recovery(identifier, ip) { return api('/auth/recovery-request', { identifier }, ip); }
function sql(query) {
  assert.equal(execFileSync('docker', ['exec', db, 'psql', '-U', 'mms_test', '-d', 'mms_test', '-At', '-c', 'SELECT current_database()'], { encoding: 'utf8' }).trim(), 'mms_test');
  return execFileSync('docker', ['exec', db, 'psql', '-U', 'mms_test', '-d', 'mms_test', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query], { encoding: 'utf8' }).trim();
}
function publicResponse(result) {
  assert.equal(result.status, 200);
  assert.deepEqual(result.data, { message });
  assert.equal(Object.keys(result.data).length, 1);
}

test('B3.1 récupération publique sans énumération et avec limites', async t => {
  const email = `recovery-${suffix}@example.mg`;
  const phone = '+261341234569';
  const registered = await api('/auth/customer-register', { firstName: 'Aina', lastName: 'Recette', phone, email, password: 'password123' }, '198.51.100.61');
  assert.equal(registered.status, 201);

  await t.test('anti-énumération email existant et absent', async () => {
    const known = await recovery(email, '198.51.100.62');
    const unknown = await recovery(`unknown-${suffix}@example.mg`, '198.51.100.63');
    publicResponse(known); publicResponse(unknown); assert.deepEqual(known, unknown);
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE identifier_normalized='${email}' AND user_id IS NOT NULL AND customer_id IS NOT NULL AND status='pending'`), '1');
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE identifier_normalized='unknown-${suffix}@example.mg' AND user_id IS NULL AND customer_id IS NULL AND status='pending'`), '1');
  });
  await t.test('anti-énumération téléphone existant et absent', async () => {
    const known = await recovery('0341234569', '198.51.100.64');
    const unknown = await recovery('0347654321', '198.51.100.65');
    publicResponse(known); publicResponse(unknown); assert.deepEqual(known, unknown);
  });
  await t.test('normalisation email et téléphone, déduplication pending', async () => {
    publicResponse(await recovery(`  RECOVERY-${suffix}@EXAMPLE.MG  `, '198.51.100.66'));
    publicResponse(await recovery('+261341234569', '198.51.100.67'));
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE identifier_normalized='${email}' AND status='pending'`), '1');
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE identifier_normalized='${phone}' AND status='pending'`), '1');
    assert.equal(sql(`SELECT identifier_masked FROM customer_access_requests WHERE identifier_normalized='${phone}'`), '034 ** *** **');
  });
  await t.test('trois appels par identifiant puis 429 sur variantes normalisées', async () => {
    const e = `limit-${suffix}@example.mg`;
    for (const [index, value] of [e, e.toUpperCase(), ` ${e} `].entries()) publicResponse(await recovery(value, `198.51.100.${70 + index}`));
    const limitedEmail = await recovery(e, '198.51.100.73');
    assert.equal(limitedEmail.status, 429); assert.match(limitedEmail.data.error, /Trop de demandes/);
    const p = ['0341234568', '+261341234568', '0341234568'];
    for (const [index, value] of p.entries()) publicResponse(await recovery(value, `198.51.100.${80 + index}`));
    const limitedPhone = await recovery('+261341234568', '198.51.100.83');
    assert.equal(limitedPhone.status, 429); assert.match(limitedPhone.data.error, /Trop de demandes/);
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE identifier_normalized='${e}' AND status='pending'`), '1');
  });
  await t.test('cinquième demande par IP acceptée, sixième limitée', async () => {
    const ip = '198.51.100.90';
    for (let index = 0; index < 5; index++) publicResponse(await recovery(`ip-${suffix}-${index}@example.mg`, ip));
    const limited = await recovery(`ip-${suffix}-5@example.mg`, ip);
    assert.equal(limited.status, 429); assert.match(limited.data.error, /Trop de demandes/);
  });
});
