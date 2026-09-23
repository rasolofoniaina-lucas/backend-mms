import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomInt, randomUUID } from 'node:crypto';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const db = process.env.MMS_TEST_DB_CONTAINER || 'mms-b1-test-db-1';
const suffix = randomUUID().slice(0, 8);
const phoneNumber = randomInt(1_000_000, 9_999_980);
const phone = offset => `+26134${phoneNumber + offset}`;
const email = `change-${suffix}@example.mg`;

async function api(path, { method = 'GET', body, token, cookie } = {}) {
  const response = await fetch(`${base}/api${path}`, { method, headers: {
    'X-Real-IP': '198.51.100.202',
    ...(body ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(cookie ? { Cookie: cookie } : {}),
  }, body: body ? JSON.stringify(body) : undefined });
  return { status: response.status, data: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
function sql(query) {
  assert.equal(execFileSync('docker', ['exec', db, 'psql', '-U', 'mms_test', '-d', 'mms_test', '-At', '-c', 'SELECT current_database()'], { encoding: 'utf8' }).trim(), 'mms_test');
  return execFileSync('docker', ['exec', db, 'psql', '-U', 'mms_test', '-d', 'mms_test', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query], { encoding: 'utf8' }).trim();
}
const reset = (userId, token) => api(`/staff/customers/${userId}/reset-password`, { method: 'POST', token, body: {} });
const login = (identifier, password) => api('/auth/customer-login', { method: 'POST', body: { identifier, password } });
const refresh = cookie => api('/auth/refresh', { method: 'POST', body: {}, cookie });
const change = (token, newPassword) => api('/auth/change-password', { method: 'POST', token, body: { newPassword } });

export async function runCustomerPasswordChangeTests(t, { admin, manager }) {
  await t.test('B3.3 changement obligatoire du mot de passe client', async t => {
    const original = 'Original-password-123';
    const registered = await api('/auth/customer-register', { method: 'POST', body: { firstName: 'Aina', lastName: 'Changement', phone: phone(0), email, password: original } });
    assert.equal(registered.status, 201);
    const customerId = registered.data.user.user.id;
    const userId = sql(`SELECT user_id FROM customers WHERE id='${customerId}'`);
    const firstReset = await reset(userId, admin.data.accessToken);
    assert.equal(firstReset.status, 200);
    let restricted;
    let temporaryPassword;
    let latest;
    let latestPassword;

    await t.test('login temporaire restreint et ancien contexte révoqué', async () => {
      assert.equal((await api('/auth/me', { token: registered.data.accessToken })).status, 401);
      assert.equal((await refresh(registered.cookie)).status, 401);
      const temporary = await login(email, firstReset.data.temporaryPassword);
      assert.equal(temporary.status, 200);
      assert.equal(temporary.data.mustChangePassword, true);
      assert.deepEqual(temporary.data.user, { user: { id: customerId }, mustChangePassword: true });
      const me = await api('/auth/me', { token: temporary.data.accessToken });
      assert.equal(me.status, 200); assert.deepEqual(me.data, { user: { id: customerId }, mustChangePassword: true });
      assert.equal(JSON.stringify(me.data).includes('password_hash'), false);
      const rotated = await refresh(temporary.cookie);
      assert.equal(rotated.status, 200); assert.equal(rotated.data.mustChangePassword, true);
      assert.deepEqual(rotated.data.user, temporary.data.user);
      assert.equal((await api('/auth/me', { token: temporary.data.accessToken })).status, 401);
      assert.equal((await refresh(temporary.cookie)).status, 401);
      restricted = rotated;
    });

    await t.test('garde backend : toutes les API métier client restent interdites', async () => {
      const blocked = [
        ['/customers/' + customerId, {}],
        [`/customers/${customerId}/tickets/MMS-2026-000001`, {}],
        [`/customers/${customerId}/vehicles`, { method: 'POST', body: { name: 'Yamaha', displacementCc: 125, year: 2024 } }],
        [`/customers/${customerId}/appointments`, { method: 'POST', body: {} }],
        [`/customers/${customerId}/messages`, { method: 'POST', body: { message: 'Test' } }],
        ['/auth/sessions', {}],
        ['/auth/phone-change/request-otp', { method: 'POST', body: { phone: phone(7) } }],
        ['/bookings/claim', { method: 'POST', body: { token: 'invalid' } }],
        ['/bookings/complete', { method: 'POST', body: {} }],
      ];
      for (const [path, options] of blocked) {
        const result = await api(path, { ...options, token: restricted.data.accessToken });
        assert.equal(result.status, 403, path); assert.equal(result.data.code, 'PASSWORD_CHANGE_REQUIRED', path);
      }
      assert.equal((await change(restricted.data.accessToken, 'short')).status, 400);
      assert.equal((await change(restricted.data.accessToken, firstReset.data.temporaryPassword)).status, 400);
      assert.equal((await api('/auth/change-password', { method: 'POST', body: { newPassword: 'Valid-12345678' } })).status, 401);
      assert.equal((await api('/auth/change-password', { method: 'POST', token: admin.data.accessToken, body: { newPassword: 'Valid-12345678' } })).status, 403);
    });

    let normal;
    const nextPassword = 'Nouveau-mot-de-passe-123';
    await t.test('changement Argon2id et nouvelle session normale', async () => {
      const beforeHash = sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`);
      normal = await change(restricted.data.accessToken, nextPassword);
      assert.equal(normal.status, 200); assert.equal(normal.data.mustChangePassword, false);
      assert.equal(normal.data.user.user.id, customerId);
      assert.notEqual(normal.cookie, restricted.cookie);
      const credential = sql(`SELECT password_hash || '|' || must_change_password || '|' || (temporary_password_expires_at IS NULL) || '|' || (password_changed_at IS NOT NULL) FROM customer_credentials WHERE user_id='${userId}'`);
      const [hash, mustChange, noExpiry, changedAt] = credential.split('|');
      assert.match(hash, /^\$argon2id\$/); assert.notEqual(hash, beforeHash);
      assert.equal(mustChange, 'false'); assert.equal(noExpiry, 'true'); assert.equal(changedAt, 'true');
      assert.equal(credential.includes(nextPassword), false);
      assert.equal((await api('/auth/me', { token: restricted.data.accessToken })).status, 401);
      assert.equal((await refresh(restricted.cookie)).status, 401);
      assert.equal((await api('/auth/me', { token: normal.data.accessToken })).status, 200);
      assert.equal((await api(`/customers/${customerId}`, { token: normal.data.accessToken })).status, 200);
      assert.equal((await api('/auth/sessions', { token: normal.data.accessToken })).status, 200);
      const vehicle = await api(`/customers/${customerId}/vehicles`, { method: 'POST', token: normal.data.accessToken,
        body: { name: 'Yamaha', displacementCc: 125, year: 2024, model: 'MT-125', plate: '' } });
      assert.equal(vehicle.status, 201);
      const appointment = await api(`/customers/${customerId}/appointments`, { method: 'POST', token: normal.data.accessToken,
        body: { vehicleId: vehicle.data.id, problem: 'La moto ne démarre plus depuis ce matin.', diagnosis: '', kind: 'Urgence', address: 'Atelier MMS', contactPhone: phone(0), immobilized: true } });
      assert.equal(appointment.status, 201);
      assert.equal((await api(`/customers/${customerId}/tickets/${appointment.data.ticket.reference}`, { token: normal.data.accessToken })).status, 200);
      assert.equal((await login(email, firstReset.data.temporaryPassword)).status, 401);
      assert.equal((await login(email, original)).status, 401);
      assert.equal((await login(email, nextPassword)).status, 200);
      assert.equal((await refresh(normal.cookie)).status, 200);
    });

    await t.test('rollback si la nouvelle session ne peut pas être créée', async () => {
      const anotherReset = await reset(userId, manager.data.accessToken);
      assert.equal(anotherReset.status, 200);
      const temporary = await login(email, anotherReset.data.temporaryPassword);
      assert.equal(temporary.status, 200);
      const beforeHash = sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`);
      const functionName = `fail_customer_session_${suffix}`;
      const triggerName = `fail_customer_session_${suffix}`;
      sql(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced mms_test session failure'; END $$`);
      sql(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON user_sessions FOR EACH ROW WHEN (NEW.user_id='${userId}') EXECUTE FUNCTION ${functionName}()`);
      try {
        assert.equal((await change(temporary.data.accessToken, 'Autre-mot-de-passe-123')).status, 500);
        assert.equal(sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`), beforeHash);
        assert.equal(sql(`SELECT must_change_password FROM customer_credentials WHERE user_id='${userId}'`), 't');
        assert.equal((await api('/auth/me', { token: temporary.data.accessToken })).status, 200);
      } finally {
        sql(`DROP TRIGGER ${triggerName} ON user_sessions`);
        sql(`DROP FUNCTION ${functionName}()`);
      }
      assert.equal((await refresh(temporary.cookie)).status, 200);
      temporaryPassword = anotherReset.data.temporaryPassword;
    });

    await t.test('logout restreint puis second reset invalide le premier', async () => {
      const temp1 = temporaryPassword;
      const tempSession = await login(phone(0), temp1);
      assert.equal(tempSession.status, 200);
      assert.equal((await api('/auth/logout', { method: 'POST', body: {}, cookie: tempSession.cookie })).status, 200);
      assert.equal((await api('/auth/me', { token: tempSession.data.accessToken })).status, 401);
      const pending = await login(phone(0), temp1);
      assert.equal(pending.status, 200);
      const second = await reset(userId, admin.data.accessToken);
      assert.equal(second.status, 200);
      assert.equal((await api('/auth/me', { token: pending.data.accessToken })).status, 401);
      assert.equal((await refresh(pending.cookie)).status, 401);
      assert.equal((await login(phone(0), temp1)).status, 401);
      latest = await login(phone(0), second.data.temporaryPassword);
      assert.equal(latest.status, 200); assert.equal(latest.data.mustChangePassword, true);
      latestPassword = second.data.temporaryPassword;
    });

    await t.test('session courte peut terminer le changement après expiration, sans accès métier', async () => {
      const renewalAttempt = await login(phone(0), latestPassword);
      assert.equal(renewalAttempt.status, 200);
      sql(`UPDATE customer_credentials SET temporary_password_expires_at=now()-interval '1 minute' WHERE user_id='${userId}'`);
      assert.equal((await api(`/customers/${customerId}`, { token: latest.data.accessToken })).status, 403);
      assert.equal((await refresh(renewalAttempt.cookie)).status, 401);
      // The access session remains usable until its 15-minute expiry for this one action.
      const finished = await change(latest.data.accessToken, 'abcdefgh');
      assert.equal(finished.status, 200); assert.equal(finished.data.mustChangePassword, false);
      assert.equal((await login(phone(0), latestPassword)).status, 401);
      assert.equal((await login(email, 'abcdefgh')).status, 200);
    });

    await t.test('mot de passe temporaire expiré et compte désactivé refusés', async () => {
      const expired = await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Expire', lastName: 'Client', phone: phone(1), role: 'customer' } });
      assert.equal(expired.status, 201);
      const expiredReset = await reset(expired.data.id, admin.data.accessToken);
      assert.equal(expiredReset.status, 200);
      sql(`UPDATE customer_credentials SET temporary_password_expires_at=now()-interval '1 minute' WHERE user_id='${expired.data.id}'`);
      const denied = await login(phone(1), expiredReset.data.temporaryPassword);
      assert.equal(denied.status, 401); assert.match(denied.data.error, /expiré/);
      assert.equal(sql(`SELECT count(*) FROM user_sessions WHERE user_id='${expired.data.id}'`), '0');
      const disabled = await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Desactive', lastName: 'Client', phone: phone(2), role: 'customer' } });
      assert.equal(disabled.status, 201);
      assert.equal((await api(`/admin/users/${disabled.data.id}/status`, { method: 'PATCH', token: admin.data.accessToken, body: { status: 'disabled' } })).status, 200);
      const disabledReset = await reset(disabled.data.id, admin.data.accessToken);
      assert.equal(disabledReset.status, 200);
      assert.equal((await login(phone(2), disabledReset.data.temporaryPassword)).status, 401);
      assert.equal(sql(`SELECT status FROM users WHERE id='${disabled.data.id}'`), 'disabled');
    });
  });
}
