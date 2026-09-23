import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomInt, randomUUID } from 'node:crypto';

const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const db = process.env.MMS_TEST_DB_CONTAINER || 'mms-b1-test-db-1';
const suffix = randomUUID().slice(0, 8);
const phoneNumber = randomInt(1_000_000, 9_999_990);
const phone = `+26134${phoneNumber}`;
const email = `reset-${suffix}@example.mg`;

async function api(path, { method = 'GET', body, token, cookie } = {}) {
  const response = await fetch(`${base}/api${path}`, { method, headers: {
    'X-Real-IP': '198.51.100.201',
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
const reset = (userId, token, requestId) => api(`/staff/customers/${userId}/reset-password`, { method: 'POST', token, body: requestId ? { requestId } : {} });
const login = (identifier, password) => api('/auth/customer-login', { method: 'POST', body: { identifier, password } });
const recovery = identifier => api('/auth/recovery-request', { method: 'POST', body: { identifier } });

export async function runCustomerPasswordResetTests(t, { admin, manager, mechanic, mechanicUser }) {
  await t.test('B3.2 reset client transactionnel par staff', async t => {
  const originalPassword = 'Original-password-123';
  const registered = await api('/auth/customer-register', { method: 'POST', body: { firstName: 'Aina', lastName: 'Reset', phone, email, password: originalPassword } });
  assert.equal(registered.status, 201);
  const userId = sql(`SELECT user_id FROM customers WHERE id='${registered.data.user.user.id}'`);
  const sessionA = registered;
  const sessionB = await login(email, originalPassword);
  assert.equal(sessionB.status, 200);
  const path = `/staff/customers/${userId}/reset-password`;

  await t.test('RBAC admin/chef et refus mechanic/client/anonyme', async () => {
    assert.equal((await reset(userId, mechanic.data.accessToken)).status, 403);
    assert.equal((await reset(userId, sessionA.data.accessToken)).status, 403);
    assert.equal((await reset(userId)).status, 401);
    assert.equal((await api(`/staff/customers/${mechanicUser.id}/reset-password`, { method: 'POST', token: admin.data.accessToken, body: {} })).status, 404);
    assert.equal((await api(path, { token: admin.data.accessToken })).status, 404);
    assert.equal((await api('/staff/access-requests', { token: manager.data.accessToken })).status, 200);
  });

  const created = await recovery(email);
  assert.equal(created.status, 200);
  const requests = await api('/staff/access-requests', { token: admin.data.accessToken });
  const request = requests.data.find(item => item.userId === userId);
  assert.ok(request);

  let firstTemporary;
  let secondSession;
  await t.test('reset admin : hash Argon2id, expiration, sessions révoquées, audit et demande résolue', async () => {
    const result = await reset(userId, admin.data.accessToken, request.id);
    assert.equal(result.status, 200);
    firstTemporary = result.data.temporaryPassword;
    assert.match(firstTemporary, /^[A-Za-z0-9]{12,}$/);
    assert.deepEqual(Object.keys(result.data), ['temporaryPassword']);
    const credential = sql(`SELECT password_hash || '|' || must_change_password || '|' || round(extract(epoch FROM (temporary_password_expires_at-now()))/3600)::text || '|' || coalesce(password_changed_at::text,'NULL') FROM customer_credentials WHERE user_id='${userId}'`);
    const [digest, mustChange, hours, changedAt] = credential.split('|');
    assert.match(digest, /^\$argon2id\$/); assert.equal(mustChange, 'true'); assert.equal(hours, '24'); assert.equal(changedAt, 'NULL');
    assert.equal(credential.includes(firstTemporary), false);
    assert.equal(sql(`SELECT status || '|' || (resolved_at IS NOT NULL) || '|' || resolved_by_user_id FROM customer_access_requests WHERE id='${request.id}'`), `resolved|true|${admin.data.user.id}`);
    assert.equal((await api('/staff/access-requests', { token: admin.data.accessToken })).data.some(item => item.id === request.id), false);
    assert.equal(sql(`SELECT count(*) FROM user_sessions WHERE user_id='${userId}' AND revoked_at IS NULL`), '0');
    for (const session of [sessionA, sessionB]) {
      assert.equal((await api('/auth/me', { token: session.data.accessToken })).status, 401);
      assert.equal((await api('/auth/refresh', { method: 'POST', body: {}, cookie: session.cookie })).status, 401);
    }
    assert.equal((await api('/staff/me', { token: admin.data.accessToken })).status, 200);
    assert.equal((await api('/staff/me', { token: manager.data.accessToken })).status, 200);
    assert.equal((await login(email, originalPassword)).status, 401);
    assert.equal((await login(email, firstTemporary)).status, 200);
    const audit = sql(`SELECT row_to_json(a)::text FROM admin_audit_events a WHERE action='customer_password_reset' AND target_user_id='${userId}' ORDER BY id DESC LIMIT 1`);
    assert.match(audit, /customer_password_reset/); assert.match(audit, new RegExp(admin.data.user.id)); assert.match(audit, new RegExp(userId));
    assert.match(audit, new RegExp(request.id)); assert.match(audit, /created_at/);
    assert.equal(audit.includes(firstTemporary), false); assert.equal(audit.includes(digest), false);
    assert.equal(/password_hash|refresh_token|secret|credential/i.test(audit), false);
  });

  await t.test('reset chef depuis une autre demande, puis second reset invalide le premier', async () => {
    assert.equal((await recovery(phone)).status, 200);
    const pending = (await api('/staff/access-requests', { token: manager.data.accessToken })).data.find(item => item.userId === userId);
    assert.ok(pending);
    const second = await reset(userId, manager.data.accessToken, pending.id);
    assert.equal(second.status, 200);
    assert.notEqual(second.data.temporaryPassword, firstTemporary);
    assert.equal((await login(email, firstTemporary)).status, 401);
    secondSession = await login(email, second.data.temporaryPassword);
    assert.equal(secondSession.status, 200);
    assert.equal(sql(`SELECT status || '|' || resolved_by_user_id FROM customer_access_requests WHERE id='${pending.id}'`), `resolved|${manager.data.user.id}`);
    assert.equal(sql(`SELECT count(*) FROM admin_audit_events WHERE action='customer_password_reset' AND target_user_id='${userId}'`), '2');
    assert.equal(sql(`SELECT count(*) FROM admin_audit_events WHERE request_id='${pending.id}' AND actor_user_id='${manager.data.user.id}'`), '1');
  });

  await t.test('reset direct crée les credentials manquants sans fausse demande', async () => {
    const legacyPhone = `+26134${phoneNumber + 1}`;
    const legacy = await api('/admin/users', { method: 'POST', token: admin.data.accessToken, body: { firstName: 'Ancien', lastName: 'Client', phone: legacyPhone, role: 'customer' } });
    assert.equal(legacy.status, 201);
    assert.equal(sql(`SELECT count(*) FROM customer_credentials WHERE user_id='${legacy.data.id}'`), '0');
    const before = sql(`SELECT count(*) FROM customer_access_requests WHERE user_id='${legacy.data.id}'`);
    const direct = await reset(legacy.data.id, admin.data.accessToken);
    assert.equal(direct.status, 200);
    assert.equal((await login(legacyPhone, direct.data.temporaryPassword)).status, 200);
    assert.equal(sql(`SELECT count(*) FROM customer_access_requests WHERE user_id='${legacy.data.id}'`), before);
    assert.equal(sql(`SELECT request_id IS NULL FROM admin_audit_events WHERE target_user_id='${legacy.data.id}' AND action='customer_password_reset'`), 't');
  });

  await t.test('demande incohérente provoque rollback complet', async () => {
    const before = sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`);
    const audits = sql(`SELECT count(*) FROM admin_audit_events WHERE target_user_id='${userId}' AND action='customer_password_reset'`);
    const invalid = await reset(userId, admin.data.accessToken, randomUUID());
    assert.equal(invalid.status, 409);
    assert.equal(sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`), before);
    assert.equal(sql(`SELECT count(*) FROM admin_audit_events WHERE target_user_id='${userId}' AND action='customer_password_reset'`), audits);
  });

  await t.test('échec tardif de l’audit annule credentials, révocation et résolution', async () => {
    assert.equal((await recovery(email)).status, 200);
    const pending = (await api('/staff/access-requests', { token: admin.data.accessToken })).data.find(item => item.userId === userId && item.emailMasked);
    assert.ok(pending);
    const beforeHash = sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`);
    const beforeAudits = sql(`SELECT count(*) FROM admin_audit_events WHERE target_user_id='${userId}' AND action='customer_password_reset'`);
    const functionName = `fail_customer_reset_audit_${suffix}`;
    const triggerName = `fail_customer_reset_audit_${suffix}`;
    sql(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced mms_test audit failure'; END $$`);
    sql(`CREATE TRIGGER ${triggerName} BEFORE INSERT ON admin_audit_events FOR EACH ROW WHEN (NEW.action='customer_password_reset') EXECUTE FUNCTION ${functionName}()`);
    try {
      assert.equal((await reset(userId, admin.data.accessToken, pending.id)).status, 500);
      assert.equal(sql(`SELECT password_hash FROM customer_credentials WHERE user_id='${userId}'`), beforeHash);
      assert.equal(sql(`SELECT status FROM customer_access_requests WHERE id='${pending.id}'`), 'pending');
      assert.equal(sql(`SELECT count(*) FROM admin_audit_events WHERE target_user_id='${userId}' AND action='customer_password_reset'`), beforeAudits);
      assert.equal((await api('/auth/me', { token: secondSession.data.accessToken })).status, 200);
      assert.equal((await api('/auth/refresh', { method: 'POST', body: {}, cookie: secondSession.cookie })).status, 200);
    } finally {
      sql(`DROP TRIGGER ${triggerName} ON admin_audit_events`);
      sql(`DROP FUNCTION ${functionName}()`);
    }
  });

  await t.test('compte désactivé reste désactivé après reset', async () => {
    assert.equal((await api(`/admin/users/${userId}/status`, { method: 'PATCH', token: admin.data.accessToken, body: { status: 'disabled' } })).status, 200);
    const result = await reset(userId, admin.data.accessToken);
    assert.equal(result.status, 200);
    assert.equal(sql(`SELECT status FROM users WHERE id='${userId}'`), 'disabled');
    assert.equal((await login(email, result.data.temporaryPassword)).status, 401);
    assert.equal(sql(`SELECT must_change_password FROM customer_credentials WHERE user_id='${userId}'`), 't');
  });
  });
}
