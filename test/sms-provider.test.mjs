import test from 'node:test';
import assert from 'node:assert/strict';
import { createSmsProvider, SmsProviderError } from '../src/sms-provider.ts';

const message = { challengeId: 'challenge-test', phone: '+261341234567', code: '012345' };
const env = { SMS_PROVIDER: 'orange', ORANGE_CLIENT_ID: 'test-id', ORANGE_CLIENT_SECRET: 'test-secret', ORANGE_COUNTRY_SENDER: 'tel:+2610000' };
const response = (status, data = {}) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
const token = (value, expiresIn = '3600') => response(200, { access_token: value, token_type: 'Bearer', expires_in: expiresIn });
const calls = [];
function mockFetch(sequence) {
  return async (url, options) => {
    calls.push({ url, options });
    const next = sequence.shift();
    assert.ok(next, `Appel HTTP inattendu vers ${url}`);
    return typeof next === 'function' ? next(url, options) : next;
  };
}
function orange(sequence, now = () => 0, overrides = {}) {
  calls.length = 0;
  return createSmsProvider({ ...env, ...overrides }, { fetchFn: mockFetch(sequence), now });
}
function assertNoSecrets(error) {
  assert.ok(error instanceof SmsProviderError);
  assert.doesNotMatch(String(error), /test-secret|test-token|012345|261341234567/);
  return true;
}

test('OAuth puis envoi Orange au format officiel, sans senderName vide', async () => {
  const provider = orange([token('test-token'), response(201, { outboundSMSMessageRequest: {} })]);
  await provider.sendOtp(message);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, 'https://api.orange.com/oauth/v3/token');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.body, 'grant_type=client_credentials');
  assert.equal(calls[0].options.headers.Authorization, `Basic ${Buffer.from('test-id:test-secret').toString('base64')}`);
  assert.equal(calls[0].options.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.ok(calls[0].options.signal);
  assert.equal(calls[1].url, 'https://api.orange.com/smsmessaging/v1/outbound/tel%3A%2B2610000/requests');
  assert.equal(calls[1].options.headers.Authorization, 'Bearer test-token');
  assert.deepEqual(JSON.parse(calls[1].options.body), { outboundSMSMessageRequest: {
    address: 'tel:+261341234567', senderAddress: 'tel:+2610000',
    outboundSMSTextMessage: { message: 'Votre code MMS est 012345. Il expire dans 5 minutes.' },
  } });
});

test('senderName optionnel est inclus seulement si non vide', async () => {
  const provider = orange([token('test-token'), response(201)], () => 0, { ORANGE_SENDER_NAME: 'MMS' });
  await provider.sendOtp(message);
  assert.equal(JSON.parse(calls[1].options.body).outboundSMSMessageRequest.senderName, 'MMS');
});

test('token réutilisé et une seule requête OAuth pour des envois concurrents', async () => {
  const provider = orange([token('test-token'), response(201), response(201), response(201)]);
  await Promise.all([provider.sendOtp(message), provider.sendOtp(message)]);
  await provider.sendOtp(message);
  assert.equal(calls.filter(call => call.url.endsWith('/oauth/v3/token')).length, 1);
  assert.equal(calls.length, 4);
});

test('token renouvelé avant expiration', async () => {
  let currentTime = 0;
  const provider = orange([token('test-token', 120), response(201), token('renewed-token', 120), response(201)], () => currentTime);
  await provider.sendOtp(message);
  currentTime = 61_000;
  await provider.sendOtp(message);
  assert.equal(calls.filter(call => call.url.endsWith('/oauth/v3/token')).length, 2);
  assert.equal(calls[3].options.headers.Authorization, 'Bearer renewed-token');
});

test('401 Expired credentials renouvelle puis retente une seule fois', async () => {
  const provider = orange([token('test-token'), response(401, { code: 42, message: 'Expired credentials' }), token('renewed-token'), response(201)]);
  await provider.sendOtp(message);
  assert.equal(calls.length, 4);
  assert.equal(calls[3].options.headers.Authorization, 'Bearer renewed-token');
});

test('401 autre que Expired credentials ne retente pas', async () => {
  const provider = orange([token('test-token'), response(401, { code: 41, message: 'Invalid credentials' })]);
  await assert.rejects(provider.sendOtp(message), error => assertNoSecrets(error) && error.status === 401);
  assert.equal(calls.length, 2);
});

for (const status of [400, 500]) {
  test(`erreur Orange ${status} masquée et sans nouvel envoi`, async () => {
    const provider = orange([token('test-token'), response(status, { message: 'Sensitive upstream detail' })]);
    await assert.rejects(provider.sendOtp(message), error => assertNoSecrets(error) && error.phase === 'send' && error.status === status);
    assert.equal(calls.length, 2);
  });
}

test('réponse SMS perdue ou timeout : aucun retry aveugle', async () => {
  const provider = orange([token('test-token'), () => { throw new Error('network lost with secret test-secret'); }]);
  await assert.rejects(provider.sendOtp(message), error => assertNoSecrets(error) && error.phase === 'send');
  assert.equal(calls.length, 2);
});

test('erreur OAuth masquée, sans tentative d’envoi', async () => {
  const provider = orange([response(500, { message: 'test-secret' })]);
  await assert.rejects(provider.sendOtp(message), error => assertNoSecrets(error) && error.phase === 'oauth' && error.status === 500);
  assert.equal(calls.length, 1);
});

test('credentials Orange absents refusés dès la création du provider', () => {
  assert.throws(() => createSmsProvider({ SMS_PROVIDER: 'orange' }), /ORANGE_CLIENT_ID et ORANGE_CLIENT_SECRET sont requis/);
  assert.throws(() => createSmsProvider({ ...env, ORANGE_CLIENT_SECRET: '' }), /ORANGE_CLIENT_ID et ORANGE_CLIENT_SECRET sont requis/);
});

test('console ne fait aucun appel Orange et conserve son outbox', async () => {
  const writes = []; const logs = [];
  const provider = createSmsProvider({ SMS_PROVIDER: 'console', MMS_TEST_MODE: '1' }, {
    fetchFn: () => { throw new Error('Orange ne doit pas être appelé'); },
    writeOtp: async (...args) => { writes.push(args); },
    log: value => logs.push(value),
  });
  await provider.sendOtp(message);
  assert.deepEqual(writes, [['/tmp/mms-test-otp-challenge-test', '012345', { mode: 0o600 }]]);
  assert.deepEqual(logs, ['MMS test OTP issued for challenge challenge-test']);
  assert.throws(() => createSmsProvider({ SMS_PROVIDER: 'console' }), /réservé au mode test/);
});
