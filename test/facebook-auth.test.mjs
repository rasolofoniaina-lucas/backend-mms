import test from 'node:test';
import assert from 'node:assert/strict';
import { FacebookOAuthError, facebookAuthorizationUrl, facebookConfig, fetchFacebookProfile } from '../src/facebook-auth.ts';

const config = {
  appId: 'app-123', appSecret: 'top-secret-value', callbackUrl: 'https://mms.mg/api/auth/facebook/callback',
  dialogUrl: 'https://facebook.example/dialog', tokenUrl: 'https://facebook.example/token', profileUrl: 'https://facebook.example/me',
};

test('Facebook OAuth construit une URL avec state et permissions minimales', () => {
  const url = new URL(facebookAuthorizationUrl(config, 'state-value'));
  assert.equal(url.origin + url.pathname, config.dialogUrl);
  assert.equal(url.searchParams.get('client_id'), config.appId);
  assert.equal(url.searchParams.get('redirect_uri'), config.callbackUrl);
  assert.equal(url.searchParams.get('state'), 'state-value');
  assert.equal(url.searchParams.get('scope'), 'public_profile,email');
  assert.equal(url.searchParams.get('response_type'), 'code');
});

test('Facebook OAuth refuse une configuration partielle et accepte une absence complète', () => {
  assert.equal(facebookConfig({}), null);
  assert.throws(() => facebookConfig({ FACEBOOK_APP_ID: 'only-id' }), error => error instanceof FacebookOAuthError && error.phase === 'configuration');
});

test('Facebook OAuth échange le code puis lit le profil via deux appels HTTP simulés', async () => {
  const calls = [];
  const fetcher = async (input, init = {}) => {
    calls.push({ url: String(input), init });
    if (calls.length === 1) return new Response(JSON.stringify({ access_token: 'transient-token' }), { status: 200 });
    return new Response(JSON.stringify({ id: 'facebook-42', name: 'Aina Rakoto', email: 'AINA@EXAMPLE.MG' }), { status: 200 });
  };
  const profile = await fetchFacebookProfile(config, 'one-time-code', fetcher);
  assert.deepEqual(profile, { id: 'facebook-42', name: 'Aina Rakoto', email: 'aina@example.mg' });
  assert.equal(calls.length, 2);
  assert.match(String(calls[0].init.body), /code=one-time-code/);
  assert.equal(calls[1].init.headers.Authorization, 'Bearer transient-token');
  assert.equal(new URL(calls[1].url).searchParams.get('fields'), 'id,name,email');
  assert.equal(calls[1].url.includes('transient-token'), false);
});

test('Facebook OAuth accepte un profil sans email sans en fabriquer', async () => {
  let call = 0;
  const fetcher = async () => ++call === 1
    ? new Response(JSON.stringify({ access_token: 'short-lived' }), { status: 200 })
    : new Response(JSON.stringify({ id: 'facebook-no-email', name: 'Solo' }), { status: 200 });
  assert.deepEqual(await fetchFacebookProfile(config, 'code', fetcher), { id: 'facebook-no-email', name: 'Solo', email: null });
});

test('Facebook OAuth mappe les erreurs sans exposer secret, code ou jeton', async () => {
  const tokenFailure = async () => new Response(JSON.stringify({ error: { message: 'top-secret-value one-time-code' } }), { status: 400 });
  await assert.rejects(() => fetchFacebookProfile(config, 'one-time-code', tokenFailure), error => {
    assert.ok(error instanceof FacebookOAuthError); assert.equal(error.phase, 'token');
    assert.equal(String(error).includes(config.appSecret), false); assert.equal(String(error).includes('one-time-code'), false); return true;
  });
  let call = 0;
  const profileFailure = async () => ++call === 1
    ? new Response(JSON.stringify({ access_token: 'private-token' }), { status: 200 })
    : new Response(JSON.stringify({ error: { message: 'private-token' } }), { status: 500 });
  await assert.rejects(() => fetchFacebookProfile(config, 'code', profileFailure), error => {
    assert.ok(error instanceof FacebookOAuthError); assert.equal(error.phase, 'profile');
    assert.equal(String(error).includes('private-token'), false); return true;
  });
});
