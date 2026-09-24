export type FacebookConfig = {
  appId: string;
  appSecret: string;
  callbackUrl: string;
  dialogUrl: string;
  tokenUrl: string;
  profileUrl: string;
};

export type FacebookProfile = {
  id: string;
  name: string;
  email: string | null;
};

export class FacebookOAuthError extends Error {
  constructor(public phase: 'configuration' | 'token' | 'profile', public status?: number) {
    super('Facebook Login est temporairement indisponible.');
  }
}

export function facebookConfig(env: NodeJS.ProcessEnv): FacebookConfig | null {
  const appId = env.FACEBOOK_APP_ID?.trim();
  const appSecret = env.FACEBOOK_APP_SECRET?.trim();
  const callbackUrl = env.FACEBOOK_CALLBACK_URL?.trim();
  if (!appId && !appSecret && !callbackUrl) return null;
  if (!appId || !appSecret || !callbackUrl) throw new FacebookOAuthError('configuration');
  const testMode = env.MMS_TEST_MODE === '1';
  return {
    appId,
    appSecret,
    callbackUrl,
    dialogUrl: testMode && env.FACEBOOK_DIALOG_URL ? env.FACEBOOK_DIALOG_URL : 'https://www.facebook.com/dialog/oauth',
    tokenUrl: testMode && env.FACEBOOK_TOKEN_URL ? env.FACEBOOK_TOKEN_URL : 'https://graph.facebook.com/oauth/access_token',
    profileUrl: testMode && env.FACEBOOK_PROFILE_URL ? env.FACEBOOK_PROFILE_URL : 'https://graph.facebook.com/me',
  };
}

export function facebookAuthorizationUrl(config: FacebookConfig, state: string) {
  const url = new URL(config.dialogUrl);
  url.searchParams.set('client_id', config.appId);
  url.searchParams.set('redirect_uri', config.callbackUrl);
  url.searchParams.set('state', state);
  url.searchParams.set('scope', 'public_profile,email');
  url.searchParams.set('response_type', 'code');
  return url.toString();
}

async function safeJson(response: Response): Promise<Record<string, unknown>> {
  try {
    const value: unknown = await response.json();
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch { return {}; }
}

export async function fetchFacebookProfile(
  config: FacebookConfig,
  code: string,
  fetcher: typeof fetch = fetch,
  timeoutMs = 8_000,
): Promise<FacebookProfile> {
  let accessToken = '';
  try {
    const tokenResponse = await fetcher(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({ client_id: config.appId, client_secret: config.appSecret, redirect_uri: config.callbackUrl, code }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const tokenBody = await safeJson(tokenResponse);
    if (!tokenResponse.ok || typeof tokenBody.access_token !== 'string' || !tokenBody.access_token) {
      throw new FacebookOAuthError('token', tokenResponse.status);
    }
    accessToken = tokenBody.access_token;
  } catch (error) {
    if (error instanceof FacebookOAuthError) throw error;
    throw new FacebookOAuthError('token');
  }

  try {
    const profileUrl = new URL(config.profileUrl);
    profileUrl.searchParams.set('fields', 'id,name,email');
    const profileResponse = await fetcher(profileUrl, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const profile = await safeJson(profileResponse);
    if (!profileResponse.ok || typeof profile.id !== 'string' || !profile.id || typeof profile.name !== 'string' || !profile.name) {
      throw new FacebookOAuthError('profile', profileResponse.status);
    }
    return {
      id: profile.id,
      name: profile.name,
      email: typeof profile.email === 'string' && profile.email.trim() ? profile.email.trim().toLowerCase() : null,
    };
  } catch (error) {
    if (error instanceof FacebookOAuthError) throw error;
    throw new FacebookOAuthError('profile');
  }
}
