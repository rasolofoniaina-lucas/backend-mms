import { writeFile } from 'node:fs/promises';

export type OtpMessage = { challengeId: string; phone: string; code: string };
export interface SmsProvider { sendOtp(message: OtpMessage): Promise<void> }

export class SmsProviderError extends Error {
  constructor(public readonly phase: 'oauth' | 'send', public readonly status?: number) {
    super('Envoi SMS indisponible.');
  }
}

type SmsEnvironment = NodeJS.ProcessEnv;
type SmsDependencies = {
  fetchFn?: typeof fetch;
  now?: () => number;
  writeOtp?: typeof writeFile;
  log?: (message: string) => void;
  logOrange?: (event: OrangeSmsLogEvent) => void;
};

export type OrangeSmsLogEvent = {
  timestamp_utc: string;
  sms_provider: 'orange';
  recipient_masked: string;
  http_status: number | null;
  result: 'accepted' | 'failed';
  resource_id?: string | null;
  orange_error_code?: string | null;
  orange_error_message?: string;
};

function maskedRecipient(phone: string): string {
  return /^\+261\d{9}$/.test(phone) ? `${phone.slice(0, 6)}*****${phone.slice(-2)}` : 'invalid-recipient';
}

function orangeError(data: unknown): { code: string | null; message: string } {
  const detail = data && typeof data === 'object' ? data as Record<string, unknown> : {};
  const code = String(detail.code ?? '');
  const knownMessages = new Set([
    'Expired credentials', 'Invalid credentials', 'Missing credentials', 'Invalid URL parameter value',
    'Missing body', 'Invalid body', 'Missing body field', 'Invalid body field', 'Missing header',
    'Invalid header value', 'Access denied', 'Forbidden requester', 'Forbidden user',
    'Too many requests', 'Not enough credit', 'Internal error', 'Bad gateway',
  ]);
  return {
    code: /^\d{1,3}$/.test(code) ? code : null,
    // Orange may include user data in arbitrary messages: log only known fixed phrases.
    message: typeof detail.message === 'string' && knownMessages.has(detail.message) ? detail.message : 'unavailable',
  };
}

function orangeResourceId(data: unknown, location: string | null): string | null {
  const message = data && typeof data === 'object' ? (data as Record<string, unknown>).outboundSMSMessageRequest : undefined;
  const resourceUrl = message && typeof message === 'object' ? (message as Record<string, unknown>).resourceURL : undefined;
  for (const candidate of [resourceUrl, location]) {
    if (typeof candidate !== 'string') continue;
    try {
      const id = new URL(candidate).pathname.split('/').filter(Boolean).at(-1);
      if (id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return id;
    } catch { /* Ignore malformed upstream URLs. */ }
  }
  return null;
}

class ConsoleSmsProvider implements SmsProvider {
  constructor(private readonly writeOtp: typeof writeFile, private readonly log: (message: string) => void) {}

  async sendOtp({ challengeId, code }: OtpMessage): Promise<void> {
    // Test-only outbox. Never expose the code through HTTP or logs.
    await this.writeOtp(`/tmp/mms-test-otp-${challengeId}`, code, { mode: 0o600 });
    this.log(`MMS test OTP issued for challenge ${challengeId}`);
  }
}

class OrangeSmsProvider implements SmsProvider {
  private cachedToken: { value: string; expiresAt: number } | undefined;
  private tokenRequest: Promise<string> | undefined;
  private readonly smsUrl: string;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly sender: string,
    private readonly senderName: string,
    private readonly fetchFn: typeof fetch,
    private readonly now: () => number,
    private readonly logOrange: (event: OrangeSmsLogEvent) => void,
  ) {
    this.smsUrl = `https://api.orange.com/smsmessaging/v1/outbound/${encodeURIComponent(sender)}/requests`;
  }

  private emit(event: OrangeSmsLogEvent): void {
    try { this.logOrange(event); } catch { /* Observability must not change SMS delivery. */ }
  }

  private async token(): Promise<string> {
    if (this.cachedToken && this.now() < this.cachedToken.expiresAt) return this.cachedToken.value;
    if (!this.tokenRequest) {
      this.tokenRequest = this.fetchToken().finally(() => { this.tokenRequest = undefined; });
    }
    return this.tokenRequest;
  }

  private async fetchToken(): Promise<string> {
    let response: Response;
    try {
      response = await this.fetchFn('https://api.orange.com/oauth/v3/token', {
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: 'grant_type=client_credentials',
        signal: AbortSignal.timeout(8000),
        redirect: 'error',
      });
    } catch { throw new SmsProviderError('oauth'); }
    if (!response.ok) throw new SmsProviderError('oauth', response.status);
    const data: unknown = await response.json().catch(() => undefined);
    if (!data || typeof data !== 'object') throw new SmsProviderError('oauth', response.status);
    const token = (data as Record<string, unknown>).access_token;
    const expiresIn = Number((data as Record<string, unknown>).expires_in);
    if (typeof token !== 'string' || !token || !Number.isFinite(expiresIn) || expiresIn <= 0) {
      throw new SmsProviderError('oauth', response.status);
    }
    // Orange currently uses 3600 seconds. Refresh a minute early (or halfway for short-lived tokens).
    this.cachedToken = { value: token, expiresAt: this.now() + Math.max(0, expiresIn * 1000 - Math.min(60_000, expiresIn * 500)) };
    return token;
  }

  async sendOtp({ phone, code }: OtpMessage): Promise<void> {
    const payload = {
      outboundSMSMessageRequest: {
        address: `tel:${phone}`,
        senderAddress: this.sender,
        ...(this.senderName ? { senderName: this.senderName } : {}),
        outboundSMSTextMessage: { message: `Votre code MMS est ${code}. Il expire dans 5 minutes.` },
      },
    };
    const body = JSON.stringify(payload);
    const baseEvent = { timestamp_utc: new Date(this.now()).toISOString(), sms_provider: 'orange' as const, recipient_masked: maskedRecipient(phone) };
    let errorCode: string | null = null;
    let errorMessage = 'unavailable';
    try {
      let token = await this.token();
      for (let attempt = 0; attempt < 2; attempt++) {
        let response: Response;
        try {
          response = await this.fetchFn(this.smsUrl, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
            body,
            signal: AbortSignal.timeout(8000),
            redirect: 'error',
          });
        } catch {
          // A lost response may follow a successful send. Never retry an ambiguous delivery.
          throw new SmsProviderError('send');
        }
        if (response.ok) {
          const data: unknown = await response.json().catch(() => undefined);
          this.emit({ ...baseEvent, http_status: response.status, resource_id: orangeResourceId(data, response.headers.get('location')), result: 'accepted' });
          return;
        }
        const data: unknown = await response.json().catch(() => undefined);
        const detail = orangeError(data);
        errorCode = detail.code;
        errorMessage = detail.message;
        if (response.status === 401 && attempt === 0 && (detail.code === '42' || detail.message === 'Expired credentials')) {
          if (this.cachedToken?.value === token) this.cachedToken = undefined;
          token = await this.token();
          continue; // The explicit expired-credentials response means Orange rejected the send.
        }
        throw new SmsProviderError('send', response.status);
      }
    } catch (error) {
      const failure = error instanceof SmsProviderError ? error : new SmsProviderError('send');
      this.emit({ ...baseEvent, http_status: failure.status ?? null, orange_error_code: errorCode,
        orange_error_message: failure.phase === 'oauth' ? 'OAuth unavailable' : errorMessage, result: 'failed' });
      throw failure;
    }
  }
}

export function createSmsProvider(env: SmsEnvironment, dependencies: SmsDependencies = {}): SmsProvider {
  const provider = env.SMS_PROVIDER || 'console';
  if (provider === 'console') {
    if (env.MMS_TEST_MODE !== '1') throw new Error('SMS_PROVIDER=console est réservé au mode test.');
    return new ConsoleSmsProvider(dependencies.writeOtp || writeFile, dependencies.log || console.info);
  }
  if (provider !== 'orange') throw new Error('SMS_PROVIDER doit être console ou orange.');
  const clientId = env.ORANGE_CLIENT_ID?.trim();
  const clientSecret = env.ORANGE_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) throw new Error('ORANGE_CLIENT_ID et ORANGE_CLIENT_SECRET sont requis lorsque SMS_PROVIDER=orange.');
  const sender = env.ORANGE_COUNTRY_SENDER?.trim() || 'tel:+2610000';
  if (!/^tel:\+261\d{4,12}$/.test(sender)) throw new Error('ORANGE_COUNTRY_SENDER doit être un numéro sender malgache au format tel:+261...');
  const senderName = env.ORANGE_SENDER_NAME?.trim() || '';
  if (senderName && !/^[a-zA-Z0-9 ]{1,11}$/.test(senderName)) throw new Error('ORANGE_SENDER_NAME doit contenir au plus 11 caractères alphanumériques ou espaces.');
  return new OrangeSmsProvider(clientId, clientSecret, sender, senderName, dependencies.fetchFn || fetch, dependencies.now || Date.now,
    dependencies.logOrange || (event => console.info(JSON.stringify(event))));
}
