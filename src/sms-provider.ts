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
};

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
  ) {
    this.smsUrl = `https://api.orange.com/smsmessaging/v1/outbound/${encodeURIComponent(sender)}/requests`;
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
      if (response.ok) return;
      if (response.status === 401 && attempt === 0) {
        const error: unknown = await response.json().catch(() => undefined);
        const detail = error && typeof error === 'object' ? error as Record<string, unknown> : {};
        if (detail.code === 42 || detail.code === '42' || detail.message === 'Expired credentials') {
          if (this.cachedToken?.value === token) this.cachedToken = undefined;
          token = await this.token();
          continue; // The explicit expired-credentials response means Orange rejected the send.
        }
      }
      throw new SmsProviderError('send', response.status);
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
  return new OrangeSmsProvider(clientId, clientSecret, sender, senderName, dependencies.fetchFn || fetch, dependencies.now || Date.now);
}
