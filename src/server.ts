import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { Pool } from 'pg';
import { parsePhoneNumberFromString } from 'libphonenumber-js';
import { createSmsProvider, SmsProviderError } from './sms-provider.js';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');
if (!process.env.OTP_PEPPER || !process.env.ACCESS_TOKEN_SECRET) throw new Error('OTP_PEPPER et ACCESS_TOKEN_SECRET sont requis.');
const otpPepper = process.env.OTP_PEPPER;
const accessSecret = process.env.ACCESS_TOKEN_SECRET;
const testMode = process.env.MMS_TEST_MODE === '1';
const smsProvider = createSmsProvider(process.env);
const cookieSecure = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
const termsVersion = process.env.TERMS_VERSION || '1.0';
const privacyVersion = process.env.PRIVACY_VERSION || '1.0';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
pool.on('error', error => console.error('Connexion PostgreSQL interrompue', error));

const slots = {
  'À domicile': ['08:30', '10:00', '11:30', '14:00', '16:00'],
  'En atelier': ['09:00', '10:30', '13:30', '15:00', '16:30'],
} as const;
type ScheduledKind = keyof typeof slots;
const allowedStatuses = ['Confirmé', 'Dépannage demandé', 'Pris en charge', 'En cours', 'Terminé', 'Annulé'];
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const maxPhotoBytes = 5 * 1024 * 1024;
const vehicleFields = `v.id, v.name, v.model, v.plate, v.color,
  v.displacement_cc AS "displacementCc", v.production_year AS year,
  CASE WHEN p.vehicle_id IS NOT NULL THEN '/api/customers/' || v.customer_id || '/vehicles/' || v.id ||
    '/photo?updated=' || (extract(epoch from p.updated_at) * 1000)::bigint ELSE NULL END AS "photoUrl"`;

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

type Identity = { userId: string; customerId: string; sessionId: string; role: string };
const rateBuckets = new Map<string, { count: number; reset: number }>();
function limit(key: string, max: number, windowMs: number) {
  const now = Date.now(); const found = rateBuckets.get(key);
  if (!found || found.reset < now) { rateBuckets.set(key, { count: 1, reset: now + windowMs }); return; }
  if (++found.count > max) throw new HttpError(429, 'Trop de demandes. Réessayez dans quelques minutes.');
}
function clientIp(req: IncomingMessage) { return req.socket.remoteAddress || 'unknown'; } // Forwarded headers are intentionally not trusted.
function normalizePhone(value: unknown) {
  const raw = textField(value, 'Numéro de téléphone', 6, 40);
  const candidate = raw.startsWith('+') ? raw : `+261${raw.replace(/^0/, '')}`;
  const phone = parsePhoneNumberFromString(candidate, 'MG');
  if (!phone?.isValid() || phone.country !== 'MG') throw new HttpError(400, 'Entrez un numéro de téléphone malgache valide.');
  return phone.number;
}
function otpDigest(challengeId: string, code: string) { return createHmac('sha256', otpPepper).update(`${challengeId}:${code}`).digest('hex'); }
function safeEqualHex(left: string, right: string) { const a = Buffer.from(left, 'hex'); const b = Buffer.from(right, 'hex'); return a.length === b.length && timingSafeEqual(a, b); }
function base64url(value: string | Buffer) { return Buffer.from(value).toString('base64url'); }
function accessToken(identity: Identity) {
  const now = Math.floor(Date.now() / 1000); const payload = base64url(JSON.stringify({ sub: identity.userId, cid: identity.customerId, sid: identity.sessionId, role: identity.role, iat: now, exp: now + 900 }));
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })); const signature = createHmac('sha256', accessSecret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}
function verifyAccessToken(value: string): Identity {
  const [header, payload, signature] = value.split('.');
  if (!header || !payload || !signature) throw new HttpError(401, 'Session expirée.');
  const expected = createHmac('sha256', accessSecret).update(`${header}.${payload}`).digest('base64url');
  if (expected.length !== signature.length || !timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) throw new HttpError(401, 'Session expirée.');
  try { const token = JSON.parse(Buffer.from(payload, 'base64url').toString()) as { sub: string; cid: string; sid: string; role: string; exp: number };
    if (token.exp * 1000 <= Date.now() || token.role !== 'customer') throw new Error(); return { userId: token.sub, customerId: token.cid, sessionId: token.sid, role: token.role };
  } catch { throw new HttpError(401, 'Session expirée.'); }
}
async function identity(req: IncomingMessage) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw new HttpError(401, 'Connexion requise.');
  const auth = verifyAccessToken(header.slice(7));
  const active = await pool.query(`SELECT 1 FROM user_sessions s JOIN users u ON u.id=s.user_id
    JOIN customers c ON c.user_id=u.id WHERE s.id=$1 AND s.user_id=$2 AND c.id=$3
    AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active' AND u.role='customer'`,
  [auth.sessionId, auth.userId, auth.customerId]);
  if (!active.rowCount) throw new HttpError(401, 'Session expirée.');
  return auth;
}
function cookie(req: IncomingMessage, name: string) { return req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`))?.slice(name.length + 1); }
function refreshCookie(value: string, expiresAt: Date) { return `mms_refresh=${value}; Path=/api/auth; HttpOnly; SameSite=Lax; ${cookieSecure ? 'Secure; ' : ''}Expires=${expiresAt.toUTCString()}`; }
function clearRefreshCookie() { return `mms_refresh=; Path=/api/auth; HttpOnly; SameSite=Lax; ${cookieSecure ? 'Secure; ' : ''}Max-Age=0`; }
function maskedPhone(phone: string) { return phone.replace(/(\+261\s?\d\d)\d+(\d\d)/, '$1 ** *** $2'); }

function send(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function textField(value: unknown, label: string, min = 0, max = 255): string {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) throw new HttpError(400, `${label} invalide.`);
  return value.trim();
}
function integerField(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) throw new HttpError(400, `${label} invalide.`);
  return value;
}
function vehicleInput(input: Record<string, unknown>) {
  return {
    name: textField(input.name, 'Marque de la moto', 1, 80),
    displacementCc: integerField(input.displacementCc, 'Cylindrée', 1, 5000),
    year: integerField(input.year, 'Année de la moto', 1885, new Date().getFullYear() + 1),
    model: textField(input.model ?? '', 'Modèle', 0, 100),
    plate: textField(input.plate ?? '', 'Immatriculation', 0, 32).toUpperCase(),
  };
}
async function photoBody(req: IncomingMessage, mimeType: string): Promise<Buffer> {
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(mimeType)) throw new HttpError(415, 'Photo JPEG, PNG ou WebP requise.');
  if (Number(req.headers['content-length']) > maxPhotoBytes) throw new HttpError(413, 'La photo ne doit pas dépasser 5 Mo.');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maxPhotoBytes) throw new HttpError(413, 'La photo ne doit pas dépasser 5 Mo.');
    chunks.push(bytes);
  }
  const photo = Buffer.concat(chunks);
  const valid = mimeType === 'image/jpeg' ? photo.length >= 3 && photo.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))
    : mimeType === 'image/png' ? photo.length >= 8 && photo.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
      : photo.length >= 12 && photo.toString('ascii', 0, 4) === 'RIFF' && photo.toString('ascii', 8, 12) === 'WEBP';
  if (!valid) throw new HttpError(400, 'Le fichier ne correspond pas au format de photo indiqué.');
  return photo;
}
function uuid(value: string | undefined): string {
  if (!value || !uuidPattern.test(value)) throw new HttpError(400, 'Identifiant invalide.');
  return value;
}
async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk.toString();
    if (raw.length > 100_000) throw new HttpError(413, 'Requête trop volumineuse.');
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch { throw new HttpError(400, 'Corps JSON invalide.'); }
}
function localDate(now: Date) {
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}
function localTime(now: Date) {
  return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
}
async function customerExists(id: string) {
  const result = await pool.query('SELECT 1 FROM customers WHERE id = $1', [id]);
  if (!result.rowCount) throw new HttpError(404, 'Client introuvable.');
}
async function vehicleData(customerId: string, vehicleId: string) {
  const result = await pool.query(`SELECT ${vehicleFields} FROM vehicles v
    LEFT JOIN vehicle_photos p ON p.vehicle_id = v.id WHERE v.customer_id = $1 AND v.id = $2`, [customerId, vehicleId]);
  if (!result.rowCount) throw new HttpError(404, 'Moto introuvable pour ce client.');
  return result.rows[0];
}
async function customerData(id: string) {
  const customer = await pool.query(`SELECT c.id, COALESCE(NULLIF(concat_ws(' ', first_name, last_name), ''), name) AS name,
    u.phone_e164 AS phone FROM customers c JOIN users u ON u.id = c.user_id WHERE c.id = $1`, [id]);
  if (!customer.rowCount) throw new HttpError(404, 'Client introuvable.');
  const [vehicles, appointments, maintenance, messages] = await Promise.all([
    pool.query(`SELECT ${vehicleFields} FROM vehicles v LEFT JOIN vehicle_photos p ON p.vehicle_id = v.id
      WHERE v.customer_id = $1 ORDER BY v.created_at`, [id]),
    pool.query(`SELECT id, vehicle_id AS "vehicleId", problem, diagnosis, kind, address,
      to_char(appointment_date, 'YYYY-MM-DD') AS date, to_char(appointment_time, 'HH24:MI') AS time,
      status, contact_phone AS "contactPhone", immobilized, mechanic_note AS "mechanicNote"
      FROM appointments WHERE customer_id = $1 ORDER BY created_at DESC`, [id]),
    pool.query(`SELECT id, vehicle_id AS "vehicleId", title, to_char(maintenance_date, 'YYYY-MM-DD') AS date, note
      FROM maintenance WHERE customer_id = $1 ORDER BY maintenance_date DESC`, [id]),
    pool.query('SELECT body FROM messages WHERE customer_id = $1 ORDER BY id', [id]),
  ]);
  return { user: customer.rows[0], vehicles: vehicles.rows, appointments: appointments.rows, maintenance: maintenance.rows, messages: messages.rows.map(row => row.body) };
}

async function issueSession(userId: string, customerId: string, req: IncomingMessage, res: ServerResponse) {
  const sessionId = randomUUID(); const refresh = randomBytes(32).toString('base64url'); const hash = createHmac('sha256', accessSecret).update(refresh).digest('hex');
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const agent = String(req.headers['user-agent'] || '').slice(0, 300);
  const label = /android/i.test(agent) ? 'Navigateur Android' : /iphone|ipad/i.test(agent) ? 'Navigateur iOS' : 'Navigateur web';
  await pool.query(`INSERT INTO user_sessions (id,user_id,refresh_token_hash,user_agent,device_label,expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, [sessionId, userId, hash, agent, label, expires]);
  res.setHeader('Set-Cookie', refreshCookie(refresh, expires));
  return { accessToken: accessToken({ userId, customerId, sessionId, role: 'customer' }), user: await customerData(customerId) };
}
async function createChallenge(req: IncomingMessage, input: Record<string, unknown>, purpose: 'register' | 'login' | 'phone_change', userId?: string) {
  const phone = normalizePhone(input.phone); limit(`otp:ip:${clientIp(req)}`, 12, 15 * 60_000); limit(`otp:phone:${phone}`, 4, 15 * 60_000);
  const last = await pool.query(`SELECT resend_available_at FROM otp_challenges WHERE phone_e164=$1 AND purpose=$2
    AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`, [phone, purpose]);
  if (last.rowCount && new Date(last.rows[0].resend_available_at) > new Date()) throw new HttpError(429, 'Attendez une minute avant de demander un nouveau code.');
  const exists = await pool.query(`SELECT u.id FROM users u WHERE u.phone_e164 = $1 AND u.status = 'active'`, [phone]);
  if (purpose === 'register' && exists.rowCount) throw new HttpError(409, 'Un compte existe déjà avec ce numéro. Connectez-vous.');
  if (purpose === 'login' && !exists.rowCount) throw new HttpError(404, 'Aucun compte ne correspond à ce numéro. Créez votre compte.');
  let firstName: string | null = null; let lastName: string | null = null;
  if (purpose === 'register') {
    firstName = textField(input.firstName, 'Prénom', 1, 80); lastName = textField(input.lastName, 'Nom', 1, 80);
    if (input.termsAccepted !== true || input.privacyAccepted !== true) throw new HttpError(400, 'Vous devez accepter les conditions et la politique de confidentialité.');
  }
  if (purpose === 'phone_change' && exists.rowCount && exists.rows[0].id !== userId) throw new HttpError(409, 'Ce numéro est déjà utilisé par un autre compte.');
  if (purpose === 'phone_change' && exists.rowCount && exists.rows[0].id === userId) throw new HttpError(400, 'Le nouveau numéro doit être différent de l’actuel.');
  const id = randomUUID(); const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE otp_challenges SET consumed_at=now() WHERE phone_e164=$1 AND purpose=$2 AND consumed_at IS NULL`, [phone, purpose]);
    await client.query(`INSERT INTO otp_challenges (id,phone_e164,purpose,otp_digest,registration_first_name,registration_last_name,terms_accepted,privacy_accepted,user_id,expires_at,resend_available_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '5 minutes',now()+interval '60 seconds')`, [id, phone, purpose, otpDigest(id, code), firstName, lastName, purpose === 'register' || null, purpose === 'register' || null, userId || null]);
    await smsProvider.sendOtp({ challengeId: id, phone, code });
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally { client.release(); }
  return { challengeId: id, phone: maskedPhone(phone), expiresInSeconds: 300, resendInSeconds: 60 };
}
async function verifyChallenge(req: IncomingMessage, input: Record<string, unknown>, purpose: 'register' | 'login' | 'phone_change', res: ServerResponse, authorizedUserId?: string) {
  const challengeId = uuid(typeof input.challengeId === 'string' ? input.challengeId : undefined); const code = textField(input.code, 'Code OTP', 6, 6);
  if (!/^\d{6}$/.test(code)) throw new HttpError(400, 'Le code doit contenir six chiffres.'); limit(`verify:ip:${clientIp(req)}`, 20, 15 * 60_000);
  const client = await pool.connect();
  try {
    await client.query('BEGIN'); const result = await client.query('SELECT * FROM otp_challenges WHERE id=$1 FOR UPDATE', [challengeId]);
    if (!result.rowCount || result.rows[0].purpose !== purpose || result.rows[0].consumed_at) throw new HttpError(400, 'Demande OTP introuvable. Recommencez.');
    const challenge = result.rows[0];
    if (purpose === 'phone_change' && challenge.user_id !== authorizedUserId) throw new HttpError(403, 'Accès refusé.');
    if (new Date(challenge.expires_at) < new Date()) throw new HttpError(410, 'Ce code a expiré. Demandez-en un nouveau.');
    if (challenge.attempts_remaining <= 0) throw new HttpError(429, 'Trop de tentatives. Réessayez dans quelques minutes.');
    if (!safeEqualHex(challenge.otp_digest, otpDigest(challengeId, code))) { await client.query('UPDATE otp_challenges SET attempts_remaining=attempts_remaining-1 WHERE id=$1', [challengeId]); await client.query('COMMIT'); throw new HttpError(400, 'Le code saisi est incorrect.'); }
    let userId = challenge.user_id as string; let customerId: string;
    if (purpose === 'register') {
      userId = randomUUID(); customerId = randomUUID();
      await client.query(`INSERT INTO users (id,phone_e164,role,phone_verified_at) VALUES ($1,$2,'customer',now())`, [userId, challenge.phone_e164]);
      await client.query(`INSERT INTO customers (id,user_id,name,phone,first_name,last_name,terms_accepted_at,terms_version,privacy_accepted_at,privacy_version)
        VALUES ($1,$2,$3,$4,$5,$6,now(),$7,now(),$8)`, [customerId, userId, `${challenge.registration_first_name} ${challenge.registration_last_name}`, challenge.phone_e164, challenge.registration_first_name, challenge.registration_last_name, termsVersion, privacyVersion]);
    } else if (purpose === 'login') {
      const profile = await client.query('SELECT c.id, u.id AS user_id FROM users u JOIN customers c ON c.user_id=u.id WHERE u.phone_e164=$1 AND u.status=\'active\'', [challenge.phone_e164]);
      if (!profile.rowCount) throw new HttpError(404, 'Aucun compte ne correspond à ce numéro.'); userId = profile.rows[0].user_id; customerId = profile.rows[0].id;
    } else {
      if (!userId) throw new HttpError(400, 'Demande OTP introuvable.');
      const profile = await client.query('SELECT id FROM customers WHERE user_id=$1', [userId]); if (!profile.rowCount) throw new HttpError(404, 'Compte introuvable.'); customerId = profile.rows[0].id;
      await client.query('UPDATE users SET phone_e164=$2, phone_verified_at=now(), updated_at=now() WHERE id=$1', [userId, challenge.phone_e164]);
      await client.query('UPDATE customers SET phone=$2 WHERE id=$1', [customerId, challenge.phone_e164]);
      // A changed identity invalidates sessions issued for the previous number.
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [userId]);
    }
    await client.query('UPDATE otp_challenges SET consumed_at=now() WHERE id=$1', [challengeId]); await client.query('COMMIT');
    if (testMode) await unlink(`/tmp/mms-test-otp-${challengeId}`).catch(() => undefined);
    return await issueSession(userId, customerId!, req, res);
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
}

async function route(req: IncomingMessage, res: ServerResponse) {
  const method = req.method || 'GET';
  const path = new URL(req.url || '/', 'http://localhost');
  const parts = path.pathname.split('/').filter(Boolean);
  if (['POST', 'PATCH'].includes(method) && !req.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'Content-Type application/json requis.');
  if (parts[0] !== 'api') throw new HttpError(404, 'Route introuvable.');

  if (method === 'GET' && parts[1] === 'health' && parts.length === 2) {
    await pool.query('SELECT 1');
    return send(res, 200, { status: 'ok', mode: 'test' });
  }
  if (parts[1] === 'auth') {
    if (method === 'POST' && parts[2] === 'register' && parts[3] === 'request-otp') return send(res, 200, await createChallenge(req, await body(req), 'register'));
    if (method === 'POST' && parts[2] === 'register' && parts[3] === 'verify-otp') return send(res, 201, await verifyChallenge(req, await body(req), 'register', res));
    if (method === 'POST' && parts[2] === 'login' && parts[3] === 'request-otp') return send(res, 200, await createChallenge(req, await body(req), 'login'));
    if (method === 'POST' && parts[2] === 'login' && parts[3] === 'verify-otp') return send(res, 200, await verifyChallenge(req, await body(req), 'login', res));
    if (method === 'POST' && parts[2] === 'phone-change' && parts[3] === 'request-otp') { const auth = await identity(req); return send(res, 200, await createChallenge(req, await body(req), 'phone_change', auth.userId)); }
    if (method === 'POST' && parts[2] === 'phone-change' && parts[3] === 'verify-otp') { const auth = await identity(req); return send(res, 200, await verifyChallenge(req, await body(req), 'phone_change', res, auth.userId)); }
    if (method === 'POST' && parts[2] === 'refresh') {
      limit(`refresh:${clientIp(req)}`, 30, 15 * 60_000); const token = cookie(req, 'mms_refresh'); if (!token) throw new HttpError(401, 'Session expirée.');
      const hash = createHmac('sha256', accessSecret).update(token).digest('hex'); const found = await pool.query(`SELECT s.id,s.user_id,c.id AS customer_id FROM user_sessions s JOIN customers c ON c.user_id=s.user_id WHERE s.refresh_token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()`, [hash]);
      if (!found.rowCount) throw new HttpError(401, 'Session expirée.'); await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE id=$1', [found.rows[0].id]);
      return send(res, 200, await issueSession(found.rows[0].user_id, found.rows[0].customer_id, req, res));
    }
    if (method === 'POST' && parts[2] === 'logout') { const token = cookie(req, 'mms_refresh'); if (token) await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE refresh_token_hash=$1', [createHmac('sha256', accessSecret).update(token).digest('hex')]); res.setHeader('Set-Cookie', clearRefreshCookie()); return send(res, 200, { ok: true }); }
    const auth = await identity(req);
    if (method === 'GET' && parts[2] === 'me') return send(res, 200, await customerData(auth.customerId));
    if (method === 'GET' && parts[2] === 'sessions') { const sessions = await pool.query(`SELECT id,device_label,created_at AS "createdAt",last_seen_at AS "lastSeenAt", id=$2 AS "current" FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY last_seen_at DESC`, [auth.userId, auth.sessionId]); return send(res, 200, sessions.rows); }
    if (method === 'DELETE' && parts[2] === 'sessions' && parts[3]) { const id = uuid(parts[3]); await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2', [id, auth.userId]); return send(res, 200, { ok: true }); }
    if (method === 'POST' && parts[2] === 'logout-all') { await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [auth.userId]); res.setHeader('Set-Cookie', clearRefreshCookie()); return send(res, 200, { ok: true }); }
    throw new HttpError(404, 'Route introuvable.');
  }
  if (method === 'GET' && parts[1] === 'availability' && parts.length === 2) {
    const kind = path.searchParams.get('kind');
    const date = path.searchParams.get('date');
    if (kind !== 'À domicile' && kind !== 'En atelier') throw new HttpError(400, 'Type d’intervention invalide.');
    if (!date || !datePattern.test(date) || Number.isNaN(Date.parse(`${date}T12:00:00`))) throw new HttpError(400, 'Date invalide.');
    const occupied = await pool.query(`SELECT to_char(appointment_time, 'HH24:MI') AS time FROM appointments
      WHERE kind = $1 AND appointment_date = $2 AND status IN ('Confirmé', 'Pris en charge', 'En cours')`, [kind, date]);
    return send(res, 200, { slots: slots[kind], occupied: occupied.rows.map(row => row.time) });
  }
  if (parts[1] === 'customers' && parts[2]) {
    const customerId = uuid(parts[2]);
    const auth = await identity(req);
    if (auth.customerId !== customerId) throw new HttpError(403, 'Accès refusé.');
    if (method === 'GET' && parts.length === 3) return send(res, 200, await customerData(customerId));
    if (method === 'PATCH' && parts.length === 3) {
      const input = await body(req);
      const name = textField(input.name, 'Prénom', 1, 80);
      if (input.phone !== undefined) throw new HttpError(400, 'Le changement de numéro requiert une confirmation OTP.');
      const result = await pool.query('UPDATE customers SET first_name = $2, name = $2 || \' \' || COALESCE(last_name, \'\') WHERE id = $1 RETURNING name, phone', [customerId, name]);
      if (!result.rowCount) throw new HttpError(404, 'Client introuvable.');
      return send(res, 200, result.rows[0]);
    }
    if (method === 'POST' && parts[3] === 'vehicles' && parts.length === 4) {
      const input = await body(req);
      const vehicle = vehicleInput(input);
      await customerExists(customerId);
      const id = randomUUID();
      await pool.query(`INSERT INTO vehicles (id, customer_id, name, model, plate, displacement_cc, production_year)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, customerId, vehicle.name, vehicle.model, vehicle.plate, vehicle.displacementCc, vehicle.year]);
      return send(res, 201, await vehicleData(customerId, id));
    }
    if (parts[3] === 'vehicles' && parts[4] && parts.length >= 5) {
      const vehicleId = uuid(parts[4]);
      if (method === 'PATCH' && parts.length === 5) {
        const input = vehicleInput(await body(req));
        const updated = await pool.query(`UPDATE vehicles SET name = $3, model = $4, plate = $5,
          displacement_cc = $6, production_year = $7 WHERE id = $1 AND customer_id = $2 RETURNING id`,
        [vehicleId, customerId, input.name, input.model, input.plate, input.displacementCc, input.year]);
        if (!updated.rowCount) throw new HttpError(404, 'Moto introuvable pour ce client.');
        return send(res, 200, await vehicleData(customerId, vehicleId));
      }
      if (parts[5] === 'photo' && parts.length === 6) {
        if (method === 'GET') {
          const photo = await pool.query(`SELECT p.mime_type, p.image_data FROM vehicle_photos p
            JOIN vehicles v ON v.id = p.vehicle_id WHERE v.id = $1 AND v.customer_id = $2`, [vehicleId, customerId]);
          if (!photo.rowCount) throw new HttpError(404, 'Photo introuvable.');
          const bytes: Buffer = photo.rows[0].image_data;
          res.writeHead(200, { 'Content-Type': photo.rows[0].mime_type, 'Content-Length': bytes.length,
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
          return res.end(bytes);
        }
        if (method === 'PUT') {
          await vehicleData(customerId, vehicleId);
          const mimeType = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
          const image = await photoBody(req, mimeType);
          await pool.query(`INSERT INTO vehicle_photos (vehicle_id, mime_type, image_data) VALUES ($1, $2, $3)
            ON CONFLICT (vehicle_id) DO UPDATE SET mime_type = EXCLUDED.mime_type,
              image_data = EXCLUDED.image_data, updated_at = now()`, [vehicleId, mimeType, image]);
          return send(res, 200, await vehicleData(customerId, vehicleId));
        }
        if (method === 'DELETE') {
          await vehicleData(customerId, vehicleId);
          await pool.query('DELETE FROM vehicle_photos WHERE vehicle_id = $1', [vehicleId]);
          return send(res, 200, await vehicleData(customerId, vehicleId));
        }
      }
    }
    if (method === 'POST' && parts[3] === 'appointments' && parts.length === 4) {
      const input = await body(req);
      const vehicleId = uuid(typeof input.vehicleId === 'string' ? input.vehicleId : undefined);
      const vehicle = await pool.query('SELECT 1 FROM vehicles WHERE id = $1 AND customer_id = $2', [vehicleId, customerId]);
      if (!vehicle.rowCount) throw new HttpError(400, 'Moto introuvable pour ce client.');
      const problem = textField(input.problem, 'Description de la panne', 10, 2000);
      const diagnosis = textField(input.diagnosis, 'Orientation', 0, 500);
      const kind = input.kind;
      if (kind !== 'Urgence' && kind !== 'À domicile' && kind !== 'En atelier') throw new HttpError(400, 'Type d’intervention invalide.');
      const address = textField(input.address, 'Adresse', kind === 'En atelier' ? 0 : 5, 500);
      const now = new Date();
      let date = localDate(now);
      let time = localTime(now);
      let contactPhone: string | null = null;
      let immobilized: boolean | null = null;
      if (kind === 'Urgence') {
        contactPhone = textField(input.contactPhone, 'Téléphone de contact', 6, 40);
        if (typeof input.immobilized !== 'boolean') throw new HttpError(400, 'État de la moto requis.');
        immobilized = input.immobilized;
      } else {
        date = textField(input.date, 'Date', 10, 10);
        time = textField(input.time, 'Créneau', 5, 5);
        if (!datePattern.test(date) || Number.isNaN(Date.parse(`${date}T12:00:00`)) || date < localDate(now)) throw new HttpError(400, 'Date non disponible.');
        if (!slots[kind as ScheduledKind].some(slot => slot === time)) throw new HttpError(400, 'Créneau invalide.');
      }
      const id = randomUUID();
      try {
        await pool.query(`INSERT INTO appointments (id, customer_id, vehicle_id, problem, diagnosis, kind, address,
          appointment_date, appointment_time, status, contact_phone, immobilized)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [id, customerId, vehicleId, problem, diagnosis, kind, address, date, time, kind === 'Urgence' ? 'Dépannage demandé' : 'Confirmé', contactPhone, immobilized]);
      } catch (error) {
        if ((error as { code?: string }).code === '23505') throw new HttpError(409, 'Ce créneau vient d’être réservé. Choisissez-en un autre.');
        throw error;
      }
      const data = await customerData(customerId);
      return send(res, 201, data.appointments.find((appointment: { id: string }) => appointment.id === id));
    }
    if (method === 'PATCH' && parts[3] === 'appointments' && parts[4] && parts[5] === 'cancel' && parts.length === 6) {
      const id = uuid(parts[4]);
      const result = await pool.query(`UPDATE appointments SET status = 'Annulé'
        WHERE id = $1 AND customer_id = $2 AND status IN ('Confirmé', 'Dépannage demandé') RETURNING id`, [id, customerId]);
      if (!result.rowCount) throw new HttpError(409, 'Cette demande ne peut plus être annulée.');
      return send(res, 200, { status: 'Annulé' });
    }
    if (method === 'POST' && parts[3] === 'messages' && parts.length === 4) {
      const input = await body(req);
      const message = textField(input.message, 'Message', 1, 2000);
      await customerExists(customerId);
      await pool.query('INSERT INTO messages (customer_id, body) VALUES ($1, $2)', [customerId, message]);
      return send(res, 201, { message });
    }
  }
  if (parts[1] === 'mechanic' && parts[2] === 'appointments') {
    throw new HttpError(403, 'L’accès mécanicien n’est pas encore disponible.');
    if (method === 'GET' && parts.length === 3) {
      const result = await pool.query(`SELECT a.id, a.customer_id AS "customerId", c.name AS "customerName",
        c.phone AS "customerPhone", v.name AS "vehicleName", v.model AS "vehicleModel", v.plate,
        CASE WHEN p.vehicle_id IS NOT NULL THEN '/api/customers/' || v.customer_id || '/vehicles/' || v.id ||
          '/photo?updated=' || (extract(epoch from p.updated_at) * 1000)::bigint ELSE NULL END AS "vehiclePhotoUrl",
        a.problem, a.diagnosis, a.kind, a.address,
        to_char(a.appointment_date, 'YYYY-MM-DD') AS date,
        to_char(a.appointment_time, 'HH24:MI') AS time,
        a.status, a.contact_phone AS "contactPhone", a.immobilized, a.mechanic_note AS "mechanicNote"
        FROM appointments a JOIN customers c ON c.id = a.customer_id
        JOIN vehicles v ON v.id = a.vehicle_id LEFT JOIN vehicle_photos p ON p.vehicle_id = v.id ORDER BY
        CASE WHEN a.kind = 'Urgence' AND a.status NOT IN ('Terminé','Annulé') THEN 0 ELSE 1 END,
        a.appointment_date DESC, a.appointment_time DESC`);
      return send(res, 200, result.rows);
    }
    if (method === 'PATCH' && parts[3] && parts.length === 4) {
      const id = uuid(parts[3]);
      const input = await body(req);
      const old = await pool.query('SELECT kind, status, mechanic_note FROM appointments WHERE id = $1', [id]);
      if (!old.rowCount) throw new HttpError(404, 'Demande introuvable.');
      const row = old.rows[0];
      const status = input.status === undefined ? row.status : input.status;
      if (typeof status !== 'string' || !allowedStatuses.includes(status)) throw new HttpError(400, 'Statut invalide.');
      if (row.kind === 'Urgence' && status === 'Confirmé' || row.kind !== 'Urgence' && status === 'Dépannage demandé') throw new HttpError(400, 'Statut incompatible avec la demande.');
      const note = input.mechanicNote === undefined ? row.mechanic_note : textField(input.mechanicNote, 'Note', 0, 2000);
      await pool.query('UPDATE appointments SET status = $2, mechanic_note = $3 WHERE id = $1', [id, status, note]);
      return send(res, 200, { id, status, mechanicNote: note });
    }
  }
  throw new HttpError(404, 'Route introuvable.');
}

async function start() {
  const schema = await readFile(join(__dirname, '../src/schema.sql'), 'utf8');
  await pool.query(schema);
  const server = createServer((req, res) => {
    route(req, res).catch(error => {
      if (error instanceof HttpError) return send(res, error.status, { error: error.message });
      if (error instanceof SmsProviderError) {
        console.error('Envoi Orange SMS indisponible', { phase: error.phase, status: error.status || 'network-or-response' });
        return send(res, 503, { error: 'Impossible d’envoyer le code pour le moment. Réessayez plus tard.' });
      }
      console.error('Erreur API MMS', error);
      send(res, 500, { error: 'Erreur interne du serveur.' });
    });
  });
  server.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('API MMS prête avec authentification OTP.'));
  process.on('SIGTERM', () => { server.close(); void pool.end(); });
}
start().catch(error => { console.error('Démarrage API impossible', error); process.exit(1); });
