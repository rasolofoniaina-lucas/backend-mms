import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Pool } from 'pg';
import { normalizeMalagasyPhone } from './phone.js';
import { createSmsProvider, SmsProviderError } from './sms-provider.js';
import { canTransition, hashPassword, isStaffRole, staffEmail, staffUsername, temporaryPassword, validPassword, verifyPassword, type Role, type TicketStatus } from './staff-domain.js';

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

type Identity = { userId: string; customerId: string; sessionId: string; role: Role; mustChangePassword?: boolean };
const rateBuckets = new Map<string, { count: number; reset: number }>();
const trustedNginxPeers = new Set<string>();
function limit(key: string, max: number, windowMs: number) {
  const now = Date.now(); const found = rateBuckets.get(key);
  if (!found || found.reset < now) { rateBuckets.set(key, { count: 1, reset: now + windowMs }); return; }
  if (++found.count > max) throw new HttpError(429, 'Trop de demandes. Réessayez dans quelques minutes.');
}
function clientIp(req: IncomingMessage) {
  // Only the current Docker DNS address of our Nginx service may supply this
  // header. Nginx receives X-Forwarded-For from Caddy, which must overwrite
  // untrusted inbound XFF. Direct access to port 8080 remains loopback-only.
  const peer = req.socket.remoteAddress || 'unknown';
  const real = req.headers['x-real-ip'];
  return trustedNginxPeers.has(peer) && typeof real === 'string' && isIP(real) ? real : peer;
}
function normalizePhone(value: unknown) {
  const raw = textField(value, 'Numéro de téléphone', 6, 40);
  const phone = normalizeMalagasyPhone(raw);
  if (!phone) throw new HttpError(400, 'Entrez un numéro de téléphone malgache valide.');
  return phone;
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
    if (token.exp * 1000 <= Date.now() || !['customer','mechanic','workshop_manager','admin'].includes(token.role)) throw new Error(); return { userId: token.sub, customerId: token.cid, sessionId: token.sid, role: token.role as Role };
  } catch { throw new HttpError(401, 'Session expirée.'); }
}
async function identity(req: IncomingMessage, allowed: readonly Role[] = ['customer'], allowPasswordChange = false) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw new HttpError(401, 'Connexion requise.');
  const auth = verifyAccessToken(header.slice(7));
  const active = await pool.query(`SELECT u.role,COALESCE(lc.must_change_password,false) AS must_change_password,c.id AS customer_id FROM user_sessions s
    JOIN users u ON u.id=s.user_id LEFT JOIN customers c ON c.user_id=u.id LEFT JOIN local_credentials lc ON lc.user_id=u.id
    WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'`,
  [auth.sessionId, auth.userId]);
  if (!active.rowCount || active.rows[0].role !== auth.role || (auth.role === 'customer' && active.rows[0].customer_id !== auth.customerId)) throw new HttpError(401, 'Session expirée.');
  if (!allowed.includes(auth.role)) throw new HttpError(403, 'Accès refusé.');
  if (active.rows[0].must_change_password && !allowPasswordChange) throw new HttpError(403, 'Vous devez changer votre mot de passe.');
  await pool.query(`UPDATE user_sessions SET last_seen_at=now() WHERE id=$1 AND last_seen_at < now()-interval '1 minute'`, [auth.sessionId]);
  return { ...auth, mustChangePassword: active.rows[0].must_change_password };
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
const allStaffRoles: Role[] = ['mechanic', 'workshop_manager', 'admin'];
function requireRole(req: IncomingMessage, roles: readonly Role[], allowPasswordChange = false) {
  return identity(req, roles, allowPasswordChange);
}
function ticketReference(sequence: string, date = new Date()) {
  return `MMS-${date.getFullYear()}-${sequence.padStart(6, '0')}`;
}
async function ticketEvents(ticketId: string, publicView = false) {
  const result = await pool.query(`SELECT event_type AS "eventType",old_value AS "oldValue",new_value AS "newValue",
    created_at AS "createdAt" FROM ticket_events WHERE ticket_id=$1 ORDER BY created_at,id`, [ticketId]);
  return publicView ? result.rows.map(row => ({ eventType: row.eventType,
    oldValue: row.eventType === 'status_changed' || row.eventType === 'ticket_cancelled' || row.eventType === 'ticket_completed' ? row.oldValue : null,
    newValue: row.eventType === 'status_changed' || row.eventType === 'ticket_created' || row.eventType === 'ticket_cancelled' || row.eventType === 'ticket_completed' ? row.newValue : null,
    createdAt: row.createdAt })) : result.rows;
}
const ticketColumns = `t.id,t.reference,t.customer_id AS "customerId",t.vehicle_id AS "vehicleId",
  t.appointment_id AS "appointmentId",t.intervention_type AS "interventionType",t.description,t.status,
  t.assigned_mechanic_user_id AS "assignedMechanicUserId",t.created_at AS "createdAt",t.updated_at AS "updatedAt",
  t.completed_at AS "completedAt",t.cancelled_at AS "cancelledAt",
  c.name AS "customerName",c.phone AS "customerPhone",v.name AS "vehicleName",v.model AS "vehicleModel",
  a.appointment_date AS "appointmentDate",a.appointment_time AS "appointmentTime",a.mechanic_note AS "publicNote",
  concat_ws(' ',m.first_name,m.last_name) AS "mechanicName"`;
const ticketJoin = `FROM tickets t JOIN customers c ON c.id=t.customer_id JOIN vehicles v ON v.id=t.vehicle_id
  LEFT JOIN appointments a ON a.id=t.appointment_id LEFT JOIN users m ON m.id=t.assigned_mechanic_user_id`;
function customerTicket(row: Record<string, unknown>) {
  const { customerName, customerPhone, assignedMechanicUserId, mechanicName, ...safe } = row;
  void customerName; void customerPhone; void assignedMechanicUserId; void mechanicName;
  return safe;
}
async function staffTicket(reference: string, auth: Identity, lock = false, client?: import('pg').PoolClient) {
  const db = client || pool;
  const result = await db.query(`SELECT ${ticketColumns} ${ticketJoin} WHERE t.reference=$1${lock ? ' FOR UPDATE OF t' : ''}`, [reference]);
  if (!result.rowCount) throw new HttpError(404, 'Ticket introuvable.');
  const ticket = result.rows[0];
  if (auth.role === 'mechanic' && ticket.assignedMechanicUserId !== auth.userId) throw new HttpError(404, 'Ticket introuvable.');
  return ticket;
}
function ticketStatus(value: unknown): TicketStatus {
  if (!['new','triage','assigned','in_progress','waiting_customer','completed','cancelled'].includes(String(value))) throw new HttpError(400, 'Statut invalide.');
  return value as TicketStatus;
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
  const customer = await pool.query(`SELECT c.id, COALESCE(NULLIF(concat_ws(' ', c.first_name, c.last_name), ''), c.name) AS name,
    u.phone_e164 AS phone FROM customers c JOIN users u ON u.id = c.user_id WHERE c.id = $1`, [id]);
  if (!customer.rowCount) throw new HttpError(404, 'Client introuvable.');
  const [vehicles, appointments, maintenance, messages, tickets] = await Promise.all([
    pool.query(`SELECT ${vehicleFields} FROM vehicles v LEFT JOIN vehicle_photos p ON p.vehicle_id = v.id
      WHERE v.customer_id = $1 ORDER BY v.created_at`, [id]),
    pool.query(`SELECT id, vehicle_id AS "vehicleId", problem, diagnosis, kind, address,
      to_char(appointment_date, 'YYYY-MM-DD') AS date, to_char(appointment_time, 'HH24:MI') AS time,
      status, contact_phone AS "contactPhone", immobilized, mechanic_note AS "mechanicNote"
      FROM appointments WHERE customer_id = $1 ORDER BY created_at DESC`, [id]),
    pool.query(`SELECT id, vehicle_id AS "vehicleId", title, to_char(maintenance_date, 'YYYY-MM-DD') AS date, note
      FROM maintenance WHERE customer_id = $1 ORDER BY maintenance_date DESC`, [id]),
    pool.query('SELECT body FROM messages WHERE customer_id = $1 ORDER BY id', [id]),
    pool.query(`SELECT t.id,t.reference,t.appointment_id AS "appointmentId",t.vehicle_id AS "vehicleId",
      t.intervention_type AS "interventionType",t.description,t.status,t.created_at AS "createdAt",
      a.appointment_date AS "appointmentDate",a.appointment_time AS "appointmentTime",a.mechanic_note AS "publicNote"
      FROM tickets t LEFT JOIN appointments a ON a.id=t.appointment_id
      WHERE t.customer_id=$1 ORDER BY t.created_at DESC`, [id]),
  ]);
  return { user: customer.rows[0], vehicles: vehicles.rows, appointments: appointments.rows, maintenance: maintenance.rows, messages: messages.rows.map(row => row.body), tickets: tickets.rows };
}

async function issueSession(userId: string, customerId: string, req: IncomingMessage, res: ServerResponse, role: Role = 'customer') {
  const sessionId = randomUUID(); const refresh = randomBytes(32).toString('base64url'); const hash = createHmac('sha256', accessSecret).update(refresh).digest('hex');
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const agent = String(req.headers['user-agent'] || '').slice(0, 300);
  const label = /android/i.test(agent) ? 'Navigateur Android' : /iphone|ipad/i.test(agent) ? 'Navigateur iOS' : 'Navigateur web';
  await pool.query(`INSERT INTO user_sessions (id,user_id,refresh_token_hash,user_agent,device_label,expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, [sessionId, userId, hash, agent, label, expires]);
  res.setHeader('Set-Cookie', refreshCookie(refresh, expires));
  if (role === 'customer') return { accessToken: accessToken({ userId, customerId, sessionId, role }), user: await customerData(customerId) };
  const user = await pool.query(`SELECT u.id,u.username,u.first_name AS "firstName",u.last_name AS "lastName",u.email,u.role,
    lc.must_change_password AS "mustChangePassword" FROM users u JOIN local_credentials lc ON lc.user_id=u.id WHERE u.id=$1`, [userId]);
  return { accessToken: accessToken({ userId, customerId: '', sessionId, role }), user: user.rows[0] };
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
      await client.query('UPDATE users SET phone_verified_at=COALESCE(phone_verified_at,now()) WHERE id=$1', [userId]);
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

async function staffRoute(req: IncomingMessage, res: ServerResponse, parts: string[], method: string, path: URL) {
  if (method === 'POST' && parts[2] === 'login' && parts.length === 3) {
    const input = await body(req);
    const username = staffUsername(input.username);
    const password = typeof input.password === 'string' ? input.password : '';
    limit(`staff-login-ip:${clientIp(req)}`, 30, 15 * 60_000);
    limit(`staff-login-username:${username || 'invalid'}`, 8, 15 * 60_000);
    const generic = new HttpError(401, 'Identifiant ou mot de passe incorrect.');
    if (!username || !password) throw generic;
    const found = await pool.query(`SELECT u.id,u.role,lc.password_hash FROM users u
      JOIN user_identities ui ON ui.user_id=u.id AND ui.provider='local'
      JOIN local_credentials lc ON lc.user_id=u.id
      WHERE lower(ui.provider_subject)=lower($1) AND lower(u.username)=lower($1) AND u.status='active'`, [username]);
    if (!found.rowCount || !isStaffRole(found.rows[0].role) || !found.rows[0].password_hash || !await verifyPassword(found.rows[0].password_hash, password)) throw generic;
    return send(res, 200, await issueSession(found.rows[0].id, '', req, res, found.rows[0].role));
  }
  const auth = await requireRole(req, allStaffRoles, ['me','change-password','logout-all'].includes(parts[2]));
  if (method === 'GET' && parts[2] === 'me' && parts.length === 3) {
    const found = await pool.query(`SELECT u.id,u.username,u.first_name AS "firstName",u.last_name AS "lastName",u.email,u.role,
      lc.must_change_password AS "mustChangePassword" FROM users u JOIN local_credentials lc ON lc.user_id=u.id WHERE u.id=$1`, [auth.userId]);
    return send(res, 200, found.rows[0]);
  }
  if (method === 'POST' && parts[2] === 'change-password' && parts.length === 3) {
    limit(`staff-password:${auth.userId}`, 8, 15 * 60_000);
    const input = await body(req);
    if (!validPassword(input.newPassword) || input.newPassword === input.currentPassword) throw new HttpError(400, 'Le nouveau mot de passe doit contenir au moins 12 caractères et différer de l’ancien.');
    const found = await pool.query('SELECT password_hash FROM local_credentials WHERE user_id=$1', [auth.userId]);
    if (!found.rowCount || !await verifyPassword(found.rows[0].password_hash, String(input.currentPassword || ''))) throw new HttpError(401, 'Mot de passe actuel incorrect.');
    const digest = await hashPassword(input.newPassword);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE local_credentials SET password_hash=$2,must_change_password=false,password_changed_at=now() WHERE user_id=$1', [auth.userId, digest]);
      await client.query('UPDATE users SET updated_at=now() WHERE id=$1', [auth.userId]);
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [auth.userId]);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
    res.setHeader('Set-Cookie', clearRefreshCookie());
    return send(res, 200, { ok: true, reauthenticationRequired: true });
  }
  if (method === 'POST' && parts[2] === 'logout-all' && parts.length === 3) {
    await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [auth.userId]);
    res.setHeader('Set-Cookie', clearRefreshCookie());
    return send(res, 200, { ok: true });
  }
  if (method === 'GET' && parts[2] === 'sessions' && parts.length === 3) {
    const rows = await pool.query(`SELECT id,device_label AS "deviceLabel",created_at AS "createdAt",
      last_seen_at AS "lastSeenAt",id=$2 AS "current" FROM user_sessions WHERE user_id=$1
      AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC`, [auth.userId, auth.sessionId]);
    return send(res, 200, rows.rows);
  }
  if (method === 'GET' && parts[2] === 'mechanics' && parts.length === 3) {
    if (auth.role !== 'workshop_manager') throw new HttpError(403, 'Accès refusé.');
    const rows = await pool.query(`SELECT id,concat_ws(' ',first_name,last_name) AS name FROM users
      WHERE role='mechanic' AND status='active' ORDER BY first_name,last_name`);
    return send(res, 200, rows.rows);
  }
  if (method === 'GET' && parts[2] === 'summary' && parts.length === 3) {
    if (auth.role !== 'workshop_manager') throw new HttpError(403, 'Accès refusé.');
    const result = await pool.query(`SELECT
      count(*) FILTER (WHERE status='new')::integer AS new,
      count(*) FILTER (WHERE assigned_mechanic_user_id IS NULL AND status NOT IN ('completed','cancelled'))::integer AS unassigned,
      count(*) FILTER (WHERE status='in_progress')::integer AS progress,
      count(*) FILTER (WHERE status='waiting_customer')::integer AS waiting,
      count(*) FILTER (WHERE status='completed' AND completed_at::date=CURRENT_DATE)::integer AS "doneToday"
      FROM tickets`);
    return send(res, 200, result.rows[0]);
  }
  if (parts[2] !== 'tickets') throw new HttpError(404, 'Route introuvable.');
  await requireRole(req, ['mechanic','workshop_manager']);
  if (method === 'GET' && parts.length === 3) {
    const conditions = auth.role === 'mechanic' ? ['t.assigned_mechanic_user_id=$1'] : ['true'];
    const values: unknown[] = auth.role === 'mechanic' ? [auth.userId] : [];
    const add = (sql: string, value: unknown) => { values.push(value); conditions.push(sql.replace('?', `$${values.length}`)); };
    if (path.searchParams.get('status')) add('t.status=?', ticketStatus(path.searchParams.get('status')));
    if (path.searchParams.get('kind')) add('t.intervention_type=?', path.searchParams.get('kind'));
    if (auth.role === 'workshop_manager' && path.searchParams.get('mechanic')) add('t.assigned_mechanic_user_id=?', uuid(path.searchParams.get('mechanic')!));
    if (path.searchParams.get('date')) add('t.created_at::date=?', textField(path.searchParams.get('date'), 'Date', 10, 10));
    if (path.searchParams.get('q')) add('(t.reference ILIKE ? OR c.name ILIKE ?)', `%${textField(path.searchParams.get('q'), 'Recherche', 1, 80)}%`);
    const search = path.searchParams.get('q');
    if (search) { const i = values.length; conditions[conditions.length - 1] = `(t.reference ILIKE $${i} OR c.name ILIKE $${i})`; }
    const rows = await pool.query(`SELECT ${ticketColumns} ${ticketJoin} WHERE ${conditions.join(' AND ')} ORDER BY t.created_at DESC LIMIT 200`, values);
    return send(res, 200, rows.rows);
  }
  if (parts.length < 4) throw new HttpError(404, 'Route introuvable.');
  const reference = textField(parts[3], 'Référence', 1, 40);
  if (method === 'GET' && parts.length === 4) {
    const ticket = await staffTicket(reference, auth);
    return send(res, 200, { ...ticket, events: await ticketEvents(ticket.id) });
  }
  if (method === 'PATCH' && parts[4] === 'status' && parts.length === 5) {
    const status = ticketStatus((await body(req)).status);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const ticket = await staffTicket(reference, auth, true, client);
      if (!canTransition(ticket.status, status, auth.role)) throw new HttpError(409, 'Transition de statut interdite.');
      if (status === 'assigned' && !ticket.assignedMechanicUserId) throw new HttpError(409, 'Assignez d’abord un mécanicien.');
      await client.query(`UPDATE tickets SET status=$2,updated_at=now(),
        assigned_mechanic_user_id=CASE WHEN $2='triage' THEN NULL ELSE assigned_mechanic_user_id END,
        completed_at=CASE WHEN $2='completed' THEN now() ELSE completed_at END,
        cancelled_at=CASE WHEN $2='cancelled' THEN now() ELSE cancelled_at END WHERE id=$1`, [ticket.id, status]);
      await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,old_value,new_value)
        VALUES ($1,$2,$3,$4,$5)`, [ticket.id, auth.userId, status === 'completed' ? 'ticket_completed' : status === 'cancelled' ? 'ticket_cancelled' : 'status_changed', ticket.status, status]);
      if (status === 'triage' && ticket.assignedMechanicUserId) await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,old_value,new_value)
        VALUES ($1,$2,'mechanic_reassigned',$3,NULL)`, [ticket.id, auth.userId, ticket.assignedMechanicUserId]);
      if (ticket.appointmentId) {
        const mapped: Record<string,string> = { triage: ticket.interventionType === 'Urgence' ? 'Dépannage demandé' : 'Confirmé', assigned: 'Pris en charge', in_progress: 'En cours', completed: 'Terminé', cancelled: 'Annulé' };
        if (mapped[status]) await client.query('UPDATE appointments SET status=$2 WHERE id=$1', [ticket.appointmentId, mapped[status]]);
      }
      await client.query('COMMIT');
      return send(res, 200, { ...ticket, status });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  if (method === 'PATCH' && parts[4] === 'assign' && parts.length === 5) {
    if (auth.role !== 'workshop_manager') throw new HttpError(403, 'Accès refusé.');
    const mechanicId = uuid(String((await body(req)).mechanicUserId || ''));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const mechanic = await client.query(`SELECT 1 FROM users WHERE id=$1 AND role='mechanic' AND status='active'`, [mechanicId]);
      if (!mechanic.rowCount) throw new HttpError(400, 'Mécanicien indisponible.');
      const ticket = await staffTicket(reference, auth, true, client);
      if (!['triage','assigned'].includes(ticket.status)) throw new HttpError(409, 'Qualifiez le ticket avant de l’assigner.');
      if (ticket.assignedMechanicUserId === mechanicId) throw new HttpError(409, 'Ce mécanicien est déjà assigné.');
      await client.query(`UPDATE tickets SET assigned_mechanic_user_id=$2,status='assigned',updated_at=now() WHERE id=$1`, [ticket.id, mechanicId]);
      await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,old_value,new_value) VALUES ($1,$2,$3,$4,$5)`,
        [ticket.id, auth.userId, ticket.assignedMechanicUserId ? 'mechanic_reassigned' : 'mechanic_assigned', ticket.assignedMechanicUserId, mechanicId]);
      if (ticket.status !== 'assigned') await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,old_value,new_value) VALUES ($1,$2,'status_changed',$3,'assigned')`, [ticket.id, auth.userId, ticket.status]);
      if (ticket.appointmentId) await client.query(`UPDATE appointments SET status='Pris en charge' WHERE id=$1`, [ticket.appointmentId]);
      await client.query('COMMIT');
      return send(res, 200, { ok: true });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  if (method === 'PATCH' && parts[4] === 'note' && parts.length === 5) {
    const note = textField((await body(req)).note, 'Note publique', 0, 2000);
    const ticket = await staffTicket(reference, auth);
    if (!ticket.appointmentId) throw new HttpError(409, 'Ce ticket ne possède pas de demande liée.');
    await pool.query('UPDATE appointments SET mechanic_note=$2 WHERE id=$1', [ticket.appointmentId, note]);
    return send(res, 200, { ok: true });
  }
  throw new HttpError(404, 'Route introuvable.');
}

async function adminRoute(req: IncomingMessage, res: ServerResponse, parts: string[], method: string, path: URL) {
  const auth = await requireRole(req, ['admin']);
  if (method === 'GET' && parts[2] === 'users' && parts.length === 3) {
    const values: unknown[] = [];
    const filters: string[] = [];
    const role = path.searchParams.get('role');
    if (role) {
      if (!['customer','mechanic','workshop_manager','admin'].includes(role)) throw new HttpError(400, 'Rôle invalide.');
      values.push(role); filters.push(`u.role=$${values.length}`);
    }
    const q = path.searchParams.get('q');
    if (q) { values.push(`%${textField(q,'Recherche',1,80)}%`); filters.push(`(u.username ILIKE $${values.length} OR u.email ILIKE $${values.length} OR u.phone_e164 ILIKE $${values.length} OR u.first_name ILIKE $${values.length} OR u.last_name ILIKE $${values.length} OR c.name ILIKE $${values.length})`); }
    const rows = await pool.query(`SELECT u.id,u.role,u.status,u.username,u.email,u.phone_e164 AS phone,
      COALESCE(u.first_name,c.first_name) AS "firstName",COALESCE(u.last_name,c.last_name) AS "lastName",
      u.phone_verified_at AS "phoneVerifiedAt",COALESCE(lc.must_change_password,false) AS "mustChangePassword",u.created_at AS "createdAt",
      (SELECT max(s.last_seen_at) FROM user_sessions s WHERE s.user_id=u.id) AS "lastActivity"
      FROM users u LEFT JOIN customers c ON c.user_id=u.id LEFT JOIN local_credentials lc ON lc.user_id=u.id ${filters.length ? `WHERE ${filters.join(' AND ')}` : ''}
      ORDER BY u.created_at DESC LIMIT 200`, values);
    return send(res, 200, rows.rows);
  }
  if (method === 'POST' && parts[2] === 'users' && parts.length === 3) {
    limit(`admin-create:${auth.userId}`, 30, 60 * 60_000);
    const input = await body(req);
    const role = input.role;
    if (!['customer','mechanic','workshop_manager','admin'].includes(String(role))) throw new HttpError(400, 'Rôle invalide.');
    const firstName = textField(input.firstName, 'Prénom', 1, 80);
    const lastName = textField(input.lastName, 'Nom', 1, 80);
    const isCustomer = role === 'customer';
    const phone = isCustomer ? normalizePhone(input.phone) : null;
    const username = isCustomer ? null : staffUsername(input.username);
    const email = isCustomer ? null : staffEmail(input.email);
    if (!isCustomer && !username) throw new HttpError(400, 'Username invalide : 3 à 32 caractères, commençant par une lettre, puis lettres, chiffres, point, tiret ou underscore.');
    if (!isCustomer && typeof input.email === 'string' && input.email.trim() && !email) throw new HttpError(400, 'Email invalide.');
    const temporary = isCustomer ? null : temporaryPassword();
    const digest = temporary ? await hashPassword(temporary) : null;
    const userId = randomUUID(); const customerId = isCustomer ? randomUUID() : null;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`INSERT INTO users(id,role,phone_e164,username,email,first_name,last_name)
        VALUES($1,$2,$3,$4,$5,$6,$7)`, [userId, role, phone, username, email, firstName, lastName]);
      if (isCustomer) await client.query(`INSERT INTO customers(id,user_id,name,phone,first_name,last_name)
        VALUES($1,$2,$3,$4,$5,$6)`, [customerId, userId, `${firstName} ${lastName}`, phone, firstName, lastName]);
      else {
        await client.query(`INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES($1,$2,'local',$3)`, [randomUUID(), userId, username]);
        await client.query(`INSERT INTO local_credentials(user_id,password_hash,must_change_password) VALUES($1,$2,true)`, [userId, digest]);
      }
      await client.query(`INSERT INTO admin_audit_events(actor_user_id,target_user_id,action) VALUES($1,$2,'admin_created_user')`, [auth.userId, userId]);
      await client.query('COMMIT');
      return send(res, 201, { id: userId, role, username, email, phone, temporaryPassword: temporary, phoneVerified: false });
    } catch (error) {
      await client.query('ROLLBACK');
      if ((error as { code?: string }).code === '23505') throw new HttpError(409, 'Cette identité est déjà utilisée.');
      throw error;
    } finally { client.release(); }
  }
  if (parts[2] !== 'users' || !parts[3]) throw new HttpError(404, 'Route introuvable.');
  const targetId = uuid(parts[3]);
  if (method === 'PATCH' && parts[4] === 'status' && parts.length === 5) {
    const status = (await body(req)).status;
    if (status !== 'active' && status !== 'disabled') throw new HttpError(400, 'Statut invalide.');
    if (targetId === auth.userId && status === 'disabled') throw new HttpError(409, 'Impossible de désactiver votre propre compte.');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const target = await client.query('SELECT role,status FROM users WHERE id=$1 FOR UPDATE', [targetId]);
      if (!target.rowCount) throw new HttpError(404, 'Utilisateur introuvable.');
      if (target.rows[0].role === 'admin' && target.rows[0].status === 'active' && status === 'disabled') {
        const admins = await client.query(`SELECT id FROM users WHERE role='admin' AND status='active' FOR UPDATE`);
        if ((admins.rowCount || 0) <= 1) throw new HttpError(409, 'Le dernier administrateur actif ne peut pas être désactivé.');
      }
      await client.query('UPDATE users SET status=$2,updated_at=now() WHERE id=$1', [targetId, status]);
      if (status === 'disabled') await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [targetId]);
      await client.query(`INSERT INTO admin_audit_events(actor_user_id,target_user_id,action) VALUES($1,$2,$3)`,
        [auth.userId, targetId, status === 'active' ? 'admin_enabled_user' : 'admin_disabled_user']);
      await client.query('COMMIT'); return send(res, 200, { ok: true });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  if (method === 'POST' && parts[4] === 'reset-password' && parts.length === 5) {
    limit(`admin-reset:${auth.userId}`, 20, 60 * 60_000);
    const temporary = temporaryPassword(); const digest = await hashPassword(temporary);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const target = await client.query('SELECT role FROM users WHERE id=$1 FOR UPDATE', [targetId]);
      if (!target.rowCount || !isStaffRole(target.rows[0].role)) throw new HttpError(404, 'Compte staff introuvable.');
      await client.query(`UPDATE local_credentials SET password_hash=$2,must_change_password=true,password_changed_at=NULL WHERE user_id=$1`, [targetId, digest]);
      await client.query('UPDATE users SET updated_at=now() WHERE id=$1', [targetId]);
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [targetId]);
      await client.query(`INSERT INTO admin_audit_events(actor_user_id,target_user_id,action) VALUES($1,$2,'admin_reset_password')`, [auth.userId, targetId]);
      await client.query('COMMIT'); return send(res, 200, { temporaryPassword: temporary });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  if (method === 'PATCH' && parts[4] === 'role' && parts.length === 5) {
    const role = (await body(req)).role;
    if (!isStaffRole(role)) throw new HttpError(400, 'Rôle staff invalide.');
    if (targetId === auth.userId) throw new HttpError(409, 'Impossible de changer votre propre rôle.');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const target = await client.query('SELECT role,status FROM users WHERE id=$1 FOR UPDATE', [targetId]);
      if (!target.rowCount || !isStaffRole(target.rows[0].role)) throw new HttpError(404, 'Compte staff introuvable.');
      if (target.rows[0].role === 'admin' && role !== 'admin' && target.rows[0].status === 'active') {
        const admins = await client.query(`SELECT id FROM users WHERE role='admin' AND status='active' FOR UPDATE`);
        if ((admins.rowCount || 0) <= 1) throw new HttpError(409, 'Le dernier administrateur actif ne peut pas changer de rôle.');
      }
      await client.query('UPDATE users SET role=$2,updated_at=now() WHERE id=$1', [targetId, role]);
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1', [targetId]);
      await client.query(`INSERT INTO admin_audit_events(actor_user_id,target_user_id,action) VALUES($1,$2,'admin_changed_role')`, [auth.userId, targetId]);
      await client.query('COMMIT'); return send(res, 200, { ok: true });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
  throw new HttpError(404, 'Route introuvable.');
}

async function route(req: IncomingMessage, res: ServerResponse) {
  const method = req.method || 'GET';
  const path = new URL(req.url || '/', 'http://localhost');
  const parts = path.pathname.split('/').filter(Boolean);
  if (['POST', 'PATCH'].includes(method) && !req.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'Content-Type application/json requis.');
  if (parts[0] !== 'api') throw new HttpError(404, 'Route introuvable.');

  if (method === 'GET' && parts[1] === 'health' && parts.length === 2) {
    await pool.query('SELECT 1');
    return send(res, 200, { status: 'ok', mode: testMode ? 'test' : 'production' });
  }
  if (parts[1] === 'staff') return staffRoute(req, res, parts, method, path);
  if (parts[1] === 'admin') return adminRoute(req, res, parts, method, path);
  if (parts[1] === 'auth') {
    if (method === 'POST' && parts[2] === 'register' && parts[3] === 'request-otp') return send(res, 200, await createChallenge(req, await body(req), 'register'));
    if (method === 'POST' && parts[2] === 'register' && parts[3] === 'verify-otp') return send(res, 201, await verifyChallenge(req, await body(req), 'register', res));
    if (method === 'POST' && parts[2] === 'login' && parts[3] === 'request-otp') return send(res, 200, await createChallenge(req, await body(req), 'login'));
    if (method === 'POST' && parts[2] === 'login' && parts[3] === 'verify-otp') return send(res, 200, await verifyChallenge(req, await body(req), 'login', res));
    if (method === 'POST' && parts[2] === 'phone-change' && parts[3] === 'request-otp') { const auth = await identity(req); return send(res, 200, await createChallenge(req, await body(req), 'phone_change', auth.userId)); }
    if (method === 'POST' && parts[2] === 'phone-change' && parts[3] === 'verify-otp') { const auth = await identity(req); return send(res, 200, await verifyChallenge(req, await body(req), 'phone_change', res, auth.userId)); }
    if (method === 'POST' && parts[2] === 'refresh') {
      limit(`refresh:${clientIp(req)}`, 30, 15 * 60_000); const token = cookie(req, 'mms_refresh'); if (!token) throw new HttpError(401, 'Session expirée.');
      const hash = createHmac('sha256', accessSecret).update(token).digest('hex');
      const found = await pool.query(`UPDATE user_sessions s SET revoked_at=now() FROM users u
        LEFT JOIN customers c ON c.user_id=u.id LEFT JOIN local_credentials lc ON lc.user_id=u.id WHERE s.user_id=u.id AND s.refresh_token_hash=$1
        AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'
        RETURNING s.user_id,u.role,COALESCE(lc.must_change_password,false) AS must_change_password,c.id AS customer_id`, [hash]);
      if (!found.rowCount) throw new HttpError(401, 'Session expirée.');
      return send(res, 200, await issueSession(found.rows[0].user_id, found.rows[0].customer_id || '', req, res, found.rows[0].role));
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
    if (method === 'GET' && parts[3] === 'tickets' && parts.length === 5) {
      const reference = textField(parts[4], 'Référence', 1, 40);
      const result = await pool.query(`SELECT ${ticketColumns} ${ticketJoin} WHERE t.reference=$1 AND t.customer_id=$2`, [reference, customerId]);
      if (!result.rowCount) throw new HttpError(404, 'Ticket introuvable.');
      return send(res, 200, { ...customerTicket(result.rows[0]), events: await ticketEvents(result.rows[0].id, true) });
    }
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
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`INSERT INTO appointments (id, customer_id, vehicle_id, problem, diagnosis, kind, address,
          appointment_date, appointment_time, status, contact_phone, immobilized)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [id, customerId, vehicleId, problem, diagnosis, kind, address, date, time, kind === 'Urgence' ? 'Dépannage demandé' : 'Confirmé', contactPhone, immobilized]);
        const sequence = await client.query(`SELECT nextval('ticket_reference_seq')::text AS n`);
        const ticketId = randomUUID();
        const reference = ticketReference(sequence.rows[0].n);
        await client.query(`INSERT INTO tickets(id,reference,customer_id,vehicle_id,appointment_id,intervention_type,description,status,created_by_user_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,'new',$8)`, [ticketId, reference, customerId, vehicleId, id, kind, problem, auth.userId]);
        await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,new_value)
          VALUES($1,$2,'ticket_created','new')`, [ticketId, auth.userId]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        if ((error as { code?: string }).code === '23505') throw new HttpError(409, 'Ce créneau vient d’être réservé. Choisissez-en un autre.');
        throw error;
      } finally { client.release(); }
      const data = await customerData(customerId);
      return send(res, 201, { ...data.appointments.find((appointment: { id: string }) => appointment.id === id), ticket: data.tickets.find((ticket: { appointmentId: string }) => ticket.appointmentId === id) });
    }
    if (method === 'PATCH' && parts[3] === 'appointments' && parts[4] && parts[5] === 'cancel' && parts.length === 6) {
      const id = uuid(parts[4]);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const ticket = await client.query(`SELECT id,status FROM tickets WHERE appointment_id=$1 AND customer_id=$2 FOR UPDATE`, [id, customerId]);
        if (!ticket.rowCount || !canTransition(ticket.rows[0].status, 'cancelled', 'customer')) throw new HttpError(409, 'Cette demande ne peut plus être annulée.');
        const result = await client.query(`UPDATE appointments SET status='Annulé' WHERE id=$1 AND customer_id=$2
          AND status IN ('Confirmé','Dépannage demandé') RETURNING id`, [id, customerId]);
        if (!result.rowCount) throw new HttpError(409, 'Cette demande ne peut plus être annulée.');
        await client.query(`UPDATE tickets SET status='cancelled',cancelled_at=now(),updated_at=now() WHERE id=$1`, [ticket.rows[0].id]);
        await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,old_value,new_value)
          VALUES($1,$2,'ticket_cancelled',$3,'cancelled')`, [ticket.rows[0].id, auth.userId, ticket.rows[0].status]);
        await client.query('COMMIT'); return send(res, 200, { status: 'Annulé' });
      } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
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
  }
  throw new HttpError(404, 'Route introuvable.');
}

async function start() {
  const schema = await readFile(join(__dirname, '../src/schema.sql'), 'utf8');
  await pool.query(schema);
  const refreshTrustedNginx = async () => {
    try { const addresses = await lookup('mms', { all: true }); trustedNginxPeers.clear(); for (const address of addresses) trustedNginxPeers.add(address.address); }
    catch { trustedNginxPeers.clear(); }
  };
  await refreshTrustedNginx();
  const proxyTimer = setInterval(() => { void refreshTrustedNginx(); }, 15_000);
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
  process.on('SIGTERM', () => { clearInterval(proxyTimer); server.close(); void pool.end(); });
}
start().catch(error => { console.error('Démarrage API impossible', error); process.exit(1); });
