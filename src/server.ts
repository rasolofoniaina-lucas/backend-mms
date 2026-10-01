import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Pool } from 'pg';
import { normalizeMalagasyPhone } from './phone.js';
import { createSmsProvider, SmsProviderError } from './sms-provider.js';
import { FacebookOAuthError, facebookAuthorizationUrl, facebookConfig, fetchFacebookProfile, type FacebookConfig } from './facebook-auth.js';
import { HttpError, integerField, textField } from './http.js';
import { commerceRoute, shopRoute, type ShopDeps } from './shop.js';
import { canTransition, hashPassword, isStaffRole, staffEmail, staffUsername, temporaryPassword, validPassword, verifyPassword, type Role, type TicketStatus } from './staff-domain.js';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');
if (!process.env.OTP_PEPPER || !process.env.ACCESS_TOKEN_SECRET) throw new Error('OTP_PEPPER et ACCESS_TOKEN_SECRET sont requis.');
if (!process.env.CUSTOMER_PIN_PEPPER) throw new Error('CUSTOMER_PIN_PEPPER est requis.');
const otpPepper = process.env.OTP_PEPPER;
const accessSecret = process.env.ACCESS_TOKEN_SECRET;
const customerPinPepper = process.env.CUSTOMER_PIN_PEPPER;
const testMode = process.env.MMS_TEST_MODE === '1';
const smsProvider = createSmsProvider(process.env);
const cookieSecure = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
const termsVersion = process.env.TERMS_VERSION || '1.0';
const privacyVersion = process.env.PRIVACY_VERSION || '1.0';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
pool.on('error', error => console.error('Connexion PostgreSQL interrompue', error));

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const datePattern = /^\d{4}-\d{2}-\d{2}$/;
const maxPhotoBytes = 5 * 1024 * 1024;
const vehicleFields = `v.id, v.name, v.model, v.plate, v.color,
  v.displacement_cc AS "displacementCc", v.production_year AS year,
  CASE WHEN p.vehicle_id IS NOT NULL THEN '/api/customers/' || v.customer_id || '/vehicles/' || v.id ||
    '/photo?updated=' || (extract(epoch from p.updated_at) * 1000)::bigint ELSE NULL END AS "photoUrl"`;


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
  return (testMode || trustedNginxPeers.has(peer)) && typeof real === 'string' && isIP(real) ? real : peer;
}
function normalizePhone(value: unknown) {
  const raw = textField(value, 'Numéro de téléphone', 6, 40);
  const phone = normalizeMalagasyPhone(raw);
  if (!phone) throw new HttpError(400, 'Entrez un numéro de téléphone malgache valide.');
  return phone;
}
function isYasPhone(phone: string) {
  // Centralised until a commercial numbering configuration is supplied.
  const prefixes = (process.env.YAS_PHONE_PREFIXES || '+26134').split(',').map(value => value.trim()).filter(Boolean);
  return prefixes.some(prefix => phone.startsWith(prefix));
}
function pin(value: unknown) {
  if (typeof value !== 'string' || !/^\d{6}$/.test(value)) throw new HttpError(400, 'Le code PIN doit contenir exactement six chiffres.');
  return value;
}
function customerPassword(value: unknown) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 128) throw new HttpError(400, 'Le mot de passe doit contenir au moins 8 caractères.');
  return value;
}
function customerEmail(value: unknown) {
  if (typeof value !== 'string') throw new HttpError(400, 'Adresse e-mail invalide.');
  const email = value.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new HttpError(400, 'Adresse e-mail invalide.');
  return email;
}
const pinSecret = (value: string) => `${value}:${customerPinPepper}`;
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
    if (token.exp * 1000 <= Date.now() || !['customer','mechanic','workshop_manager','admin','commercial'].includes(token.role)) throw new Error(); return { userId: token.sub, customerId: token.cid, sessionId: token.sid, role: token.role as Role };
  } catch { throw new HttpError(401, 'Session expirée.'); }
}
async function identity(req: IncomingMessage, allowed: readonly Role[] = ['customer'], allowPasswordChange = false) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw new HttpError(401, 'Connexion requise.');
  const auth = verifyAccessToken(header.slice(7));
  const active = await pool.query(`SELECT u.role,COALESCE(lc.must_change_password,false) AS staff_must_change_password,
    COALESCE(cc.must_change_password,false) AS customer_must_change_password,c.id AS customer_id FROM user_sessions s
    JOIN users u ON u.id=s.user_id LEFT JOIN customers c ON c.user_id=u.id
    LEFT JOIN local_credentials lc ON lc.user_id=u.id LEFT JOIN customer_credentials cc ON cc.user_id=u.id
    WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'`,
  [auth.sessionId, auth.userId]);
  if (!active.rowCount || active.rows[0].role !== auth.role || (auth.role === 'customer' && active.rows[0].customer_id !== auth.customerId)) throw new HttpError(401, 'Session expirée.');
  if (!allowed.includes(auth.role)) throw new HttpError(403, 'Accès refusé.');
  const mustChangePassword = auth.role === 'customer' ? active.rows[0].customer_must_change_password : active.rows[0].staff_must_change_password;
  if (mustChangePassword && !allowPasswordChange) throw new HttpError(403, 'Vous devez changer votre mot de passe.', auth.role === 'customer' ? 'PASSWORD_CHANGE_REQUIRED' : undefined);
  await pool.query(`UPDATE user_sessions SET last_seen_at=now() WHERE id=$1 AND last_seen_at < now()-interval '1 minute'`, [auth.sessionId]);
  return { ...auth, mustChangePassword };
}
function cookie(req: IncomingMessage, name: string) { return req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`))?.slice(name.length + 1); }
function refreshCookie(value: string, expiresAt: Date) { return `mms_refresh=${value}; Path=/api/auth; HttpOnly; SameSite=Lax; ${cookieSecure ? 'Secure; ' : ''}Expires=${expiresAt.toUTCString()}`; }
function clearRefreshCookie() { return `mms_refresh=; Path=/api/auth; HttpOnly; SameSite=Lax; ${cookieSecure ? 'Secure; ' : ''}Max-Age=0`; }
function appendCookie(res: ServerResponse, value: string) {
  const current = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', current ? [...(Array.isArray(current) ? current : [String(current)]), value] : value);
}
function facebookCookie(name: string, value: string, maxAge: number) { return `${name}=${value}; Path=/api/auth/facebook; HttpOnly; SameSite=Lax; ${cookieSecure ? 'Secure; ' : ''}Max-Age=${maxAge}`; }
function clearFacebookCookie(name: string) { return facebookCookie(name, '', 0); }
function maskedPhone(phone: string) { return phone.replace(/(\+261\s?\d\d)\d+(\d\d)/, '$1 ** *** $2'); }

function send(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function redirect(res: ServerResponse, location: string) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end();
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
const allStaffRoles: Role[] = ['mechanic', 'workshop_manager', 'admin', 'commercial'];
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
function weekdayFor(date: string) { return new Date(`${date}T12:00:00Z`).getUTCDay(); }
function slotRange(opens: string, closes: string) {
  const [oh, om] = opens.slice(0, 5).split(':').map(Number); const [ch, cm] = closes.slice(0, 5).split(':').map(Number);
  const start = oh * 60 + om; const end = ch * 60 + cm; const values: string[] = [];
  for (let minute = start; minute + 60 <= end; minute += 60) values.push(`${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`);
  return values;
}
async function availabilityFor(date: string, client: import('pg').Pool | import('pg').PoolClient = pool) {
  const rule = await client.query(`SELECT COALESCE(e.is_open,r.is_open) AS is_open,
    COALESCE(e.opens_at,r.opens_at)::text AS opens_at, COALESCE(e.closes_at,r.closes_at)::text AS closes_at
    FROM workshop_schedule_rules r LEFT JOIN workshop_schedule_exceptions e ON e.day=$1 WHERE r.weekday=$2`, [date, weekdayFor(date)]);
  if (!rule.rowCount || !rule.rows[0].is_open) return { slots: [] as string[], occupied: [] as string[] };
  const slots = slotRange(rule.rows[0].opens_at, rule.rows[0].closes_at);
  const [occupied, blocked] = await Promise.all([
    client.query(`SELECT to_char(appointment_time,'HH24:MI') AS time FROM appointments WHERE appointment_date=$1 AND status IN ('Confirmé','Pris en charge','En cours')`, [date]),
    client.query(`SELECT to_char(slot_time,'HH24:MI') AS time FROM blocked_slots WHERE slot_date=$1`, [date]),
  ]);
  return { slots, occupied: [...occupied.rows, ...blocked.rows].map(row => row.time) };
}
function scheduledKind(value: unknown): 'À domicile' | 'En atelier' {
  if (value === 'À domicile' || value === 'En atelier') return value;
  throw new HttpError(400, 'Type d’intervention invalide.');
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

async function issueSession(userId: string, customerId: string, req: IncomingMessage, res: ServerResponse, role: Role = 'customer', expectedCustomerPasswordHash?: string | null) {
  const credential = role === 'customer' ? await pool.query(`SELECT must_change_password,temporary_password_expires_at FROM customer_credentials WHERE user_id=$1`, [userId]) : null;
  const restricted = role === 'customer' && credential?.rows[0]?.must_change_password === true;
  if (restricted && (!credential?.rows[0]?.temporary_password_expires_at || new Date(credential.rows[0].temporary_password_expires_at) <= new Date())) throw new HttpError(401, "Ce mot de passe temporaire a expiré. Contactez l'atelier.");
  const sessionId = randomUUID(); const refresh = randomBytes(32).toString('base64url'); const hash = createHmac('sha256', accessSecret).update(refresh).digest('hex');
  // Restricted sessions last 15 minutes. A refresh may rotate them only while
  // the temporary credential is valid; an already issued session may finish
  // the password change during its remaining short lifetime.
  const expires = new Date(Date.now() + (restricted ? 15 * 60 * 1000 : (role === 'customer' ? 90 : 30) * 24 * 60 * 60 * 1000));
  const agent = String(req.headers['user-agent'] || '').slice(0, 300);
  const label = /android/i.test(agent) ? 'Navigateur Android' : /iphone|ipad/i.test(agent) ? 'Navigateur iOS' : 'Navigateur web';
  await pool.query(`INSERT INTO user_sessions (id,user_id,refresh_token_hash,user_agent,device_label,expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, [sessionId, userId, hash, agent, label, expires]);
  if (role === 'customer' && expectedCustomerPasswordHash !== undefined) {
    const current = await pool.query('SELECT password_hash FROM customer_credentials WHERE user_id=$1', [userId]);
    if ((current.rows[0]?.password_hash || null) !== expectedCustomerPasswordHash) {
      await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE id=$1', [sessionId]);
      throw new HttpError(401, 'Session expirée.');
    }
  }
  appendCookie(res, refreshCookie(refresh, expires));
  if (role === 'customer') return restricted
    ? { accessToken: accessToken({ userId, customerId, sessionId, role }), user: { user: { id: customerId }, mustChangePassword: true }, mustChangePassword: true }
    : { accessToken: accessToken({ userId, customerId, sessionId, role }), user: await customerData(customerId), mustChangePassword: false };
  const user = await pool.query(`SELECT u.id,u.username,u.first_name AS "firstName",u.last_name AS "lastName",u.email,u.role,
    lc.must_change_password AS "mustChangePassword" FROM users u JOIN local_credentials lc ON lc.user_id=u.id WHERE u.id=$1`, [userId]);
  return { accessToken: accessToken({ userId, customerId: '', sessionId, role }), user: user.rows[0] };
}
async function createChallenge(req: IncomingMessage, input: Record<string, unknown>, purpose: 'register' | 'login' | 'phone_change', userId?: string) {
  const phone = normalizePhone(input.phone); limit(`otp:ip:${clientIp(req)}`, 12, 15 * 60_000); limit(`otp:phone:${phone}`, 4, 15 * 60_000);
  if (isYasPhone(phone) && purpose !== 'phone_change') throw new HttpError(409, 'Ce numéro nécessite une validation manuelle par l’atelier. Créez votre code PIN pour continuer.');
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
      await client.query(`INSERT INTO users (id,phone_e164,role,phone_verified_at,phone_verification_status,phone_verified_method) VALUES ($1,$2,'customer',now(),'verified_otp','otp')`, [userId, challenge.phone_e164]);
      await client.query(`INSERT INTO customers (id,user_id,name,phone,first_name,last_name,terms_accepted_at,terms_version,privacy_accepted_at,privacy_version)
        VALUES ($1,$2,$3,$4,$5,$6,now(),$7,now(),$8)`, [customerId, userId, `${challenge.registration_first_name} ${challenge.registration_last_name}`, challenge.phone_e164, challenge.registration_first_name, challenge.registration_last_name, termsVersion, privacyVersion]);
    } else if (purpose === 'login') {
      const profile = await client.query('SELECT c.id, u.id AS user_id FROM users u JOIN customers c ON c.user_id=u.id WHERE u.phone_e164=$1 AND u.status=\'active\'', [challenge.phone_e164]);
      if (!profile.rowCount) throw new HttpError(404, 'Aucun compte ne correspond à ce numéro.'); userId = profile.rows[0].user_id; customerId = profile.rows[0].id;
      await client.query(`UPDATE users SET phone_verified_at=COALESCE(phone_verified_at,now()),phone_verification_status='verified_otp',phone_verified_method='otp' WHERE id=$1`, [userId]);
    } else {
      if (!userId) throw new HttpError(400, 'Demande OTP introuvable.');
      const profile = await client.query('SELECT id FROM customers WHERE user_id=$1', [userId]); if (!profile.rowCount) throw new HttpError(404, 'Compte introuvable.'); customerId = profile.rows[0].id;
      await client.query(`UPDATE users SET phone_e164=$2, phone_verified_at=now(),phone_verification_status='verified_otp',phone_verified_method='otp', updated_at=now() WHERE id=$1`, [userId, challenge.phone_e164]);
      await client.query('UPDATE customers SET phone=$2 WHERE id=$1', [customerId, challenge.phone_e164]);
      // A changed identity invalidates sessions issued for the previous number.
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [userId]);
    }
    await client.query('UPDATE otp_challenges SET consumed_at=now() WHERE id=$1', [challengeId]); await client.query('COMMIT');
    if (testMode) await unlink(`/tmp/mms-test-otp-${challengeId}`).catch(() => undefined);
    return await issueSession(userId, customerId!, req, res);
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
}

async function customerPinLogin(req: IncomingMessage, input: Record<string, unknown>, res: ServerResponse) {
  const phone = normalizePhone(input.phone); const value = pin(input.pin);
  limit(`customer-pin-ip:${clientIp(req)}`, 20, 15 * 60_000); limit(`customer-pin-phone:${phone}`, 8, 15 * 60_000);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(`SELECT u.id AS user_id,c.id AS customer_id,p.pin_hash,p.failed_attempts,p.locked_until
      FROM users u JOIN customers c ON c.user_id=u.id LEFT JOIN customer_pin_credentials p ON p.user_id=u.id
      WHERE u.phone_e164=$1 AND u.status='active' FOR UPDATE`, [phone]);
    const generic = new HttpError(401, 'Numéro ou code PIN incorrect.');
    if (!found.rowCount || !found.rows[0].pin_hash) throw generic;
    const row = found.rows[0];
    if (row.locked_until && new Date(row.locked_until) > new Date()) throw new HttpError(429, 'Trop de tentatives. Réessayez dans 15 minutes.');
    if (!await verifyPassword(row.pin_hash, pinSecret(value))) {
      const failures = Number(row.failed_attempts) + 1;
      await client.query(`UPDATE customer_pin_credentials SET failed_attempts=$2,locked_until=CASE WHEN $2>=5 THEN now()+interval '15 minutes' ELSE NULL END,updated_at=now() WHERE user_id=$1`, [row.user_id, failures]);
      await client.query('COMMIT'); throw generic;
    }
    await client.query('UPDATE customer_pin_credentials SET failed_attempts=0,locked_until=NULL,updated_at=now() WHERE user_id=$1', [row.user_id]);
    await client.query('COMMIT');
    return issueSession(row.user_id, row.customer_id, req, res);
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
}
async function setCustomerPin(req: IncomingMessage, input: Record<string, unknown>, res: ServerResponse) {
  const auth = await identity(req); const value = pin(input.pin); limit(`customer-pin-set:${auth.userId}`, 5, 60 * 60_000);
  const digest = await hashPassword(pinSecret(value));
  await pool.query(`INSERT INTO customer_pin_credentials(user_id,pin_hash,failed_attempts,locked_until) VALUES($1,$2,0,NULL)
    ON CONFLICT(user_id) DO UPDATE SET pin_hash=excluded.pin_hash,failed_attempts=0,locked_until=NULL,updated_at=now()`, [auth.userId, digest]);
  return send(res, 200, { ok: true });
}
async function createYasCustomer(req: IncomingMessage, input: Record<string, unknown>, res: ServerResponse) {
  const phone = normalizePhone(input.phone); if (!isYasPhone(phone)) throw new HttpError(400, 'Ce parcours est réservé aux numéros Yas.');
  const firstName = textField(input.firstName, 'Prénom', 1, 80); const lastName = textField(input.lastName, 'Nom', 1, 80); const value = pin(input.pin);
  if (input.termsAccepted !== true || input.privacyAccepted !== true) throw new HttpError(400, 'Vous devez accepter les conditions et la politique de confidentialité.');
  limit(`yas-register-ip:${clientIp(req)}`, 8, 60 * 60_000);
  const userId = randomUUID(), customerId = randomUUID(), digest = await hashPassword(pinSecret(value)); const client = await pool.connect();
  try { await client.query('BEGIN');
    await client.query(`INSERT INTO users(id,phone_e164,role,phone_verification_status) VALUES($1,$2,'customer','pending_manual')`, [userId, phone]);
    await client.query(`INSERT INTO customers(id,user_id,name,phone,first_name,last_name,terms_accepted_at,terms_version,privacy_accepted_at,privacy_version) VALUES($1,$2,$3,$4,$5,$6,now(),$7,now(),$8)`, [customerId,userId,`${firstName} ${lastName}`,phone,firstName,lastName,termsVersion,privacyVersion]);
    await client.query('INSERT INTO customer_pin_credentials(user_id,pin_hash) VALUES($1,$2)', [userId,digest]); await client.query('COMMIT');
    return issueSession(userId, customerId, req, res);
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); if ((error as {code?:string}).code==='23505') throw new HttpError(409,'Un compte existe déjà avec ce numéro.'); throw error; } finally { client.release(); }
}
async function registerCustomerPassword(req: IncomingMessage, input: Record<string, unknown>, res: ServerResponse) {
  const firstName = textField(input.firstName, 'Prénom', 1, 80); const lastName = textField(input.lastName, 'Nom', 1, 80);
  const phone = normalizePhone(input.phone); const email = customerEmail(input.email); const password = customerPassword(input.password);
  limit(`customer-register-ip:${clientIp(req)}`, 10, 60 * 60_000);
  const claimToken = typeof input.claimToken === 'string' ? input.claimToken : ''; const client = await pool.connect(); const userId = randomUUID(); let customerId = randomUUID();
  try { await client.query('BEGIN');
    const conflict = await client.query(`SELECT u.id FROM users u LEFT JOIN customers c ON c.user_id=u.id WHERE u.status='active' AND (u.phone_e164=$1 OR lower(c.email)=lower($2)) FOR UPDATE OF u`, [phone,email]);
    if (conflict.rowCount) throw new HttpError(409, 'Ces coordonnées sont déjà associées à un autre compte. Contactez l’atelier pour obtenir de l’aide.');
    let claimId: string | null = null;
    if (claimToken) {
      const claimHash = createHmac('sha256', accessSecret).update(`booking:${claimToken}`).digest('hex');
      const claim = await client.query(`SELECT bc.id,bc.customer_id,c.user_id FROM booking_claims bc JOIN customers c ON c.id=bc.customer_id JOIN tickets t ON t.id=bc.ticket_id WHERE bc.token_hash=$1 AND bc.expires_at>now() AND bc.consumed_at IS NULL FOR UPDATE`, [claimHash]);
      if (!claim.rowCount) throw new HttpError(409, 'Cette demande ne peut plus être rattachée automatiquement à un compte. Contactez l’atelier si vous avez besoin d’aide.');
      if (claim.rows[0].user_id) throw new HttpError(409, 'Cette demande a déjà été associée à un espace MMS.');
      claimId = claim.rows[0].id; customerId = claim.rows[0].customer_id;
    }
    const digest = await hashPassword(password);
    await client.query(`INSERT INTO users(id,phone_e164,role,phone_verification_status,email_verified_at) VALUES($1,$2,'customer','unverified',NULL)`,[userId,phone]);
    if (claimId) await client.query(`UPDATE customers SET user_id=$2 WHERE id=$1`, [customerId,userId]);
    else await client.query(`INSERT INTO customers(id,user_id,name,phone,email,first_name,last_name,terms_accepted_at,terms_version,privacy_accepted_at,privacy_version) VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,now(),$9)`,[customerId,userId,`${firstName} ${lastName}`,phone,email,firstName,lastName,termsVersion,privacyVersion]);
    await client.query(`INSERT INTO customer_credentials(user_id,password_hash,password_changed_at) VALUES($1,$2,now())`,[userId,digest]);
    if (claimId) await client.query(`UPDATE booking_claims SET consumed_at=now() WHERE id=$1`, [claimId]);
    await client.query('COMMIT'); return issueSession(userId,customerId,req,res);
  } catch(error) { await client.query('ROLLBACK').catch(()=>undefined); if ((error as {code?:string}).code==='23505') throw new HttpError(409,'Ces coordonnées sont déjà associées à un autre compte. Contactez l’atelier pour obtenir de l’aide.'); throw error; } finally { client.release(); }
}
async function claimBooking(auth: Identity, input: Record<string, unknown>) {
  const token = typeof input.claimToken === 'string' ? input.claimToken : '';
  if (!token || token.length > 256) throw new HttpError(400, 'Jeton de rattachement invalide.');
  const hash = createHmac('sha256', accessSecret).update(`booking:${token}`).digest('hex'); const client = await pool.connect();
  try { await client.query('BEGIN');
    const claim = await client.query(`SELECT bc.id,bc.customer_id,bc.ticket_id,bc.consumed_at,bc.expires_at,c.user_id FROM booking_claims bc JOIN customers c ON c.id=bc.customer_id JOIN tickets t ON t.id=bc.ticket_id WHERE bc.token_hash=$1 FOR UPDATE`, [hash]);
    if (!claim.rowCount) throw new HttpError(400, 'Jeton de rattachement invalide.');
    const row = claim.rows[0];
    if (row.consumed_at) throw new HttpError(409, 'Cette demande a déjà été associée à un espace MMS.');
    if (new Date(row.expires_at) <= new Date()) throw new HttpError(409, 'Cette demande ne peut plus être rattachée automatiquement à un compte. Contactez l’atelier si vous avez besoin d’aide.');
    if (row.user_id && row.user_id !== auth.userId) { console.warn('booking claim ownership anomaly', { claimId: row.id }); throw new HttpError(409, 'Cette demande a déjà été associée à un espace MMS.'); }
    if (!row.user_id) {
      // The authenticated account already owns its customer profile: move only
      // the claimed booking graph, never any similarly named historical data.
      await client.query('UPDATE vehicles SET customer_id=$2 WHERE customer_id=$1', [row.customer_id,auth.customerId]);
      await client.query('UPDATE appointments SET customer_id=$2 WHERE customer_id=$1', [row.customer_id,auth.customerId]);
      await client.query('UPDATE tickets SET customer_id=$2 WHERE id=$1', [row.ticket_id,auth.customerId]);
    }
    await client.query('UPDATE booking_claims SET consumed_at=now() WHERE id=$1', [row.id]); await client.query('COMMIT');
    return customerData(auth.customerId);
  } catch (error) { await client.query('ROLLBACK').catch(()=>undefined); throw error; } finally { client.release(); }
}
async function customerPasswordLogin(req: IncomingMessage, input: Record<string, unknown>, res: ServerResponse) {
  const identifier = textField(input.identifier,'Identifiant',3,254); const password = typeof input.password === 'string' ? input.password : '';
  let phone: string | null = null; let email: string | null = null;
  if (identifier.includes('@')) email = customerEmail(identifier); else phone = normalizePhone(identifier);
  limit(`customer-password-login-ip:${clientIp(req)}`,20,15*60_000); limit(`customer-password-login-id:${(email||phone)!}`,8,15*60_000);
  const generic = new HttpError(401,'Identifiant ou mot de passe incorrect.');
  const found = await pool.query(`SELECT u.id AS user_id,c.id AS customer_id,cc.password_hash,cc.must_change_password,cc.temporary_password_expires_at FROM users u JOIN customers c ON c.user_id=u.id JOIN customer_credentials cc ON cc.user_id=u.id WHERE u.status='active' AND (($1::text IS NOT NULL AND lower(c.email)=lower($1)) OR ($2::text IS NOT NULL AND u.phone_e164=$2))`,[email,phone]);
  if (!found.rowCount || !await verifyPassword(found.rows[0].password_hash,password)) throw generic;
  if (found.rows[0].must_change_password && (!found.rows[0].temporary_password_expires_at || new Date(found.rows[0].temporary_password_expires_at) <= new Date())) throw new HttpError(401, "Ce mot de passe temporaire a expiré. Contactez l'atelier.");
  const session = await issueSession(found.rows[0].user_id,found.rows[0].customer_id,req,res,'customer',found.rows[0].password_hash);
  return { ...session, mustChangePassword: Boolean(found.rows[0].must_change_password) };
}
function requiredFacebookConfig(): FacebookConfig {
  try {
    const config = facebookConfig(process.env);
    if (!config) throw new FacebookOAuthError('configuration');
    return config;
  } catch (error) {
    if (error instanceof FacebookOAuthError && error.phase === 'configuration') throw new HttpError(503, 'Facebook Login n’est pas configuré.');
    throw error;
  }
}
function facebookStateSignature(state: string, expires: number) {
  return createHmac('sha256', accessSecret).update(`facebook-state:${state}:${expires}`).digest('base64url');
}
function facebookStateCookie() {
  const state = randomBytes(32).toString('base64url');
  const expires = Date.now() + 10 * 60_000;
  return { state, value: `${state}.${expires}.${facebookStateSignature(state, expires)}` };
}
function validFacebookState(req: IncomingMessage, received: string | null) {
  const saved = cookie(req, 'mms_facebook_state');
  if (!saved || !received) return false;
  const [state, expiresRaw, signature] = saved.split('.');
  const expires = Number(expiresRaw);
  if (!state || !signature || !Number.isFinite(expires) || expires <= Date.now() || state !== received) return false;
  const expected = facebookStateSignature(state, expires);
  return expected.length === signature.length && timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
function facebookPendingHash(token: string) {
  return createHmac('sha256', accessSecret).update(`facebook-pending:${token}`).digest('hex');
}
function splitFacebookName(name: string) {
  const values = name.trim().split(/\s+/).filter(Boolean);
  return { firstName: values.shift() || '', lastName: values.join(' ') };
}
async function beginFacebook(req: IncomingMessage, res: ServerResponse) {
  limit(`facebook-start:${clientIp(req)}`, 30, 15 * 60_000);
  const config = requiredFacebookConfig();
  const state = facebookStateCookie();
  appendCookie(res, facebookCookie('mms_facebook_state', state.value, 600));
  return redirect(res, facebookAuthorizationUrl(config, state.state));
}
async function facebookCallback(req: IncomingMessage, res: ServerResponse, path: URL) {
  const stateValid = validFacebookState(req, path.searchParams.get('state'));
  appendCookie(res, clearFacebookCookie('mms_facebook_state'));
  if (!stateValid) return redirect(res, '/login?facebook=invalid-state');
  if (path.searchParams.has('error')) return redirect(res, '/login?facebook=cancelled');
  const code = path.searchParams.get('code');
  if (!code || code.length > 2048) return redirect(res, '/login?facebook=error');
  limit(`facebook-callback:${clientIp(req)}`, 30, 15 * 60_000);
  let profile;
  try { profile = await fetchFacebookProfile(requiredFacebookConfig(), code); }
  catch (error) {
    if (error instanceof FacebookOAuthError) {
      console.warn('Facebook OAuth indisponible', { phase: error.phase, status: error.status || 'network-or-response' });
      return redirect(res, '/login?facebook=error');
    }
    throw error;
  }
  const identity = await pool.query(`SELECT u.id AS user_id,c.id AS customer_id FROM user_identities ui
    JOIN users u ON u.id=ui.user_id JOIN customers c ON c.user_id=u.id
    WHERE ui.provider='facebook' AND ui.provider_subject=$1 AND u.role='customer' AND u.status='active'`, [profile.id]);
  if (identity.rowCount) {
    await issueSession(identity.rows[0].user_id, identity.rows[0].customer_id, req, res);
    return redirect(res, '/login?facebook=success');
  }
  const names = splitFacebookName(profile.name);
  const rawToken = randomBytes(32).toString('base64url');
  await pool.query(`DELETE FROM external_auth_registrations WHERE expires_at<=now() OR consumed_at IS NOT NULL`);
  await pool.query(`INSERT INTO external_auth_registrations(id,provider,token_hash,provider_subject,first_name,last_name,email,expires_at)
    VALUES($1,'facebook',$2,$3,$4,$5,$6,now()+interval '10 minutes')`,
  [randomUUID(), facebookPendingHash(rawToken), profile.id, names.firstName, names.lastName, profile.email]);
  appendCookie(res, facebookCookie('mms_facebook_pending', rawToken, 600));
  return redirect(res, '/register?facebook=complete');
}
async function facebookPending(req: IncomingMessage) {
  const token = cookie(req, 'mms_facebook_pending');
  if (!token) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
  const found = await pool.query(`SELECT first_name AS "firstName",last_name AS "lastName",email
    FROM external_auth_registrations WHERE provider='facebook' AND token_hash=$1 AND consumed_at IS NULL AND expires_at>now()`, [facebookPendingHash(token)]);
  if (!found.rowCount) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
  return { ...found.rows[0], emailProvided: Boolean(found.rows[0].email) };
}
async function completeFacebook(req: IncomingMessage, res: ServerResponse, input: Record<string, unknown>) {
  limit(`facebook-complete:${clientIp(req)}`, 10, 60 * 60_000);
  const token = cookie(req, 'mms_facebook_pending');
  if (!token) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
  const phone = normalizePhone(input.phone);
  const client = await pool.connect();
  const userId = randomUUID(); const customerId = randomUUID();
  try {
    await client.query('BEGIN');
    const pending = await client.query(`SELECT * FROM external_auth_registrations WHERE provider='facebook' AND token_hash=$1
      AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, [facebookPendingHash(token)]);
    if (!pending.rowCount) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
    const row = pending.rows[0];
    const firstName = row.first_name ? textField(row.first_name, 'Prénom', 1, 80) : textField(input.firstName, 'Prénom', 1, 80);
    const lastName = row.last_name ? textField(row.last_name, 'Nom', 1, 80) : textField(input.lastName, 'Nom', 1, 80);
    const email = row.email ? customerEmail(row.email) : customerEmail(input.email);
    const linked = await client.query(`SELECT user_id FROM user_identities WHERE provider='facebook' AND provider_subject=$1 FOR UPDATE`, [row.provider_subject]);
    if (linked.rowCount) throw new HttpError(409, 'Ce compte Facebook est déjà associé à un autre espace MMS.', 'FACEBOOK_ALREADY_LINKED');
    const conflicts = await client.query(`SELECT u.id,u.phone_e164=$1 AS phone_match,lower(c.email)=lower($2) AS email_match
      FROM users u JOIN customers c ON c.user_id=u.id
      WHERE u.status='active' AND (u.phone_e164=$1 OR lower(c.email)=lower($2)) FOR UPDATE OF u`, [phone, email]);
    const phoneAccount = conflicts.rows.find(account => account.phone_match);
    const emailAccounts = conflicts.rows.filter(account => account.email_match);
    if (phoneAccount && emailAccounts.some(account => account.id !== phoneAccount.id)) {
      throw new HttpError(409, 'Ces informations sont déjà associées à des espaces MMS différents. Contactez l’atelier pour obtenir de l’aide.', 'FACEBOOK_IDENTITY_CONFLICT');
    }
    if (phoneAccount) {
      throw new HttpError(409, 'Ce numéro est déjà associé à un espace MMS.', 'FACEBOOK_EXISTING_ACCOUNT');
    }
    if (emailAccounts.length) {
      throw new HttpError(409, 'Cette adresse email est déjà associée à un espace MMS. Contactez l’atelier pour obtenir de l’aide.', 'FACEBOOK_DETAILS_ALREADY_USED');
    }
    await client.query(`INSERT INTO users(id,phone_e164,role,phone_verification_status) VALUES($1,$2,'customer','unverified')`, [userId, phone]);
    await client.query(`INSERT INTO customers(id,user_id,name,phone,email,first_name,last_name,terms_accepted_at,terms_version,privacy_accepted_at,privacy_version)
      VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,now(),$9)`, [customerId,userId,`${firstName} ${lastName}`,phone,email,firstName,lastName,termsVersion,privacyVersion]);
    await client.query(`INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES($1,$2,'facebook',$3)`, [randomUUID(),userId,row.provider_subject]);
    await client.query(`UPDATE external_auth_registrations SET consumed_at=now() WHERE id=$1`, [row.id]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((error as { code?: string }).code === '23505') throw new HttpError(409, 'Un espace MMS utilise déjà ces coordonnées. Connectez-vous avec votre méthode habituelle ou contactez l’atelier.');
    throw error;
  } finally { client.release(); }
  appendCookie(res, clearFacebookCookie('mms_facebook_pending'));
  return issueSession(userId, customerId, req, res);
}
async function linkFacebookToExisting(req: IncomingMessage, res: ServerResponse, input: Record<string, unknown>) {
  const token = cookie(req, 'mms_facebook_pending');
  if (!token) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
  const phone = normalizePhone(input.phone);
  const password = typeof input.password === 'string' ? input.password : '';
  const claimToken = typeof input.claimToken === 'string' ? input.claimToken : '';
  limit(`facebook-link-ip:${clientIp(req)}`, 20, 15 * 60_000);
  limit(`facebook-link-phone:${phone}`, 8, 15 * 60_000);
  const generic = new HttpError(401, 'Identifiant ou mot de passe incorrect.');
  const client = await pool.connect();
  let userId = ''; let customerId = ''; let passwordHash = '';
  try {
    await client.query('BEGIN');
    const pending = await client.query(`SELECT * FROM external_auth_registrations WHERE provider='facebook' AND token_hash=$1
      AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, [facebookPendingHash(token)]);
    if (!pending.rowCount) throw new HttpError(401, 'Cette connexion Facebook a expiré. Recommencez.');
    const row = pending.rows[0];
    const target = await client.query(`SELECT u.id AS user_id,c.id AS customer_id,cc.password_hash,cc.must_change_password,cc.temporary_password_expires_at
      FROM users u JOIN customers c ON c.user_id=u.id JOIN customer_credentials cc ON cc.user_id=u.id
      WHERE u.phone_e164=$1 AND u.role='customer' AND u.status='active' FOR UPDATE OF u,cc`, [phone]);
    if (!target.rowCount || !await verifyPassword(target.rows[0].password_hash, password)) throw generic;
    if (target.rows[0].must_change_password && (!target.rows[0].temporary_password_expires_at || new Date(target.rows[0].temporary_password_expires_at) <= new Date())) {
      throw new HttpError(401, "Ce mot de passe temporaire a expiré. Contactez l'atelier.");
    }
    userId = target.rows[0].user_id; customerId = target.rows[0].customer_id; passwordHash = target.rows[0].password_hash;
    const linkedIdentity = await client.query(`SELECT user_id FROM user_identities
      WHERE provider='facebook' AND provider_subject=$1 FOR UPDATE`, [row.provider_subject]);
    if (linkedIdentity.rowCount && linkedIdentity.rows[0].user_id !== userId) {
      throw new HttpError(409, 'Ce compte Facebook est déjà associé à un autre espace MMS.', 'FACEBOOK_ALREADY_LINKED');
    }
    const targetFacebook = await client.query(`SELECT provider_subject FROM user_identities
      WHERE provider='facebook' AND user_id=$1 FOR UPDATE`, [userId]);
    if (targetFacebook.rowCount && targetFacebook.rows[0].provider_subject !== row.provider_subject) {
      throw new HttpError(409, 'Ce compte Facebook est déjà associé à un autre espace MMS.', 'FACEBOOK_ALREADY_LINKED');
    }
    if (row.email) {
      const emailOwner = await client.query(`SELECT u.id FROM users u JOIN customers c ON c.user_id=u.id
        WHERE lower(c.email)=lower($1) AND u.status='active' FOR UPDATE OF u`, [customerEmail(row.email)]);
      if (emailOwner.rows.some(owner => owner.id !== userId)) {
        throw new HttpError(409, 'Ces informations sont déjà associées à des espaces MMS différents. Contactez l’atelier pour obtenir de l’aide.', 'FACEBOOK_IDENTITY_CONFLICT');
      }
    }
    if (claimToken) {
      const claimHash = createHmac('sha256', accessSecret).update(`booking:${claimToken}`).digest('hex');
      const claim = await client.query(`SELECT bc.id,bc.customer_id,bc.ticket_id,bc.expires_at,c.user_id
        FROM booking_claims bc JOIN customers c ON c.id=bc.customer_id JOIN tickets t ON t.id=bc.ticket_id
        WHERE bc.token_hash=$1 AND bc.consumed_at IS NULL FOR UPDATE`, [claimHash]);
      if (!claim.rowCount || new Date(claim.rows[0].expires_at) <= new Date()) {
        throw new HttpError(409, 'Cette demande ne peut plus être rattachée automatiquement à un compte. Contactez l’atelier si vous avez besoin d’aide.');
      }
      if (claim.rows[0].user_id && claim.rows[0].user_id !== userId) {
        throw new HttpError(409, 'Cette demande a déjà été associée à un espace MMS.');
      }
      if (!claim.rows[0].user_id) {
        await client.query('UPDATE vehicles SET customer_id=$2 WHERE customer_id=$1', [claim.rows[0].customer_id, customerId]);
        await client.query('UPDATE appointments SET customer_id=$2 WHERE customer_id=$1', [claim.rows[0].customer_id, customerId]);
        await client.query('UPDATE tickets SET customer_id=$2 WHERE id=$1', [claim.rows[0].ticket_id, customerId]);
      }
      await client.query('UPDATE booking_claims SET consumed_at=now() WHERE id=$1', [claim.rows[0].id]);
    }
    if (!linkedIdentity.rowCount) {
      await client.query(`INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES($1,$2,'facebook',$3)`, [randomUUID(), userId, row.provider_subject]);
    }
    await client.query(`UPDATE external_auth_registrations SET consumed_at=now() WHERE id=$1`, [row.id]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if ((error as { code?: string }).code === '23505') throw new HttpError(409, 'Ce compte Facebook est déjà associé à un autre espace MMS.', 'FACEBOOK_ALREADY_LINKED');
    throw error;
  } finally { client.release(); }
  appendCookie(res, clearFacebookCookie('mms_facebook_pending'));
  return issueSession(userId, customerId, req, res, 'customer', passwordHash);
}
async function changeCustomerPassword(req: IncomingMessage, res: ServerResponse, input: Record<string, unknown>) {
  const auth = await identity(req, ['customer'], true);
  if (!auth.mustChangePassword) throw new HttpError(409, 'Aucun changement de mot de passe temporaire requis.');
  const nextPassword = customerPassword(input.newPassword);
  const digest = await hashPassword(nextPassword);
  const sessionId = randomUUID();
  const refresh = randomBytes(32).toString('base64url');
  const refreshHash = createHmac('sha256', accessSecret).update(refresh).digest('hex');
  const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
  const agent = String(req.headers['user-agent'] || '').slice(0, 300);
  const label = /android/i.test(agent) ? 'Navigateur Android' : /iphone|ipad/i.test(agent) ? 'Navigateur iOS' : 'Navigateur web';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const credential = await client.query(`SELECT cc.password_hash,cc.must_change_password FROM users u
      JOIN customer_credentials cc ON cc.user_id=u.id WHERE u.id=$1 AND u.role='customer' AND u.status='active' FOR UPDATE OF u,cc`, [auth.userId]);
    if (!credential.rowCount || !credential.rows[0].must_change_password) throw new HttpError(409, 'Le changement de mot de passe n’est plus requis.');
    const currentSession = await client.query(`SELECT id FROM user_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, [auth.sessionId, auth.userId]);
    if (!currentSession.rowCount) throw new HttpError(401, 'Session expirée.');
    if (await verifyPassword(credential.rows[0].password_hash, nextPassword)) throw new HttpError(400, 'Choisissez un mot de passe différent du mot de passe temporaire.');
    await client.query(`UPDATE customer_credentials SET password_hash=$2,must_change_password=false,
      temporary_password_expires_at=NULL,password_changed_at=now(),updated_at=now() WHERE user_id=$1`, [auth.userId, digest]);
    // Self-service changes use password_changed_at; admin_audit_events remains staff-action-only.
    await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [auth.userId]);
    await client.query(`INSERT INTO user_sessions(id,user_id,refresh_token_hash,user_agent,device_label,expires_at)
      VALUES($1,$2,$3,$4,$5,$6)`, [sessionId, auth.userId, refreshHash, agent, label, expires]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
  res.setHeader('Set-Cookie', refreshCookie(refresh, expires));
  return { accessToken: accessToken({ userId: auth.userId, customerId: auth.customerId, sessionId, role: 'customer' }),
    user: await customerData(auth.customerId), mustChangePassword: false };
}
async function createRecoveryRequest(req: IncomingMessage, input: Record<string, unknown>) {
  const identifier = textField(input.identifier, 'Identifiant', 3, 254); let normalized: string; let type: 'email'|'phone';
  if (identifier.includes('@')) { normalized = customerEmail(identifier); type = 'email'; } else { normalized = normalizePhone(identifier); type = 'phone'; }
  try { limit(`recovery-ip:${clientIp(req)}`,5,60*60_000); limit(`recovery-identifier:${normalized}`,3,24*60*60_000); }
  catch (error) { if (error instanceof HttpError && error.status === 429) throw new HttpError(429, 'Trop de demandes ont été effectuées. Réessayez plus tard.'); throw error; }
  const found = await pool.query(`SELECT u.id AS user_id,c.id AS customer_id FROM users u JOIN customers c ON c.user_id=u.id WHERE u.status='active' AND (${type === 'email' ? 'lower(c.email)=lower($1)' : 'u.phone_e164=$1'}) LIMIT 1`, [normalized]);
  await pool.query(`INSERT INTO customer_access_requests(id,user_id,customer_id,identifier_type,identifier_normalized,type,status,identifier_masked) VALUES($1,$2,$3,$4,$5,'password_reset','pending',$6) ON CONFLICT DO NOTHING`, [randomUUID(),found.rows[0]?.user_id||null,found.rows[0]?.customer_id||null,type,normalized,maskIdentifier(normalized,type)]);
  return { message: 'Votre demande a bien été prise en compte. Si un espace MMS correspond à ces informations, notre équipe pourra vous contacter.' };
}
function maskIdentifier(value: string, type: string) { return type === 'email' ? `${value.slice(0,2)}***@${value.split('@')[1]}` : `0${value.slice(4,6)} ** *** **`; }

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
  if (method === 'GET' && parts[2] === 'access-requests' && parts.length === 3) {
    await requireRole(req, ['workshop_manager','admin']);
    const rows = await pool.query(`SELECT r.id,r.user_id AS "userId",r.status,r.created_at AS "createdAt",CASE WHEN r.identifier_type='email' THEN r.identifier_masked ELSE NULL END AS "emailMasked",CASE WHEN r.identifier_type='phone' THEN r.identifier_masked ELSE NULL END AS "phoneMasked",CASE WHEN c.id IS NULL THEN NULL ELSE COALESCE(NULLIF(concat_ws(' ',c.first_name,c.last_name),''),c.name) END AS customer FROM customer_access_requests r LEFT JOIN customers c ON c.id=r.customer_id WHERE r.status='pending' AND r.type='password_reset' ORDER BY r.created_at DESC`);
    return send(res,200,rows.rows);
  }
  const auth = await requireRole(req, allStaffRoles, ['me','change-password','logout-all'].includes(parts[2]));
  if (method === 'POST' && parts[2] === 'customers' && parts[3] && parts[4] === 'reset-password' && parts.length === 5) {
    if (!['workshop_manager','admin'].includes(auth.role)) throw new HttpError(403, 'Accès refusé.');
    const targetId = uuid(parts[3]);
    const input = await body(req);
    const requestId = input.requestId == null ? null : uuid(typeof input.requestId === 'string' ? input.requestId : undefined);
    limit(`customer-reset:${auth.userId}`, 20, 60 * 60_000);
    const temporary = temporaryPassword();
    const digest = await hashPassword(temporary);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const target = await client.query(`SELECT u.id FROM users u JOIN customers c ON c.user_id=u.id WHERE u.id=$1 AND u.role='customer' FOR UPDATE OF u`, [targetId]);
      if (!target.rowCount) throw new HttpError(404, 'Compte client introuvable.');
      if (requestId) {
        const request = await client.query(`SELECT id FROM customer_access_requests WHERE id=$1 AND user_id=$2 AND status='pending' AND type='password_reset' FOR UPDATE`, [requestId, targetId]);
        if (!request.rowCount) throw new HttpError(409, "Cette demande d'accès ne correspond pas au compte client ou n'est plus en attente.");
      }
      await client.query(`INSERT INTO customer_credentials(user_id,password_hash,must_change_password,temporary_password_expires_at,password_changed_at)
        VALUES($1,$2,true,now()+interval '24 hours',NULL)
        ON CONFLICT (user_id) DO UPDATE SET password_hash=excluded.password_hash,must_change_password=true,
          temporary_password_expires_at=excluded.temporary_password_expires_at,password_changed_at=NULL,updated_at=now()`, [targetId, digest]);
      await client.query('UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [targetId]);
      if (requestId) await client.query(`UPDATE customer_access_requests SET status='resolved',resolved_at=now(),resolved_by_user_id=$2 WHERE id=$1`, [requestId, auth.userId]);
      await client.query(`INSERT INTO admin_audit_events(actor_user_id,target_user_id,action,request_id) VALUES($1,$2,'customer_password_reset',$3)`, [auth.userId, targetId, requestId]);
      // A disabled account stays disabled; resetting credentials never changes users.status.
      await client.query('COMMIT');
      return send(res, 200, { temporaryPassword: temporary });
    } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  }
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
  if (parts[2] === 'schedule') {
    if (!['workshop_manager','admin'].includes(auth.role)) throw new HttpError(403, 'Accès réservé au responsable atelier ou à l’administrateur.');
    if (method === 'GET' && parts.length === 3) {
      const [rules, exceptions, blocks] = await Promise.all([
        pool.query(`SELECT weekday,opens_at::text AS "opensAt",closes_at::text AS "closesAt",is_open AS "isOpen" FROM workshop_schedule_rules ORDER BY weekday`),
        pool.query(`SELECT to_char(day,'YYYY-MM-DD') AS day,opens_at::text AS "opensAt",closes_at::text AS "closesAt",is_open AS "isOpen",reason FROM workshop_schedule_exceptions ORDER BY day`),
        pool.query(`SELECT id,to_char(slot_date,'YYYY-MM-DD') AS date,to_char(slot_time,'HH24:MI') AS time,reason FROM blocked_slots ORDER BY slot_date,slot_time`),
      ]); return send(res, 200, { timezone: 'Indian/Antananarivo', rules: rules.rows, exceptions: exceptions.rows, blockedSlots: blocks.rows });
    }
    if (method === 'PUT' && parts[3] === 'rules' && parts.length === 4) {
      const input = await body(req); if (!Array.isArray(input.rules) || input.rules.length !== 7) throw new HttpError(400, 'Les sept jours doivent être renseignés.');
      const client = await pool.connect(); try { await client.query('BEGIN');
        for (const raw of input.rules as Record<string,unknown>[]) { const weekday = integerField(raw.weekday,'Jour',0,6); const open = raw.isOpen === true; const opens = open ? textField(raw.opensAt,'Ouverture',5,5) : null; const closes = open ? textField(raw.closesAt,'Fermeture',5,5) : null; if (open && (!/^\d\d:\d\d$/.test(opens!) || !/^\d\d:\d\d$/.test(closes!) || opens! >= closes!)) throw new HttpError(400,'Horaires invalides.'); await client.query(`INSERT INTO workshop_schedule_rules(weekday,opens_at,closes_at,is_open,updated_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(weekday) DO UPDATE SET opens_at=excluded.opens_at,closes_at=excluded.closes_at,is_open=excluded.is_open,updated_at=now()`,[weekday,opens,closes,open]); }
        await client.query('COMMIT'); return send(res,200,{ok:true});
      } catch(error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
    }
    if (method === 'POST' && parts[3] === 'exceptions' && parts.length === 4) {
      const input = await body(req); const day=textField(input.day,'Date',10,10); if(!datePattern.test(day)) throw new HttpError(400,'Date invalide.'); const open=input.isOpen===true; const opens=open?textField(input.opensAt,'Ouverture',5,5):null; const closes=open?textField(input.closesAt,'Fermeture',5,5):null; if(open && (!/^\d\d:\d\d$/.test(opens!) || !/^\d\d:\d\d$/.test(closes!) || opens!>=closes!)) throw new HttpError(400,'Horaires invalides.'); await pool.query(`INSERT INTO workshop_schedule_exceptions(day,opens_at,closes_at,is_open,reason,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(day) DO UPDATE SET opens_at=excluded.opens_at,closes_at=excluded.closes_at,is_open=excluded.is_open,reason=excluded.reason,created_by_user_id=excluded.created_by_user_id`,[day,opens,closes,open,textField(input.reason??'','Motif',0,300),auth.userId]); return send(res,201,{ok:true});
    }
    if (method === 'POST' && parts[3] === 'blocks' && parts.length === 4) { const input=await body(req); const day=textField(input.date,'Date',10,10), time=textField(input.time,'Créneau',5,5); if(!datePattern.test(day)||!/^\d\d:\d\d$/.test(time)) throw new HttpError(400,'Créneau invalide.'); await pool.query(`INSERT INTO blocked_slots(id,slot_date,slot_time,reason,created_by_user_id) VALUES($1,$2,$3,$4,$5)`,[randomUUID(),day,time,textField(input.reason??'','Motif',0,300),auth.userId]); return send(res,201,{ok:true}); }
    if (method === 'DELETE' && parts[3] === 'blocks' && parts[4] && parts.length === 5) { await pool.query('DELETE FROM blocked_slots WHERE id=$1',[uuid(parts[4])]); return send(res,200,{ok:true}); }
    throw new HttpError(404,'Route introuvable.');
  }
  if (method === 'POST' && parts[2] === 'customers' && parts[3] && parts[4] === 'verify-phone' && parts.length === 5) {
    const customerId = uuid(parts[3]);
    if (auth.role === 'mechanic') {
      const assigned = await pool.query(`SELECT 1 FROM tickets WHERE customer_id=$1 AND assigned_mechanic_user_id=$2 AND status NOT IN ('completed','cancelled')`, [customerId,auth.userId]);
      if (!assigned.rowCount) throw new HttpError(403,'Ce client ne vous est pas attribué.');
    } else if (!['workshop_manager','admin'].includes(auth.role)) throw new HttpError(403,'Accès refusé.');
    const updated = await pool.query(`UPDATE users u SET phone_verified_at=COALESCE(phone_verified_at,now()),phone_verification_status='verified_manual',phone_verified_method='manual',phone_verified_by_user_id=$2,updated_at=now() FROM customers c WHERE c.id=$1 AND c.user_id=u.id RETURNING u.id`,[customerId,auth.userId]);
    if (!updated.rowCount) throw new HttpError(404,'Client introuvable.');
    await pool.query(`INSERT INTO customer_verification_events(customer_id,actor_user_id,action) VALUES($1,$2,'phone_verified_manual')`,[customerId,auth.userId]);
    return send(res,200,{ok:true});
  }
  if (method === 'POST' && parts[2] === 'customers' && parts[3] && parts[4] === 'reset-pin' && parts.length === 5) {
    if (!['workshop_manager','admin'].includes(auth.role)) throw new HttpError(403,'Accès réservé au responsable atelier ou à l’administrateur.');
    const customerId=uuid(parts[3]); const target=await pool.query('SELECT u.id FROM users u JOIN customers c ON c.user_id=u.id WHERE c.id=$1',[customerId]); if(!target.rowCount) throw new HttpError(404,'Client introuvable.');
    await pool.query('DELETE FROM customer_pin_credentials WHERE user_id=$1',[target.rows[0].id]); await pool.query(`INSERT INTO customer_verification_events(customer_id,actor_user_id,action) VALUES($1,$2,'pin_reset')`,[customerId,auth.userId]);
    return send(res,200,{ok:true});
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
      if (!['customer','mechanic','workshop_manager','admin','commercial'].includes(role)) throw new HttpError(400, 'Rôle invalide.');
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
    if (!['customer','mechanic','workshop_manager','admin','commercial'].includes(String(role))) throw new HttpError(400, 'Rôle invalide.');
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

const shopDeps: ShopDeps = {
  pool, send, body, limit, clientIp, photoBody, normalizePhone, customerEmail,
  requireRole: (req, roles) => requireRole(req, roles),
  // A shop order may be placed as a guest; a valid customer session only links it to the account.
  optionalCustomerId: async req => {
    if (!req.headers.authorization) return null;
    try { return (await identity(req, ['customer'])).customerId || null; } catch { return null; }
  },
};

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
  if (parts[1] === 'shop') return shopRoute(shopDeps, req, res, parts, method, path);
  if (parts[1] === 'commerce') return commerceRoute(shopDeps, req, res, parts, method, path);
  if (parts[1] === 'auth') {
    if (method === 'GET' && parts[2] === 'facebook' && parts.length === 3) return beginFacebook(req, res);
    if (method === 'GET' && parts[2] === 'facebook' && parts[3] === 'callback' && parts.length === 4) return facebookCallback(req, res, path);
    if (method === 'GET' && parts[2] === 'facebook' && parts[3] === 'pending' && parts.length === 4) return send(res, 200, await facebookPending(req));
    if (method === 'POST' && parts[2] === 'facebook' && parts[3] === 'complete' && parts.length === 4) return send(res, 201, await completeFacebook(req, res, await body(req)));
    if (method === 'POST' && parts[2] === 'facebook' && parts[3] === 'link-existing' && parts.length === 4) return send(res, 200, await linkFacebookToExisting(req, res, await body(req)));
    if (method === 'POST' && parts[2] === 'recovery-request' && parts.length === 3) return send(res, 200, await createRecoveryRequest(req, await body(req)));
    if (method === 'POST' && parts[2] === 'customer-register' && parts.length === 3) return send(res, 201, await registerCustomerPassword(req, await body(req), res));
    if (method === 'POST' && parts[2] === 'customer-login' && parts.length === 3) return send(res, 200, await customerPasswordLogin(req, await body(req), res));
    if (method === 'POST' && parts[2] === 'pin-login' && parts.length === 3) return send(res, 200, await customerPinLogin(req, await body(req), res));
    if (method === 'POST' && parts[2] === 'yas-register' && parts.length === 3) return send(res, 201, await createYasCustomer(req, await body(req), res));
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
        LEFT JOIN customers c ON c.user_id=u.id LEFT JOIN local_credentials lc ON lc.user_id=u.id
        LEFT JOIN customer_credentials cc ON cc.user_id=u.id WHERE s.user_id=u.id AND s.refresh_token_hash=$1
        AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'
        RETURNING s.user_id,u.role,COALESCE(lc.must_change_password,false) AS must_change_password,c.id AS customer_id,cc.password_hash AS customer_password_hash`, [hash]);
      if (!found.rowCount) throw new HttpError(401, 'Session expirée.');
      return send(res, 200, await issueSession(found.rows[0].user_id, found.rows[0].customer_id || '', req, res, found.rows[0].role,
        found.rows[0].role === 'customer' ? found.rows[0].customer_password_hash : undefined));
    }
    if (method === 'POST' && parts[2] === 'logout') { const token = cookie(req, 'mms_refresh'); if (token) await pool.query('UPDATE user_sessions SET revoked_at=now() WHERE refresh_token_hash=$1', [createHmac('sha256', accessSecret).update(token).digest('hex')]); res.setHeader('Set-Cookie', clearRefreshCookie()); return send(res, 200, { ok: true }); }
    if (method === 'POST' && parts[2] === 'change-password' && parts.length === 3) return send(res, 200, await changeCustomerPassword(req, res, await body(req)));
    if (method === 'GET' && parts[2] === 'me' && parts.length === 3) {
      const auth = await identity(req, ['customer'], true);
      return send(res, 200, auth.mustChangePassword ? { user: { id: auth.customerId }, mustChangePassword: true } : await customerData(auth.customerId));
    }
    const auth = await identity(req);
    if (method === 'POST' && parts[2] === 'pin' && parts.length === 3) return setCustomerPin(req, await body(req), res);
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
    return send(res, 200, await availabilityFor(date));
  }
  if (method === 'POST' && parts[1] === 'bookings' && parts[2] === 'complete' && parts.length === 3) {
    let auth: Identity | null = null; try { auth = await identity(req); } catch (error) { if (!(error instanceof HttpError) || error.status !== 401) throw error; }
    const input = await body(req);
    const kind = input.kind === 'Urgence' ? 'Urgence' : scheduledKind(input.kind);
    const problem = textField(input.problem, 'Description du problème', 10, 2000);
    const vehicle = vehicleInput((input.vehicle && typeof input.vehicle === 'object' ? input.vehicle : {}) as Record<string, unknown>);
    const address = textField(input.address ?? '', 'Localisation', kind === 'En atelier' ? 0 : 5, 500);
    const date = kind === 'Urgence' ? null : textField(input.date, 'Date', 10, 10);
    const time = kind === 'Urgence' ? null : textField(input.time, 'Créneau', 5, 5);
    if (date && (!datePattern.test(date) || Number.isNaN(Date.parse(`${date}T12:00:00`)))) throw new HttpError(400, 'Date invalide.');
    if (time && !/^\d{2}:\d{2}$/.test(time)) throw new HttpError(400, 'Créneau invalide.');
    const contactPhone = input.contactPhone ? normalizePhone(input.contactPhone) : null;
    const firstName = auth ? '' : textField(input.firstName, 'Prénom', 1, 80); const lastName = auth ? '' : textField(input.lastName, 'Nom', 1, 80); const email = auth ? null : customerEmail(input.email);
    if (!auth && !contactPhone) throw new HttpError(400, 'Téléphone requis.');
    limit(`anonymous-booking-ip:${clientIp(req)}`, 5, 60 * 60_000); if (!auth) { limit(`anonymous-booking-phone:${contactPhone}`, 3, 24 * 60 * 60_000); limit(`anonymous-booking-email:${email}`, 3, 24 * 60 * 60_000); }
    const immobilized = typeof input.immobilized === 'boolean' ? input.immobilized : null;
    if (kind === 'Urgence' && (contactPhone === null || immobilized === null)) throw new HttpError(400, 'Complétez les informations de dépannage.');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const customerId = auth?.customerId || randomUUID();
      if (!auth) await client.query(`INSERT INTO customers(id,name,phone,email,first_name,last_name) VALUES($1,$2,$3,$4,$5,$6)`, [customerId,`${firstName} ${lastName}`,contactPhone,email,firstName,lastName]);
      const vehicleId = randomUUID();
      await client.query(`INSERT INTO vehicles(id,customer_id,name,model,plate,color,displacement_cc,production_year) VALUES($1,$2,$3,$4,$5,'#dce8ef',$6,$7)`, [vehicleId,customerId,vehicle.name,vehicle.model,vehicle.plate,vehicle.displacementCc,vehicle.year]);
      let appointmentId: string | null = null;
      if (kind !== 'Urgence') {
        const available = await availabilityFor(date!, client);
        if (!available.slots.includes(time!) || available.occupied.includes(time!)) throw new HttpError(409, 'Ce créneau vient d’être réservé. Choisissez-en un autre.');
        appointmentId = randomUUID();
        await client.query(`INSERT INTO appointments(id,customer_id,vehicle_id,problem,kind,address,appointment_date,appointment_time,status,contact_phone,immobilized)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,'Confirmé',$9,$10)`, [appointmentId,customerId,vehicleId,problem,kind,address,date,time,contactPhone,immobilized]);
      }
      const ticketId = randomUUID(); const sequence = await client.query(`SELECT nextval('ticket_reference_seq') AS value`);
      const reference = ticketReference(String(sequence.rows[0].value));
      await client.query(`INSERT INTO tickets(id,reference,customer_id,vehicle_id,appointment_id,intervention_type,description,status,created_by_user_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,'new',$8)`, [ticketId,reference,customerId,vehicleId,appointmentId,kind,problem,auth?.userId || null]);
      await client.query(`INSERT INTO ticket_events(ticket_id,actor_user_id,event_type,new_value) VALUES($1,$2,'ticket_created','new')`, [ticketId,auth?.userId || null]);
      const claim = randomBytes(32).toString('base64url'); const claimHash = createHmac('sha256', accessSecret).update(`booking:${claim}`).digest('hex');
      await client.query(`INSERT INTO booking_claims(id,customer_id,ticket_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '24 hours')`,[randomUUID(),customerId,ticketId,claimHash]);
      await client.query('COMMIT');
      const result = await pool.query(`SELECT t.id,t.reference,t.appointment_id AS "appointmentId",t.vehicle_id AS "vehicleId",t.intervention_type AS "interventionType",t.description,t.status,t.created_at AS "createdAt",a.appointment_date AS "appointmentDate",a.appointment_time AS "appointmentTime" FROM tickets t LEFT JOIN appointments a ON a.id=t.appointment_id WHERE t.id=$1`, [ticketId]);
      return send(res, 201, { ticket: result.rows[0], appointmentId, bookingClaim: claim });
    } catch (error) { await client.query('ROLLBACK').catch(() => undefined); if ((error as {code?: string}).code === '23505') throw new HttpError(409, 'Ce créneau vient d’être réservé. Choisissez-en un autre.'); throw error; } finally { client.release(); }
  }
  if (method === 'POST' && parts[1] === 'bookings' && parts[2] === 'claim' && parts.length === 3) {
    const auth = await identity(req); return send(res, 200, await claimBooking(auth, await body(req)));
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
        const available = await availabilityFor(date);
        if (!available.slots.includes(time) || available.occupied.includes(time)) throw new HttpError(400, 'Créneau invalide ou indisponible.');
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
      if (error instanceof HttpError) return send(res, error.status, error.code ? { error: error.message, code: error.code } : { error: error.message });
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
