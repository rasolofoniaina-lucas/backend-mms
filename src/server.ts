import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { Pool } from 'pg';

if (process.env.MMS_TEST_MODE !== '1') {
  throw new Error('Ce backend sans authentification ne peut démarrer que si MMS_TEST_MODE=1.');
}
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');

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

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

function send(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function textField(value: unknown, label: string, min = 0, max = 255): string {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) throw new HttpError(400, `${label} invalide.`);
  return value.trim();
}
function uuid(value: string | undefined): string {
  if (!value || !uuidPattern.test(value)) throw new HttpError(400, 'Identifiant invalide.');
  return value;
}
function codeHash(challengeId: string, code: string) {
  return createHash('sha256').update(`${challengeId}:${code}`).digest('hex');
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
async function customerData(id: string) {
  const customer = await pool.query('SELECT name, phone FROM customers WHERE id = $1', [id]);
  if (!customer.rowCount) throw new HttpError(404, 'Client introuvable.');
  const [vehicles, appointments, maintenance, messages] = await Promise.all([
    pool.query('SELECT id, name, model, plate, color FROM vehicles WHERE customer_id = $1 ORDER BY created_at', [id]),
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
  if (method === 'GET' && parts[1] === 'availability' && parts.length === 2) {
    const kind = path.searchParams.get('kind');
    const date = path.searchParams.get('date');
    if (kind !== 'À domicile' && kind !== 'En atelier') throw new HttpError(400, 'Type d’intervention invalide.');
    if (!date || !datePattern.test(date) || Number.isNaN(Date.parse(`${date}T12:00:00`))) throw new HttpError(400, 'Date invalide.');
    const occupied = await pool.query(`SELECT to_char(appointment_time, 'HH24:MI') AS time FROM appointments
      WHERE kind = $1 AND appointment_date = $2 AND status IN ('Confirmé', 'Pris en charge', 'En cours')`, [kind, date]);
    return send(res, 200, { slots: slots[kind], occupied: occupied.rows.map(row => row.time) });
  }
  if (method === 'POST' && parts[1] === 'customers' && parts.length === 2) {
    const input = await body(req);
    const hasProfile = input.name !== undefined || input.phone !== undefined;
    const name = hasProfile ? textField(input.name, 'Prénom', 1, 80) : 'Motard';
    const phone = hasProfile ? textField(input.phone, 'Téléphone', 6, 40) : '';
    const id = randomUUID();
    await pool.query('INSERT INTO customers (id, name, phone) VALUES ($1, $2, $3)', [id, name, phone]);
    return send(res, 201, { id, data: await customerData(id) });
  }
  if (parts[1] === 'customers' && parts[2]) {
    const customerId = uuid(parts[2]);
    if (method === 'GET' && parts.length === 3) return send(res, 200, await customerData(customerId));
    if (method === 'PATCH' && parts.length === 3) {
      const input = await body(req);
      const name = textField(input.name, 'Prénom', 1, 80);
      if (input.phone !== undefined) throw new HttpError(400, 'Le changement de numéro requiert une confirmation OTP.');
      const result = await pool.query('UPDATE customers SET name = $2 WHERE id = $1 RETURNING name, phone', [customerId, name]);
      if (!result.rowCount) throw new HttpError(404, 'Client introuvable.');
      return send(res, 200, result.rows[0]);
    }
    if (method === 'POST' && parts[3] === 'phone-change' && parts.length === 4) {
      const input = await body(req);
      const phone = textField(input.phone, 'Nouveau numéro', 6, 40);
      const customer = await pool.query('SELECT phone FROM customers WHERE id = $1', [customerId]);
      if (!customer.rowCount) throw new HttpError(404, 'Client introuvable.');
      if (customer.rows[0].phone === phone) throw new HttpError(400, 'Le nouveau numéro doit être différent de l’actuel.');
      const challengeId = randomUUID();
      const testCode = '000000';
      await pool.query(`INSERT INTO phone_change_challenges (customer_id, challenge_id, new_phone, code_hash, expires_at, attempts)
        VALUES ($1, $2, $3, $4, now() + interval '10 minutes', 0)
        ON CONFLICT (customer_id) DO UPDATE SET challenge_id = EXCLUDED.challenge_id, new_phone = EXCLUDED.new_phone,
          code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = 0`,
      [customerId, challengeId, phone, codeHash(challengeId, testCode)]);
      return send(res, 200, { challengeId, testCode, expiresInSeconds: 600 });
    }
    if (method === 'POST' && parts[3] === 'phone-change' && parts[4] === 'confirm' && parts.length === 5) {
      const input = await body(req);
      const challengeId = uuid(typeof input.challengeId === 'string' ? input.challengeId : undefined);
      const code = textField(input.code, 'Code OTP', 6, 6);
      if (!/^\d{6}$/.test(code)) throw new HttpError(400, 'Le code OTP doit contenir six chiffres.');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const challenge = await client.query(`SELECT challenge_id, new_phone, code_hash, expires_at, attempts
          FROM phone_change_challenges WHERE customer_id = $1 FOR UPDATE`, [customerId]);
        if (!challenge.rowCount || challenge.rows[0].challenge_id !== challengeId) throw new HttpError(400, 'Demande OTP introuvable. Recommencez.');
        const pending = challenge.rows[0];
        if (new Date(pending.expires_at) < new Date()) throw new HttpError(410, 'Code OTP expiré. Recommencez.');
        if (pending.attempts >= 5) throw new HttpError(429, 'Trop de tentatives. Demandez un nouveau code.');
        const expected = Buffer.from(pending.code_hash, 'hex');
        const received = Buffer.from(codeHash(challengeId, code), 'hex');
        if (!timingSafeEqual(expected, received)) {
          await client.query('UPDATE phone_change_challenges SET attempts = attempts + 1 WHERE customer_id = $1', [customerId]);
          await client.query('COMMIT');
          return send(res, 400, { error: 'Code OTP incorrect.' });
        }
        const updated = await client.query('UPDATE customers SET phone = $2 WHERE id = $1 RETURNING name, phone', [customerId, pending.new_phone]);
        await client.query('DELETE FROM phone_change_challenges WHERE customer_id = $1', [customerId]);
        await client.query('COMMIT');
        return send(res, 200, updated.rows[0]);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally { client.release(); }
    }
    if (method === 'POST' && parts[3] === 'vehicles' && parts.length === 4) {
      const input = await body(req);
      const name = textField(input.name, 'Marque et modèle', 2, 100);
      const model = textField(input.model, 'Version ou année', 1, 100);
      const plate = textField(input.plate, 'Immatriculation', 2, 32).toUpperCase();
      await customerExists(customerId);
      const id = randomUUID();
      const result = await pool.query(`INSERT INTO vehicles (id, customer_id, name, model, plate, color)
        VALUES ($1, $2, $3, $4, $5, '#dce8ef') RETURNING id, name, model, plate, color`, [id, customerId, name, model, plate]);
      return send(res, 201, result.rows[0]);
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
    if (method === 'GET' && parts.length === 3) {
      const result = await pool.query(`SELECT a.id, a.customer_id AS "customerId", c.name AS "customerName",
        c.phone AS "customerPhone", v.name AS "vehicleName", v.model AS "vehicleModel", v.plate,
        a.problem, a.diagnosis, a.kind, a.address,
        to_char(a.appointment_date, 'YYYY-MM-DD') AS date,
        to_char(a.appointment_time, 'HH24:MI') AS time,
        a.status, a.contact_phone AS "contactPhone", a.immobilized, a.mechanic_note AS "mechanicNote"
        FROM appointments a JOIN customers c ON c.id = a.customer_id
        JOIN vehicles v ON v.id = a.vehicle_id ORDER BY
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
      console.error('Erreur API MMS', error);
      send(res, 500, { error: 'Erreur interne du serveur.' });
    });
  });
  server.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('API MMS prête (mode test, sans authentification).'));
  process.on('SIGTERM', () => { server.close(); void pool.end(); });
}
start().catch(error => { console.error('Démarrage API impossible', error); process.exit(1); });
