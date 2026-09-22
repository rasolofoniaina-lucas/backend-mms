CREATE TABLE IF NOT EXISTS customers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  phone text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Identity is deliberately separate from the customer business profile so that
-- mechanic and administrator identities can be added without changing data.
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  phone_e164 text NOT NULL,
  role text NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'mechanic', 'admin')),
  phone_verified_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_active_phone_unique ON users(phone_e164) WHERE status = 'active';

-- Phase A: staff identities share the existing users/session infrastructure.
ALTER TABLE users ALTER COLUMN phone_e164 DROP NOT NULL;
ALTER TABLE users ALTER COLUMN phone_verified_at DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('customer', 'mechanic', 'workshop_manager', 'admin'));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email)) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_role_status_idx ON users(role, status);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_identity_shape_check;
ALTER TABLE users ADD CONSTRAINT users_identity_shape_check CHECK (
  (role='customer' AND phone_e164 IS NOT NULL AND email IS NULL AND password_hash IS NULL)
  OR (role IN ('mechanic','workshop_manager','admin') AND phone_e164 IS NULL AND email IS NOT NULL AND password_hash IS NOT NULL)
);

ALTER TABLE customers ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS first_name text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS last_name text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS terms_version text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS privacy_accepted_at timestamptz;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS privacy_version text;
CREATE UNIQUE INDEX IF NOT EXISTS customers_user_unique ON customers(user_id) WHERE user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS otp_challenges (
  id uuid PRIMARY KEY,
  phone_e164 text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('register', 'login', 'phone_change')),
  otp_digest text NOT NULL,
  registration_first_name text,
  registration_last_name text,
  terms_accepted boolean,
  privacy_accepted boolean,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  attempts_remaining integer NOT NULL DEFAULT 5 CHECK (attempts_remaining >= 0),
  resend_available_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS otp_challenges_phone_created_idx ON otp_challenges(phone_e164, created_at DESC);

CREATE TABLE IF NOT EXISTS user_sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash text NOT NULL UNIQUE,
  user_agent text NOT NULL DEFAULT '',
  device_label text NOT NULL DEFAULT 'Navigateur web',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS phone_change_challenges (
  customer_id uuid PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
  challenge_id uuid NOT NULL,
  new_phone text NOT NULL,
  code_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vehicles (
  id uuid PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  name text NOT NULL,
  model text NOT NULL,
  plate text NOT NULL,
  color text NOT NULL DEFAULT '#dce8ef',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Existing motorcycles remain readable; these required fields are enforced for new/edited rows by the API.
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS displacement_cc integer;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS production_year integer;

CREATE TABLE IF NOT EXISTS vehicle_photos (
  vehicle_id uuid PRIMARY KEY REFERENCES vehicles(id) ON DELETE CASCADE,
  mime_type text NOT NULL,
  image_data bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS appointments (
  id uuid PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  vehicle_id uuid NOT NULL REFERENCES vehicles(id),
  problem text NOT NULL,
  diagnosis text NOT NULL DEFAULT '',
  kind text NOT NULL CHECK (kind IN ('Urgence', 'À domicile', 'En atelier')),
  address text NOT NULL DEFAULT '',
  appointment_date date NOT NULL,
  appointment_time time NOT NULL,
  status text NOT NULL CHECK (status IN ('Confirmé', 'Dépannage demandé', 'Pris en charge', 'En cours', 'Terminé', 'Annulé')),
  contact_phone text,
  immobilized boolean,
  mechanic_note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS unique_active_slot ON appointments(kind, appointment_date, appointment_time)
  WHERE kind <> 'Urgence' AND status IN ('Confirmé', 'Pris en charge', 'En cours');

CREATE INDEX IF NOT EXISTS appointments_customer_idx ON appointments(customer_id, appointment_date DESC);
CREATE INDEX IF NOT EXISTS appointments_date_idx ON appointments(appointment_date, appointment_time);

CREATE TABLE IF NOT EXISTS maintenance (
  id uuid PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  vehicle_id uuid NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
  title text NOT NULL,
  maintenance_date date NOT NULL,
  note text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS messages (
  id bigserial PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- The sequence is global and transactional inserts use nextval(), never COUNT()+1.
CREATE SEQUENCE IF NOT EXISTS ticket_reference_seq;
CREATE TABLE IF NOT EXISTS tickets (
  id uuid PRIMARY KEY,
  reference text NOT NULL UNIQUE,
  customer_id uuid NOT NULL REFERENCES customers(id),
  vehicle_id uuid NOT NULL REFERENCES vehicles(id),
  appointment_id uuid UNIQUE REFERENCES appointments(id),
  intervention_type text NOT NULL CHECK (intervention_type IN ('Urgence', 'À domicile', 'En atelier')),
  description text NOT NULL,
  status text NOT NULL CHECK (status IN ('new','triage','assigned','in_progress','waiting_customer','completed','cancelled')),
  assigned_mechanic_user_id uuid REFERENCES users(id),
  created_by_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  cancelled_at timestamptz
);
CREATE INDEX IF NOT EXISTS tickets_customer_idx ON tickets(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_status_idx ON tickets(status, created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_mechanic_idx ON tickets(assigned_mechanic_user_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS ticket_events (
  id bigserial PRIMARY KEY,
  ticket_id uuid NOT NULL REFERENCES tickets(id),
  actor_user_id uuid REFERENCES users(id),
  event_type text NOT NULL CHECK (event_type IN ('ticket_created','status_changed','mechanic_assigned','mechanic_reassigned','ticket_cancelled','ticket_completed')),
  old_value text,
  new_value text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ticket_events_ticket_idx ON ticket_events(ticket_id, created_at, id);

CREATE TABLE IF NOT EXISTS admin_audit_events (
  id bigserial PRIMARY KEY,
  actor_user_id uuid REFERENCES users(id),
  target_user_id uuid REFERENCES users(id),
  action text NOT NULL CHECK (action IN ('admin_created_user','admin_disabled_user','admin_enabled_user','admin_reset_password','admin_changed_role')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_audit_actor_idx ON admin_audit_events(actor_user_id, created_at DESC);

-- Backfill each legacy appointment exactly once. Appointment remains the slot truth.
INSERT INTO tickets (id, reference, customer_id, vehicle_id, appointment_id, intervention_type, description, status, created_by_user_id, created_at, updated_at, completed_at, cancelled_at)
SELECT gen_random_uuid(), 'MMS-' || extract(year FROM a.created_at)::integer || '-' || lpad(nextval('ticket_reference_seq')::text, 6, '0'),
  a.customer_id, a.vehicle_id, a.id, a.kind, a.problem,
  CASE a.status WHEN 'Annulé' THEN 'cancelled' WHEN 'Terminé' THEN 'completed'
    WHEN 'En cours' THEN 'in_progress' WHEN 'Pris en charge' THEN 'triage' ELSE 'new' END,
  c.user_id, a.created_at, a.created_at,
  CASE WHEN a.status='Terminé' THEN a.created_at ELSE NULL END,
  CASE WHEN a.status='Annulé' THEN a.created_at ELSE NULL END
FROM appointments a JOIN customers c ON c.id=a.customer_id
WHERE NOT EXISTS (SELECT 1 FROM tickets t WHERE t.appointment_id=a.id);

INSERT INTO ticket_events (ticket_id, actor_user_id, event_type, new_value, created_at)
SELECT t.id, t.created_by_user_id, 'ticket_created', t.status, t.created_at
FROM tickets t WHERE NOT EXISTS (SELECT 1 FROM ticket_events e WHERE e.ticket_id=t.id);
