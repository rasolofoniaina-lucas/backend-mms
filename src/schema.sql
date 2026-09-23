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

-- Staff business identities share users/session infrastructure, while login
-- identities and credentials live in dedicated tables for future providers.
ALTER TABLE users ALTER COLUMN phone_e164 DROP NOT NULL;
ALTER TABLE users ALTER COLUMN phone_verified_at DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS username text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at timestamptz;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('customer', 'mechanic', 'workshop_manager', 'admin'));
-- Phase A installations had staff passwords on users. Give those development
-- identities a stable collision-free username before tightening constraints.
UPDATE users SET username='legacy_' || substr(replace(id::text,'-',''),1,12)
WHERE role IN ('mechanic','workshop_manager','admin') AND username IS NULL;
UPDATE users SET username=lower(trim(username)),email=lower(trim(email))
WHERE role IN ('mechanic','workshop_manager','admin');
CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users (lower(username)) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email)) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_role_status_idx ON users(role, status);
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verification_status text NOT NULL DEFAULT 'unverified';
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_method text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified_by_user_id uuid REFERENCES users(id);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_phone_verification_status_check;
ALTER TABLE users ADD CONSTRAINT users_phone_verification_status_check CHECK (phone_verification_status IN ('unverified','pending_manual','verified_otp','verified_manual'));
UPDATE users SET phone_verification_status=CASE WHEN phone_verified_at IS NOT NULL THEN 'verified_otp' ELSE 'unverified' END
WHERE phone_verification_status='unverified' AND phone_verified_at IS NOT NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_identity_shape_check;
ALTER TABLE users ADD CONSTRAINT users_identity_shape_check CHECK (
  (role='customer' AND phone_e164 IS NOT NULL AND username IS NULL)
  OR (role IN ('mechanic','workshop_manager','admin') AND phone_e164 IS NULL
      AND username IS NOT NULL AND username ~ '^[a-z][a-z0-9._-]{2,31}$')
);

CREATE TABLE IF NOT EXISTS user_identities (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('local','ldap','active_directory','oidc')),
  provider_subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id,provider)
);
CREATE UNIQUE INDEX IF NOT EXISTS user_identities_provider_subject_unique
  ON user_identities(provider,lower(provider_subject));

CREATE TABLE IF NOT EXISTS local_credentials (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  must_change_password boolean NOT NULL DEFAULT true,
  password_changed_at timestamptz
);

-- Idempotent Phase A data migration. No business FK changes: user.id remains canonical.
INSERT INTO user_identities(id,user_id,provider,provider_subject)
SELECT gen_random_uuid(),id,'local',username FROM users
WHERE role IN ('mechanic','workshop_manager','admin')
ON CONFLICT (user_id,provider) DO NOTHING;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='password_hash') THEN
    INSERT INTO local_credentials(user_id,password_hash,must_change_password,password_changed_at)
    SELECT id,password_hash,must_change_password,
      CASE WHEN must_change_password THEN NULL ELSE updated_at END
    FROM users WHERE role IN ('mechanic','workshop_manager','admin') AND password_hash IS NOT NULL
    ON CONFLICT (user_id) DO NOTHING;
  END IF;
END $$;
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
ALTER TABLE users DROP COLUMN IF EXISTS must_change_password;

ALTER TABLE customers ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS first_name text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS last_name text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS terms_version text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS privacy_accepted_at timestamptz;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS privacy_version text;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS email text;
-- Anonymous bookings must never merge customer histories merely because a phone
-- number or email matches. Account uniqueness is enforced on users at signup.
DROP INDEX IF EXISTS customers_email_unique;
CREATE INDEX IF NOT EXISTS customers_email_lookup_idx ON customers(lower(email)) WHERE email IS NOT NULL;

-- Client password credentials are deliberately separate from staff local_credentials.
CREATE TABLE IF NOT EXISTS customer_credentials (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  must_change_password boolean NOT NULL DEFAULT false,
  temporary_password_expires_at timestamptz,
  password_changed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS booking_claims (
  id uuid PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS customer_access_requests (
  id uuid PRIMARY KEY,
  customer_id uuid REFERENCES customers(id) ON DELETE SET NULL,
  identifier_masked text NOT NULL,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  resolved_by_user_id uuid REFERENCES users(id)
);
ALTER TABLE customer_access_requests ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE customer_access_requests ADD COLUMN IF NOT EXISTS identifier_type text;
ALTER TABLE customer_access_requests ADD COLUMN IF NOT EXISTS identifier_normalized text;
ALTER TABLE customer_access_requests ADD COLUMN IF NOT EXISTS type text NOT NULL DEFAULT 'password_reset';
ALTER TABLE customer_access_requests ADD COLUMN IF NOT EXISTS resolved_by_user_id uuid REFERENCES users(id);
ALTER TABLE customer_access_requests ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE customer_access_requests DROP CONSTRAINT IF EXISTS customer_access_requests_status_check;
UPDATE customer_access_requests SET status='pending' WHERE status='open';
ALTER TABLE customer_access_requests DROP CONSTRAINT IF EXISTS customer_access_requests_type_check;
ALTER TABLE customer_access_requests ADD CONSTRAINT customer_access_requests_type_check CHECK (type IN ('password_reset'));
ALTER TABLE customer_access_requests ADD CONSTRAINT customer_access_requests_status_check CHECK (status IN ('pending','resolved','cancelled'));
CREATE INDEX IF NOT EXISTS customer_access_requests_pending_identifier_idx ON customer_access_requests(identifier_normalized,created_at DESC) WHERE status='pending';
CREATE UNIQUE INDEX IF NOT EXISTS customer_access_requests_one_pending_identifier ON customer_access_requests(identifier_normalized) WHERE status='pending' AND identifier_normalized IS NOT NULL;
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

-- Customer PINs are intentionally separate from staff credentials.  The hash
-- is Argon2id and is calculated from PIN + server-side CUSTOMER_PIN_PEPPER.
CREATE TABLE IF NOT EXISTS customer_pin_credentials (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  pin_hash text NOT NULL,
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS booking_settings (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  timezone text NOT NULL DEFAULT 'Indian/Antananarivo',
  slot_minutes integer NOT NULL DEFAULT 60 CHECK (slot_minutes=60),
  capacity integer NOT NULL DEFAULT 1 CHECK (capacity=1)
);
INSERT INTO booking_settings(id) VALUES(true) ON CONFLICT (id) DO NOTHING;
CREATE TABLE IF NOT EXISTS workshop_schedule_rules (
  weekday smallint PRIMARY KEY CHECK (weekday BETWEEN 0 AND 6),
  opens_at time,
  closes_at time,
  is_open boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO workshop_schedule_rules(weekday,opens_at,closes_at,is_open) VALUES
 (0,NULL,NULL,false),(1,'08:00','17:00',true),(2,'08:00','17:00',true),(3,'08:00','17:00',true),(4,'08:00','17:00',true),(5,'08:00','17:00',true),(6,'08:00','13:00',true)
ON CONFLICT (weekday) DO NOTHING;
CREATE TABLE IF NOT EXISTS workshop_schedule_exceptions (
  day date PRIMARY KEY,
  opens_at time,
  closes_at time,
  is_open boolean NOT NULL,
  reason text NOT NULL DEFAULT '',
  created_by_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS blocked_slots (
  id uuid PRIMARY KEY,
  slot_date date NOT NULL,
  slot_time time NOT NULL,
  reason text NOT NULL DEFAULT '',
  created_by_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(slot_date,slot_time)
);
CREATE TABLE IF NOT EXISTS customer_verification_events (
  id bigserial PRIMARY KEY,
  customer_id uuid NOT NULL REFERENCES customers(id),
  actor_user_id uuid REFERENCES users(id),
  action text NOT NULL CHECK (action IN ('phone_verified_manual','pin_reset')),
  created_at timestamptz NOT NULL DEFAULT now()
);

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

DROP INDEX IF EXISTS unique_active_slot;
CREATE UNIQUE INDEX IF NOT EXISTS unique_active_slot ON appointments(appointment_date, appointment_time)
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
ALTER TABLE booking_claims ADD COLUMN IF NOT EXISTS ticket_id uuid REFERENCES tickets(id) ON DELETE CASCADE;

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
ALTER TABLE admin_audit_events ADD COLUMN IF NOT EXISTS request_id uuid REFERENCES customer_access_requests(id);
ALTER TABLE admin_audit_events DROP CONSTRAINT IF EXISTS admin_audit_events_action_check;
ALTER TABLE admin_audit_events ADD CONSTRAINT admin_audit_events_action_check CHECK (action IN ('admin_created_user','admin_disabled_user','admin_enabled_user','admin_reset_password','admin_changed_role','customer_password_reset'));
CREATE INDEX IF NOT EXISTS admin_audit_actor_idx ON admin_audit_events(actor_user_id, created_at DESC);

CREATE OR REPLACE FUNCTION reject_mms_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Audit history is append-only';
END $$;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='ticket_events_append_only') THEN
    CREATE TRIGGER ticket_events_append_only BEFORE UPDATE OR DELETE ON ticket_events
      FOR EACH ROW EXECUTE FUNCTION reject_mms_audit_mutation();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='admin_audit_append_only') THEN
    CREATE TRIGGER admin_audit_append_only BEFORE UPDATE OR DELETE ON admin_audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_mms_audit_mutation();
  END IF;
END $$;

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
