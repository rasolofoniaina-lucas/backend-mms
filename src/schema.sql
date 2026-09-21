CREATE TABLE IF NOT EXISTS customers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  phone text NOT NULL DEFAULT '',
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
