CREATE TABLE IF NOT EXISTS colleges (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  role_access_ids JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  college_id    TEXT NOT NULL REFERENCES colleges(id) ON DELETE CASCADE,
  role          TEXT NOT NULL,
  name          TEXT NOT NULL,
  father_name   TEXT,
  phone         TEXT NOT NULL,
  branch        TEXT,
  year          TEXT,
  department    TEXT,
  designation   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at    TIMESTAMPTZ,
  UNIQUE (college_id, role, phone)
);

CREATE TABLE IF NOT EXISTS tickets (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  short_id      TEXT UNIQUE NOT NULL,
  college_id    TEXT NOT NULL REFERENCES colleges(id) ON DELETE CASCADE,
  owner_id      UUID REFERENCES accounts(id) ON DELETE SET NULL,
  name          TEXT NOT NULL,
  phone         TEXT NOT NULL,
  category      TEXT NOT NULL,
  urgent        BOOLEAN NOT NULL DEFAULT FALSE,
  description   TEXT,
  issue_image   TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
  forwarded     BOOLEAN NOT NULL DEFAULT FALSE,
  forwarded_at  TIMESTAMPTZ,
  fix_image     TEXT,
  fixed_at      TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lectures (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  college_id      TEXT NOT NULL REFERENCES colleges(id) ON DELETE CASCADE,
  professor_id    UUID REFERENCES accounts(id) ON DELETE SET NULL,
  professor_name  TEXT,
  professor_phone TEXT,
  subject         TEXT NOT NULL,
  branch          TEXT NOT NULL,
  year            INT NOT NULL,
  semester        TEXT NOT NULL,
  room            TEXT,
  date            DATE NOT NULL,
  start_time      TEXT NOT NULL,
  end_time        TEXT NOT NULL,
  type            TEXT NOT NULL,
  attendance      TEXT CHECK (attendance IN ('attend','not-attend')),
  attendance_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS student_profiles (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  college_id   TEXT NOT NULL REFERENCES colleges(id) ON DELETE CASCADE,
  account_id   UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  father_name  TEXT,
  title        TEXT,
  branch       TEXT,
  year         TEXT,
  bio          TEXT,
  line         TEXT,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (college_id, account_id)
);

CREATE TABLE IF NOT EXISTS recovery_otps (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone        TEXT NOT NULL,
  code_hash    TEXT NOT NULL,
  attempts     INT NOT NULL DEFAULT 0,
  expires_at   TIMESTAMPTZ NOT NULL,
  consumed_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accounts_college_role
  ON accounts (college_id, role) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tickets_college_status
  ON tickets (college_id, status);

CREATE INDEX IF NOT EXISTS idx_lectures_college_bysem
  ON lectures (college_id, branch, year, semester);