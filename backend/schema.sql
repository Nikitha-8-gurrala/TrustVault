CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN ('admin', 'owner', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);