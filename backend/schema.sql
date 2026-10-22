CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN ('admin', 'owner', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    document_id UUID NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    permission TEXT NOT NULL
        CHECK (permission IN ('read', 'edit')),

    granted_by UUID NOT NULL
        REFERENCES users(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (document_id, user_id)
);

-- Audit trail for security-sensitive actions
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    outcome TEXT NOT NULL
        CHECK (outcome IN ('success', 'denied', 'failure')),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    previous_hash TEXT,
    entry_hash TEXT NOT NULL
);
