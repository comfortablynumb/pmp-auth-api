-- migrate:up
-- OAuth2 client registry table
CREATE TABLE oauth2_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret TEXT,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    response_types TEXT[] NOT NULL DEFAULT '{}',
    client_type VARCHAR(20) NOT NULL DEFAULT 'confidential',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    public_key_pem TEXT,
    jwks_uri TEXT,
    token_endpoint_auth_method VARCHAR(50),
    backchannel_logout_uri TEXT,
    backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    frontchannel_logout_uri TEXT,
    frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT oauth2_clients_client_type_check CHECK (client_type IN ('confidential', 'public'))
);

-- Index for tenant lookups
CREATE INDEX idx_oauth2_clients_tenant_id ON oauth2_clients(tenant_id);

-- Index for active clients
CREATE INDEX idx_oauth2_clients_active ON oauth2_clients(active) WHERE active = TRUE;

-- migrate:down
DROP INDEX IF EXISTS idx_oauth2_clients_active;
DROP INDEX IF EXISTS idx_oauth2_clients_tenant_id;
DROP TABLE IF EXISTS oauth2_clients;
