-- PostgreSQL initialization script for PMP Auth API

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables for OAuth2 tokens and sessions
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    access_token VARCHAR(500) UNIQUE NOT NULL,
    refresh_token VARCHAR(500),
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scope TEXT,
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth2_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret VARCHAR(255),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[],
    grant_types TEXT[],
    scope TEXT,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    scopes TEXT[],
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255),
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    secret VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT false,
    verified BOOLEAN DEFAULT false,
    backup_codes TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_oauth2_codes_expires ON oauth2_authorization_codes(expires_at);
CREATE INDEX idx_oauth2_codes_client ON oauth2_authorization_codes(client_id);
CREATE INDEX idx_oauth2_codes_user ON oauth2_authorization_codes(user_id);

CREATE INDEX idx_oauth2_tokens_access ON oauth2_access_tokens(access_token);
CREATE INDEX idx_oauth2_tokens_refresh ON oauth2_access_tokens(refresh_token);
CREATE INDEX idx_oauth2_tokens_expires ON oauth2_access_tokens(expires_at);
CREATE INDEX idx_oauth2_tokens_user ON oauth2_access_tokens(user_id);

CREATE INDEX idx_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_audit_action ON audit_logs(action);

-- Insert sample OAuth2 client for testing
INSERT INTO oauth2_clients (client_id, client_secret, tenant_id, name, redirect_uris, grant_types, scope)
VALUES (
    'demo-client',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYFJ3hX4VTK',  -- hashed: 'demo-secret'
    'demo-ldap',
    'Demo OAuth2 Client',
    ARRAY['http://localhost:8080/callback', 'http://localhost:3000/callback'],
    ARRAY['authorization_code', 'refresh_token', 'client_credentials'],
    'openid profile email'
) ON CONFLICT DO NOTHING;

INSERT INTO oauth2_clients (client_id, client_secret, tenant_id, name, redirect_uris, grant_types, scope)
VALUES (
    'test-app',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYFJ3hX4VTK',  -- hashed: 'demo-secret'
    'demo-mock',
    'Test Application',
    ARRAY['http://localhost:8080/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    'openid profile email'
) ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pmp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pmp_user;
