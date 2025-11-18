-- migrate:up
-- Initial schema for PMP Auth API storage
-- PostgreSQL database

-- Authorization codes table
CREATE TABLE authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    nonce VARCHAR(255)
);

CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes (expires_at);
CREATE INDEX idx_authorization_codes_tenant_id ON authorization_codes (tenant_id);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
CREATE INDEX idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- API keys table
CREATE TABLE api_keys (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX idx_api_keys_revoked ON api_keys (revoked);
CREATE INDEX idx_api_keys_expires_at ON api_keys (expires_at);
CREATE INDEX idx_api_keys_tenant_revoked ON api_keys (tenant_id, revoked);

-- Sessions table
CREATE TABLE sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX idx_sessions_tenant_id ON sessions (tenant_id);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);

-- Device codes table (RFC 8628)
CREATE TABLE device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    user_code VARCHAR(20) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    user_id VARCHAR(255)
);

CREATE INDEX idx_device_codes_user_code ON device_codes (user_code);
CREATE INDEX idx_device_codes_expires_at ON device_codes (expires_at);
CREATE INDEX idx_device_codes_tenant_id ON device_codes (tenant_id);
CREATE INDEX idx_device_codes_status ON device_codes (status);
CREATE INDEX idx_device_codes_user_code_status ON device_codes (user_code, status);

-- Revoked tokens table
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);

-- Create function for automatic cleanup of expired items
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    total_deleted INTEGER := 0;
    deleted_count INTEGER;
BEGIN
    -- Delete expired authorization codes
    DELETE FROM authorization_codes WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Delete expired sessions
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Delete expired device codes
    DELETE FROM device_codes WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Delete expired revoked tokens
    DELETE FROM revoked_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    RETURN total_deleted;
END;
$$ LANGUAGE plpgsql;

-- migrate:down

-- Drop function
DROP FUNCTION IF EXISTS cleanup_expired_data();

-- Drop tables in reverse order
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS device_codes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS authorization_codes;
