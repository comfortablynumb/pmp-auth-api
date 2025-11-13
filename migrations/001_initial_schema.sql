-- Initial schema for PMP Auth API storage
-- PostgreSQL database

-- Authorization codes table
CREATE TABLE IF NOT EXISTS authorization_codes (
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
    nonce VARCHAR(255),
    INDEX idx_authorization_codes_expires_at (expires_at),
    INDEX idx_authorization_codes_tenant_id (tenant_id)
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    INDEX idx_refresh_tokens_expires_at (expires_at),
    INDEX idx_refresh_tokens_tenant_id (tenant_id),
    INDEX idx_refresh_tokens_user_id (user_id)
);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_api_keys_tenant_id (tenant_id),
    INDEX idx_api_keys_revoked (revoked),
    INDEX idx_api_keys_expires_at (expires_at)
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    INDEX idx_sessions_expires_at (expires_at),
    INDEX idx_sessions_tenant_id (tenant_id),
    INDEX idx_sessions_user_id (user_id)
);

-- Device codes table (RFC 8628)
CREATE TABLE IF NOT EXISTS device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    user_code VARCHAR(20) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    user_id VARCHAR(255),
    INDEX idx_device_codes_user_code (user_code),
    INDEX idx_device_codes_expires_at (expires_at),
    INDEX idx_device_codes_tenant_id (tenant_id),
    INDEX idx_device_codes_status (status)
);

-- Revoked tokens table
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    INDEX idx_revoked_tokens_expires_at (expires_at)
);

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

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_revoked ON api_keys (tenant_id, revoked);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code_status ON device_codes (user_code, status);
