-- migrate:up
-- Add session_id column to authorization_codes and refresh_tokens for session management
-- This enables proper OIDC session management including logout coordination
-- NOTE: session_id is REQUIRED (NOT NULL) - no backward compatibility

-- Add session_id to authorization codes table
ALTER TABLE authorization_codes
ADD COLUMN session_id VARCHAR(255) NOT NULL;

-- Add index for session_id lookups
CREATE INDEX idx_authorization_codes_session_id ON authorization_codes (session_id);

-- Add session_id to refresh tokens table
ALTER TABLE refresh_tokens
ADD COLUMN session_id VARCHAR(255) NOT NULL;

-- Add index for session_id lookups
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);

-- migrate:down

-- Remove session_id from refresh tokens
DROP INDEX IF EXISTS idx_refresh_tokens_session_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS session_id;

-- Remove session_id from authorization codes
DROP INDEX IF EXISTS idx_authorization_codes_session_id;
ALTER TABLE authorization_codes DROP COLUMN IF EXISTS session_id;
