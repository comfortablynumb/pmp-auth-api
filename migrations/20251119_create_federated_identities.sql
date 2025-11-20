-- Create federated_identities table
-- This table links users to external OAuth2/OIDC providers (Google, GitHub, Azure AD, etc.)
CREATE TABLE IF NOT EXISTS federated_identities (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255) NOT NULL,
    provider_email_verified BOOLEAN NOT NULL DEFAULT false,
    provider_profile_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,

    -- Unique constraint: one provider identity per tenant
    CONSTRAINT unique_federated_identity UNIQUE (tenant_id, provider_id, provider_user_id),

    -- Foreign keys
    CONSTRAINT fk_federated_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_federated_identities_user_id ON federated_identities(user_id);
CREATE INDEX idx_federated_identities_tenant_provider ON federated_identities(tenant_id, provider_id);
CREATE INDEX idx_federated_identities_email ON federated_identities(provider_email);
CREATE INDEX idx_federated_identities_last_login ON federated_identities(last_login_at);

-- Comments
COMMENT ON TABLE federated_identities IS 'Links users to external OAuth2/OIDC providers (Google, GitHub, etc.)';
COMMENT ON COLUMN federated_identities.id IS 'Unique ID for this federated identity link';
COMMENT ON COLUMN federated_identities.tenant_id IS 'Tenant ID this federated identity belongs to';
COMMENT ON COLUMN federated_identities.user_id IS 'Our internal user ID';
COMMENT ON COLUMN federated_identities.provider_id IS 'Provider identifier (e.g., "google", "github", "azure-ad")';
COMMENT ON COLUMN federated_identities.provider_user_id IS 'User ID from the external provider (e.g., Google sub, GitHub id)';
COMMENT ON COLUMN federated_identities.provider_email IS 'Email address from the external provider';
COMMENT ON COLUMN federated_identities.provider_email_verified IS 'Whether the email is verified by the provider';
COMMENT ON COLUMN federated_identities.provider_profile_data IS 'Full profile data from provider stored as JSON';
COMMENT ON COLUMN federated_identities.created_at IS 'When this identity was first linked';
COMMENT ON COLUMN federated_identities.updated_at IS 'When this identity was last updated';
COMMENT ON COLUMN federated_identities.last_login_at IS 'When the user last authenticated via this provider';
