use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a tenant in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique identifier for the tenant
    pub id: String,
    /// Display name for the tenant
    pub name: String,
    /// Description of the tenant
    pub description: Option<String>,
    /// Identity provider configuration
    pub identity_provider: IdentityProviderConfig,
    /// Identity backend for user storage/validation
    pub identity_backend: IdentityBackend,
    /// API key configuration (optional)
    pub api_keys: Option<ApiKeyConfig>,
    /// Whether this tenant is active
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

/// Identity provider configuration (what this service provides)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    /// OAuth2 authorization server configuration
    pub oauth2: Option<OAuth2ServerConfig>,
    /// OpenID Connect provider configuration
    pub oidc: Option<OidcProviderConfig>,
    /// SAML identity provider configuration
    pub saml: Option<SamlIdpConfig>,
}

/// OAuth2 Authorization Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ServerConfig {
    /// Issuer URL
    pub issuer: String,
    /// Supported grant types
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    /// Token endpoint path
    #[serde(default = "default_token_endpoint")]
    pub token_endpoint: String,
    /// Authorization endpoint path
    #[serde(default = "default_authorize_endpoint")]
    pub authorize_endpoint: String,
    /// JWKS endpoint path
    #[serde(default = "default_jwks_endpoint")]
    pub jwks_endpoint: String,
    /// Access token expiration in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_access_token_expiration")]
    pub access_token_expiration_secs: i64,
    /// Refresh token expiration in seconds (default: 2592000 = 30 days)
    #[serde(default = "default_refresh_token_expiration")]
    pub refresh_token_expiration_secs: i64,
    /// JWK signing configuration
    pub signing_key: JwkSigningConfig,
}

fn default_grant_types() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "client_credentials".to_string(),
        "refresh_token".to_string(),
    ]
}

fn default_token_endpoint() -> String {
    "/oauth/token".to_string()
}

fn default_authorize_endpoint() -> String {
    "/oauth/authorize".to_string()
}

fn default_jwks_endpoint() -> String {
    "/.well-known/jwks.json".to_string()
}

fn default_access_token_expiration() -> i64 {
    3600
}

fn default_refresh_token_expiration() -> i64 {
    2592000
}

/// JWK signing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSigningConfig {
    /// Algorithm (RS256, ES256, etc.)
    #[serde(default = "default_signing_algorithm")]
    pub algorithm: String,
    /// Key ID
    pub kid: String,
    /// Private key path or inline PEM
    pub private_key: String,
    /// Public key path or inline PEM
    pub public_key: String,
}

fn default_signing_algorithm() -> String {
    "RS256".to_string()
}

/// OpenID Connect provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Issuer URL (same as OAuth2 but required for OIDC)
    pub issuer: String,
    /// UserInfo endpoint path
    #[serde(default = "default_userinfo_endpoint")]
    pub userinfo_endpoint: String,
    /// Supported claims
    #[serde(default = "default_oidc_claims")]
    pub claims_supported: Vec<String>,
    /// Supported scopes
    #[serde(default = "default_oidc_scopes")]
    pub scopes_supported: Vec<String>,
    /// ID token expiration in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_id_token_expiration")]
    pub id_token_expiration_secs: i64,
}

fn default_userinfo_endpoint() -> String {
    "/oauth/userinfo".to_string()
}

fn default_oidc_claims() -> Vec<String> {
    vec![
        "sub".to_string(),
        "email".to_string(),
        "email_verified".to_string(),
        "name".to_string(),
        "picture".to_string(),
    ]
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

fn default_id_token_expiration() -> i64 {
    3600
}

/// SAML Identity Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    /// Entity ID
    pub entity_id: String,
    /// SSO URL
    #[serde(default = "default_sso_url")]
    pub sso_url: String,
    /// SLO (Single Logout) URL
    pub slo_url: Option<String>,
    /// Certificate (PEM format or path)
    pub certificate: String,
    /// Private key (PEM format or path)
    pub private_key: String,
    /// Metadata endpoint
    #[serde(default = "default_metadata_endpoint")]
    pub metadata_endpoint: String,
    /// Name ID format
    #[serde(default = "default_name_id_format")]
    pub name_id_format: String,
}

fn default_sso_url() -> String {
    "/saml/sso".to_string()
}

fn default_metadata_endpoint() -> String {
    "/saml/metadata".to_string()
}

fn default_name_id_format() -> String {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
}

/// Identity backend - where user identities come from
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IdentityBackend {
    /// External OAuth2 provider (Google, GitHub, etc.)
    OAuth2(OAuth2BackendConfig),
    /// LDAP/Active Directory
    Ldap(LdapBackendConfig),
    /// Database (PostgreSQL, MySQL, etc.)
    Database(DatabaseBackendConfig),
    /// Federated identity from upstream IdP
    Federated(FederatedBackendConfig),
    /// Mock backend for testing
    Mock(MockBackendConfig),
}

/// OAuth2 backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2BackendConfig {
    /// Provider name (google, github, microsoft, etc.)
    pub provider: String,
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token endpoint URL
    pub token_url: String,
    /// UserInfo endpoint URL
    pub userinfo_url: String,
    /// OAuth2 scopes to request
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// LDAP backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapBackendConfig {
    /// LDAP server URL (ldap://... or ldaps://...)
    pub url: String,
    /// Bind DN for authentication
    pub bind_dn: String,
    /// Bind password
    pub bind_password: String,
    /// Base DN for user searches
    pub base_dn: String,
    /// User filter (e.g., "(uid={username})")
    pub user_filter: String,
    /// Attributes to fetch
    #[serde(default = "default_ldap_attributes")]
    pub attributes: Vec<String>,
}

fn default_ldap_attributes() -> Vec<String> {
    vec![
        "uid".to_string(),
        "mail".to_string(),
        "cn".to_string(),
        "displayName".to_string(),
    ]
}

/// Database backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseBackendConfig {
    /// Database connection URL
    pub connection_url: String,
    /// Database type (postgres, mysql, etc.)
    pub db_type: String,
    /// Users table name
    #[serde(default = "default_users_table")]
    pub users_table: String,
    /// ID column name
    #[serde(default = "default_id_column")]
    pub id_column: String,
    /// Email column name
    #[serde(default = "default_email_column")]
    pub email_column: String,
    /// Additional attribute mappings
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
}

fn default_users_table() -> String {
    "users".to_string()
}

fn default_id_column() -> String {
    "id".to_string()
}

fn default_email_column() -> String {
    "email".to_string()
}

/// Federated backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedBackendConfig {
    /// Upstream IdP type (saml, oidc, etc.)
    pub idp_type: String,
    /// SAML metadata URL or configuration
    pub metadata_url: Option<String>,
    /// OIDC discovery URL
    pub discovery_url: Option<String>,
    /// Client ID (for OIDC)
    pub client_id: Option<String>,
    /// Client secret (for OIDC)
    pub client_secret: Option<String>,
}

/// Mock backend for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockBackendConfig {
    /// Predefined users for testing
    #[serde(default)]
    pub users: Vec<MockUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// API Key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Whether API keys are enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// API key expiration in seconds (0 = no expiration)
    #[serde(default)]
    pub expiration_secs: i64,
    /// Allowed scopes for API keys
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// JWK for signing API keys
    pub signing_key: JwkSigningConfig,
}

fn default_enabled() -> bool {
    true
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageConfig {
    /// In-memory storage (default, no persistence)
    Memory,
    /// PostgreSQL database storage
    Postgres {
        /// PostgreSQL connection string
        connection_string: String,
    },
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig::Memory
    }
}

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Map of tenant ID to tenant configuration
    pub tenants: HashMap<String, Tenant>,
    /// Storage backend configuration
    #[serde(default)]
    pub storage: StorageConfig,
}

impl AppConfig {
    /// Get a tenant by ID
    pub fn get_tenant(&self, tenant_id: &str) -> Option<&Tenant> {
        self.tenants.get(tenant_id)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.tenants.is_empty() {
            return Err("Configuration must have at least one tenant".to_string());
        }

        for (tenant_id, tenant) in &self.tenants {
            // Check that at least one identity provider is configured
            if tenant.identity_provider.oauth2.is_none()
                && tenant.identity_provider.oidc.is_none()
                && tenant.identity_provider.saml.is_none()
            {
                return Err(format!(
                    "Tenant '{}' must have at least one identity provider configured (oauth2, oidc, or saml)",
                    tenant_id
                ));
            }

            // Validate OAuth2 server config if present
            if let Some(oauth2) = &tenant.identity_provider.oauth2
                && oauth2.issuer.is_empty()
            {
                return Err(format!(
                    "OAuth2 issuer for tenant '{}' cannot be empty",
                    tenant_id
                ));
            }

            // Validate OIDC config if present
            if let Some(oidc) = &tenant.identity_provider.oidc
                && oidc.issuer.is_empty()
            {
                return Err(format!(
                    "OIDC issuer for tenant '{}' cannot be empty",
                    tenant_id
                ));
            }

            // Validate SAML config if present
            if let Some(saml) = &tenant.identity_provider.saml {
                if saml.entity_id.is_empty() {
                    return Err(format!(
                        "SAML entity_id for tenant '{}' cannot be empty",
                        tenant_id
                    ));
                }
                if saml.certificate.is_empty() || saml.private_key.is_empty() {
                    return Err(format!(
                        "SAML certificate and private_key for tenant '{}' cannot be empty",
                        tenant_id
                    ));
                }
            }

            // Validate identity backend
            match &tenant.identity_backend {
                IdentityBackend::OAuth2(config) => {
                    if config.client_id.is_empty() || config.client_secret.is_empty() {
                        return Err(format!(
                            "OAuth2 backend for tenant '{}' must have client_id and client_secret",
                            tenant_id
                        ));
                    }
                }
                IdentityBackend::Ldap(config) => {
                    if config.url.is_empty() || config.base_dn.is_empty() {
                        return Err(format!(
                            "LDAP backend for tenant '{}' must have url and base_dn",
                            tenant_id
                        ));
                    }
                }
                IdentityBackend::Database(config) => {
                    if config.connection_url.is_empty() {
                        return Err(format!(
                            "Database backend for tenant '{}' must have connection_url",
                            tenant_id
                        ));
                    }
                }
                IdentityBackend::Federated(config) => {
                    if config.idp_type.is_empty() {
                        return Err(format!(
                            "Federated backend for tenant '{}' must have idp_type",
                            tenant_id
                        ));
                    }
                }
                IdentityBackend::Mock(_) => {
                    // Mock backend is always valid
                }
            }
        }

        Ok(())
    }
}
