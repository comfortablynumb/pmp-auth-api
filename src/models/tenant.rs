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
    /// Identity providers map (provider_id -> IdentityProvider)
    #[serde(default)]
    pub identity_providers: HashMap<String, IdentityProvider>,
    /// Identity storage map for user storage/validation (per-tenant storage)
    #[serde(default)]
    pub identity_storage: HashMap<String, IdentityStorage>,
    /// API key configuration (optional)
    pub api_keys: Option<ApiKeyConfig>,
    /// Federation providers for external OAuth2/OIDC authentication (e.g., Google, GitHub)
    #[serde(default)]
    pub federation_providers: HashMap<String, crate::auth::federation::types::FederationProviderConfig>,
    /// Whether this tenant is active
    #[serde(default = "default_active")]
    pub active: bool,
    /// Allowed CORS origins for this tenant
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_active() -> bool {
    true
}

impl Tenant {
    /// Get a storage by ID from this tenant's storage map
    pub fn get_storage(&self, storage_id: &str) -> Option<&IdentityStorage> {
        self.identity_storage.get(storage_id)
    }

    /// Get the default storage (first in map or one named "default")
    /// This is for backward compatibility during transition
    pub fn get_default_storage(&self) -> Option<&IdentityStorage> {
        // First try to find one named "default"
        if let Some(storage) = self.identity_storage.get("default") {
            return Some(storage);
        }

        // Otherwise return the first one
        self.identity_storage.values().next()
    }

    /// Get a provider by ID from this tenant's provider map
    pub fn get_provider(&self, provider_id: &str) -> Option<&IdentityProvider> {
        self.identity_providers.get(provider_id)
    }

    /// Get the default provider (first in map or one named "default")
    /// This is for backward compatibility during transition
    pub fn get_default_provider(&self) -> Option<&IdentityProvider> {
        // First try to find one named "default"
        if let Some(provider) = self.identity_providers.get("default") {
            return Some(provider);
        }

        // Otherwise return the first one
        self.identity_providers.values().next()
    }

    /// Get a specific OAuth2 provider by ID
    /// Returns (config, storage_id)
    pub fn get_oauth2_provider_by_id(&self, provider_id: &str) -> Option<(&OAuth2ServerConfig, &str)> {
        if let Some(IdentityProvider::OAuth2 {
            config,
            identity_storage_id,
        }) = self.identity_providers.get(provider_id)
        {
            return Some((config, identity_storage_id));
        }
        None
    }

    /// Get the first OAuth2 provider from this tenant (for backward compatibility)
    /// Returns (config, storage_id)
    pub fn get_oauth2_provider(&self) -> Option<(&OAuth2ServerConfig, &str)> {
        // First try to find one named "default"
        if let Some(result) = self.get_oauth2_provider_by_id("default") {
            return Some(result);
        }

        // Otherwise return the first OAuth2 provider
        for (_, provider) in &self.identity_providers {
            if let IdentityProvider::OAuth2 {
                config,
                identity_storage_id,
            } = provider
            {
                return Some((config, identity_storage_id));
            }
        }
        None
    }

    /// Get a specific OIDC provider by ID
    /// Returns (config, storage_id)
    pub fn get_oidc_provider_by_id(&self, provider_id: &str) -> Option<(&OidcProviderConfig, &str)> {
        if let Some(IdentityProvider::Oidc {
            config,
            identity_storage_id,
        }) = self.identity_providers.get(provider_id)
        {
            return Some((config, identity_storage_id));
        }
        None
    }

    /// Get the first OIDC provider from this tenant (for backward compatibility)
    /// Returns (config, storage_id)
    pub fn get_oidc_provider(&self) -> Option<(&OidcProviderConfig, &str)> {
        // First try to find one named "default"
        if let Some(result) = self.get_oidc_provider_by_id("default") {
            return Some(result);
        }

        // Otherwise return the first OIDC provider
        for (_, provider) in &self.identity_providers {
            if let IdentityProvider::Oidc {
                config,
                identity_storage_id,
            } = provider
            {
                return Some((config, identity_storage_id));
            }
        }
        None
    }

    /// Get a specific SAML provider by ID
    /// Returns (config, storage_id)
    pub fn get_saml_provider_by_id(&self, provider_id: &str) -> Option<(&SamlIdpConfig, &str)> {
        if let Some(IdentityProvider::Saml {
            config,
            identity_storage_id,
        }) = self.identity_providers.get(provider_id)
        {
            return Some((config, identity_storage_id));
        }
        None
    }

    /// Get the first SAML provider from this tenant (for backward compatibility)
    /// Returns (config, storage_id)
    pub fn get_saml_provider(&self) -> Option<(&SamlIdpConfig, &str)> {
        // First try to find one named "default"
        if let Some(result) = self.get_saml_provider_by_id("default") {
            return Some(result);
        }

        // Otherwise return the first SAML provider
        for (_, provider) in &self.identity_providers {
            if let IdentityProvider::Saml {
                config,
                identity_storage_id,
            } = provider
            {
                return Some((config, identity_storage_id));
            }
        }
        None
    }

    /// Get a federation provider by ID
    pub fn get_federation_provider(&self, provider_id: &str) -> Option<&crate::auth::federation::types::FederationProviderConfig> {
        self.federation_providers.get(provider_id)
    }

    /// Get all federation providers
    pub fn get_all_federation_providers(&self) -> Vec<&crate::auth::federation::types::FederationProviderConfig> {
        self.federation_providers.values().collect()
    }
}

/// Identity provider configuration (what this service provides)
/// This enum represents a single identity provider with its configuration and linked storage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IdentityProvider {
    /// OAuth2 authorization server
    OAuth2 {
        /// OAuth2 configuration
        #[serde(flatten)]
        config: OAuth2ServerConfig,
        /// ID of the identity storage to use for user lookup
        identity_storage_id: String,
    },
    /// OpenID Connect provider
    Oidc {
        /// OIDC configuration
        #[serde(flatten)]
        config: OidcProviderConfig,
        /// ID of the identity storage to use for user lookup
        identity_storage_id: String,
    },
    /// SAML identity provider
    Saml {
        /// SAML configuration
        #[serde(flatten)]
        config: SamlIdpConfig,
        /// ID of the identity storage to use for user lookup
        identity_storage_id: String,
    },
}

/// Legacy identity provider configuration (deprecated, kept for backward compatibility during migration)
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
    /// Whether password grant is enabled (default: false for security)
    #[serde(default)]
    pub password_grant_enabled: bool,
    /// Whether request parameter is supported (RFC 9101)
    #[serde(default)]
    pub request_parameter_supported: bool,
    /// Whether request_uri parameter is supported (RFC 9101)
    #[serde(default)]
    pub request_uri_parameter_supported: bool,
    /// Whether request_uri registration is required (RFC 9101)
    #[serde(default)]
    pub require_request_uri_registration: bool,
    /// Supported request object signing algorithms (RFC 9101)
    #[serde(default)]
    pub request_object_signing_alg_values_supported: Vec<String>,
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

/// JWK encryption configuration for ID tokens (JWE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkEncryptionConfig {
    /// Key encryption algorithm (RSA-OAEP, RSA-OAEP-256, etc.)
    #[serde(default = "default_encryption_algorithm")]
    pub alg: String,
    /// Content encryption algorithm (A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512)
    #[serde(default = "default_encryption_enc")]
    pub enc: String,
    /// Key ID
    pub kid: String,
    /// Public key for encryption (path or inline PEM)
    pub public_key: String,
    /// Private key for decryption (path or inline PEM) - optional, only needed for decryption
    pub private_key: Option<String>,
}

fn default_encryption_algorithm() -> String {
    "RSA-OAEP".to_string()
}

fn default_encryption_enc() -> String {
    "A256GCM".to_string()
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
    /// Optional encryption key for ID tokens (JWE)
    pub encryption_key: Option<JwkEncryptionConfig>,
    /// Supported ID token encryption algorithms
    #[serde(default)]
    pub id_token_encryption_alg_values_supported: Vec<String>,
    /// Supported ID token encryption encoding values
    #[serde(default)]
    pub id_token_encryption_enc_values_supported: Vec<String>,
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

/// Identity storage - where user identities come from
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IdentityStorage {
    /// LDAP/Active Directory
    Ldap(LdapStorageConfig),
    /// Database (PostgreSQL, MySQL, etc.)
    Database(DatabaseStorageConfig),
}

/// LDAP storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapStorageConfig {
    /// LDAP server URL (ldap://... or ldaps://...)
    pub url: String,
    /// Bind DN for authentication
    pub bind_dn: Option<String>,
    /// Bind password
    pub bind_password: Option<String>,
    /// Base DN for user searches
    pub base_dn: String,
    /// User filter (e.g., "(uid={username})")
    pub user_filter: Option<String>,
    /// Attributes to fetch
    #[serde(default = "default_ldap_attributes")]
    pub attributes: Option<Vec<String>>,
    /// ID attribute name (default: uid)
    pub id_attribute: Option<String>,
    /// Email attribute name (default: mail)
    pub email_attribute: Option<String>,
    /// Name attribute name (default: cn)
    pub name_attribute: Option<String>,
    /// Group base DN (for group queries)
    pub group_base_dn: Option<String>,
    /// Admin group DN (users in this group become admins)
    pub admin_group: Option<String>,
    /// Use StartTLS (default: false)
    pub use_starttls: Option<bool>,
}

fn default_ldap_attributes() -> Option<Vec<String>> {
    Some(vec![
        "uid".to_string(),
        "mail".to_string(),
        "cn".to_string(),
        "displayName".to_string(),
    ])
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStorageConfig {
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageConfig {
    /// In-memory storage (default, no persistence)
    #[default]
    Memory,
    /// PostgreSQL database storage
    Postgres {
        /// PostgreSQL connection string
        connection_string: String,
    },
}

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Map of tenant ID to tenant configuration
    pub tenants: HashMap<String, Tenant>,
    /// Global identity storage map (can be inherited by tenants)
    #[serde(default)]
    pub identity_storage: HashMap<String, IdentityStorage>,
    /// Storage backend configuration
    #[serde(default)]
    pub storage: StorageConfig,
}

impl AppConfig {
    /// Get a tenant by ID
    pub fn get_tenant(&self, tenant_id: &str) -> Option<&Tenant> {
        self.tenants.get(tenant_id)
    }

    /// Get identity storage by ID, checking both global and tenant-specific storage
    pub fn get_identity_storage(
        &self,
        tenant_id: &str,
        storage_id: &str,
    ) -> Option<&IdentityStorage> {
        // First check tenant-specific storage
        if let Some(tenant) = self.get_tenant(tenant_id) {
            if let Some(storage) = tenant.identity_storage.get(storage_id) {
                return Some(storage);
            }
        }

        // Fall back to global storage
        self.identity_storage.get(storage_id)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.tenants.is_empty() {
            return Err("Configuration must have at least one tenant".to_string());
        }

        for (tenant_id, tenant) in &self.tenants {
            // Check that at least one identity provider is configured
            if tenant.identity_providers.is_empty() {
                return Err(format!(
                    "Tenant '{}' must have at least one identity provider configured",
                    tenant_id
                ));
            }

            // Validate each provider
            for (provider_id, provider) in &tenant.identity_providers {
                match provider {
                    IdentityProvider::OAuth2 { config, identity_storage_id } => {
                        if config.issuer.is_empty() {
                            return Err(format!(
                                "OAuth2 provider '{}' for tenant '{}' must have an issuer",
                                provider_id, tenant_id
                            ));
                        }

                        // Validate that the storage_id exists
                        if !tenant.identity_storage.contains_key(identity_storage_id)
                            && !self.identity_storage.contains_key(identity_storage_id)
                        {
                            return Err(format!(
                                "OAuth2 provider '{}' for tenant '{}' references non-existent storage '{}'",
                                provider_id, tenant_id, identity_storage_id
                            ));
                        }

                        // Validate password grant requires database or LDAP storage
                        if config.password_grant_enabled {
                            let storage = self.get_identity_storage(tenant_id, identity_storage_id);
                            if storage.is_none() {
                                return Err(format!(
                                    "OAuth2 provider '{}' for tenant '{}' has password grant enabled but storage '{}' not found",
                                    provider_id, tenant_id, identity_storage_id
                                ));
                            }
                        }
                    }
                    IdentityProvider::Oidc { config, identity_storage_id } => {
                        if config.issuer.is_empty() {
                            return Err(format!(
                                "OIDC provider '{}' for tenant '{}' must have an issuer",
                                provider_id, tenant_id
                            ));
                        }

                        // Validate that the storage_id exists
                        if !tenant.identity_storage.contains_key(identity_storage_id)
                            && !self.identity_storage.contains_key(identity_storage_id)
                        {
                            return Err(format!(
                                "OIDC provider '{}' for tenant '{}' references non-existent storage '{}'",
                                provider_id, tenant_id, identity_storage_id
                            ));
                        }
                    }
                    IdentityProvider::Saml { config, identity_storage_id } => {
                        if config.entity_id.is_empty() {
                            return Err(format!(
                                "SAML provider '{}' for tenant '{}' must have an entity_id",
                                provider_id, tenant_id
                            ));
                        }
                        if config.certificate.is_empty() || config.private_key.is_empty() {
                            return Err(format!(
                                "SAML provider '{}' for tenant '{}' must have certificate and private_key",
                                provider_id, tenant_id
                            ));
                        }

                        // Validate that the storage_id exists
                        if !tenant.identity_storage.contains_key(identity_storage_id)
                            && !self.identity_storage.contains_key(identity_storage_id)
                        {
                            return Err(format!(
                                "SAML provider '{}' for tenant '{}' references non-existent storage '{}'",
                                provider_id, tenant_id, identity_storage_id
                            ));
                        }
                    }
                }
            }

            // Validate identity storage - check both tenant-specific and will validate providers reference valid IDs in later phase
            for (storage_id, storage) in &tenant.identity_storage {
                match storage {
                    IdentityStorage::Ldap(config) => {
                        if config.url.is_empty() || config.base_dn.is_empty() {
                            return Err(format!(
                                "LDAP storage '{}' for tenant '{}' must have url and base_dn",
                                storage_id, tenant_id
                            ));
                        }
                    }
                    IdentityStorage::Database(config) => {
                        if config.connection_url.is_empty() {
                            return Err(format!(
                                "Database storage '{}' for tenant '{}' must have connection_url",
                                storage_id, tenant_id
                            ));
                        }
                    }
                }
            }
        }

        // Validate global identity storage
        for (storage_id, storage) in &self.identity_storage {
            match storage {
                IdentityStorage::Ldap(config) => {
                    if config.url.is_empty() || config.base_dn.is_empty() {
                        return Err(format!(
                            "Global LDAP storage '{}' must have url and base_dn",
                            storage_id
                        ));
                    }
                }
                IdentityStorage::Database(config) => {
                    if config.connection_url.is_empty() {
                        return Err(format!(
                            "Global database storage '{}' must have connection_url",
                            storage_id
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth2_config_password_grant_default_false() {
        let yaml = r#"
issuer: "https://test.example.com"
grant_types: ["authorization_code"]
token_endpoint: "/oauth/token"
authorize_endpoint: "/oauth/authorize"
jwks_endpoint: "/.well-known/jwks.json"
access_token_expiration_secs: 3600
refresh_token_expiration_secs: 86400
signing_key:
  algorithm: "RS256"
  kid: "test-key"
  private_key: "private.pem"
  public_key: "public.pem"
"#;

        let config: OAuth2ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(
            !config.password_grant_enabled,
            "Password grant should be disabled by default"
        );
    }

    #[test]
    fn test_oauth2_config_password_grant_explicitly_enabled() {
        let yaml = r#"
issuer: "https://test.example.com"
grant_types: ["authorization_code", "password"]
token_endpoint: "/oauth/token"
authorize_endpoint: "/oauth/authorize"
jwks_endpoint: "/.well-known/jwks.json"
access_token_expiration_secs: 3600
refresh_token_expiration_secs: 86400
password_grant_enabled: true
signing_key:
  algorithm: "RS256"
  kid: "test-key"
  private_key: "private.pem"
  public_key: "public.pem"
"#;

        let config: OAuth2ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(
            config.password_grant_enabled,
            "Password grant should be enabled when set to true"
        );
    }

    #[test]
    fn test_oauth2_config_password_grant_explicitly_disabled() {
        let yaml = r#"
issuer: "https://test.example.com"
grant_types: ["authorization_code"]
token_endpoint: "/oauth/token"
authorize_endpoint: "/oauth/authorize"
jwks_endpoint: "/.well-known/jwks.json"
access_token_expiration_secs: 3600
refresh_token_expiration_secs: 86400
password_grant_enabled: false
signing_key:
  algorithm: "RS256"
  kid: "test-key"
  private_key: "private.pem"
  public_key: "public.pem"
"#;

        let config: OAuth2ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(
            !config.password_grant_enabled,
            "Password grant should be disabled when explicitly set to false"
        );
    }
}
