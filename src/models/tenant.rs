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
    /// Authentication strategies configured for this tenant
    pub auth_strategies: HashMap<String, AuthStrategy>,
    /// Whether this tenant is active
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

/// Different authentication strategies that can be configured per tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthStrategy {
    /// JWT authentication using JWK (JSON Web Key) sets
    JwkJwt(JwkConfig),
    /// JWT authentication using a shared secret
    SecretJwt(SecretJwtConfig),
    /// OAuth2 authentication
    OAuth2(OAuth2Config),
    /// Local username/password authentication
    Local(LocalAuthConfig),
}

/// Configuration for JWK-based JWT authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkConfig {
    /// URL to fetch the JWK Set (JSON Web Key Set)
    pub jwks_uri: String,
    /// Expected issuer claim in the JWT
    pub issuer: Option<String>,
    /// Expected audience claim in the JWT
    pub audience: Option<Vec<String>>,
    /// Cache duration for JWKs in seconds (default: 3600)
    #[serde(default = "default_jwk_cache_duration")]
    pub cache_duration_secs: u64,
    /// Allowed signing algorithms (default: RS256)
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
}

fn default_jwk_cache_duration() -> u64 {
    3600
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

/// Configuration for secret-based JWT authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretJwtConfig {
    /// Secret key for signing/verifying JWTs
    pub secret: String,
    /// Expected issuer claim in the JWT
    pub issuer: Option<String>,
    /// Expected audience claim in the JWT
    pub audience: Option<Vec<String>>,
    /// Token expiration in seconds (default: 86400 = 24 hours)
    #[serde(default = "default_token_expiration")]
    pub expiration_secs: i64,
}

fn default_token_expiration() -> i64 {
    86400
}

/// Configuration for OAuth2 authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token endpoint URL
    pub token_url: String,
    /// Redirect URI for OAuth2 callback
    pub redirect_uri: String,
    /// OAuth2 scopes to request
    #[serde(default)]
    pub scopes: Vec<String>,
    /// User info endpoint URL (optional)
    pub userinfo_url: Option<String>,
}

/// Configuration for local username/password authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuthConfig {
    /// Whether to allow user registration
    #[serde(default = "default_allow_registration")]
    pub allow_registration: bool,
    /// Minimum password length
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
    /// Whether to require email verification
    #[serde(default)]
    pub require_email_verification: bool,
    /// JWT secret for this tenant's local auth
    pub jwt_secret: String,
    /// Token expiration in seconds (default: 86400 = 24 hours)
    #[serde(default = "default_token_expiration")]
    pub expiration_secs: i64,
}

fn default_allow_registration() -> bool {
    true
}

fn default_min_password_length() -> usize {
    8
}

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Map of tenant ID to tenant configuration
    pub tenants: HashMap<String, Tenant>,
}

impl AppConfig {
    /// Get a tenant by ID
    pub fn get_tenant(&self, tenant_id: &str) -> Option<&Tenant> {
        self.tenants.get(tenant_id)
    }

    /// Get an auth strategy for a tenant
    pub fn get_auth_strategy(&self, tenant_id: &str, strategy_name: &str) -> Option<&AuthStrategy> {
        self.get_tenant(tenant_id)?
            .auth_strategies
            .get(strategy_name)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.tenants.is_empty() {
            return Err("Configuration must have at least one tenant".to_string());
        }

        for (tenant_id, tenant) in &self.tenants {
            if tenant.auth_strategies.is_empty() {
                return Err(format!(
                    "Tenant '{}' must have at least one auth strategy",
                    tenant_id
                ));
            }

            // Validate each auth strategy
            for (strategy_name, strategy) in &tenant.auth_strategies {
                match strategy {
                    AuthStrategy::JwkJwt(config) => {
                        if config.jwks_uri.is_empty() {
                            return Err(format!(
                                "JWK strategy '{}' for tenant '{}' must have a jwks_uri",
                                strategy_name, tenant_id
                            ));
                        }
                    }
                    AuthStrategy::SecretJwt(config) => {
                        if config.secret.is_empty() {
                            return Err(format!(
                                "Secret JWT strategy '{}' for tenant '{}' must have a secret",
                                strategy_name, tenant_id
                            ));
                        }
                    }
                    AuthStrategy::OAuth2(config) => {
                        if config.client_id.is_empty() || config.client_secret.is_empty() {
                            return Err(format!(
                                "OAuth2 strategy '{}' for tenant '{}' must have client_id and client_secret",
                                strategy_name, tenant_id
                            ));
                        }
                    }
                    AuthStrategy::Local(config) => {
                        if config.jwt_secret.is_empty() {
                            return Err(format!(
                                "Local auth strategy '{}' for tenant '{}' must have a jwt_secret",
                                strategy_name, tenant_id
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
