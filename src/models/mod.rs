pub mod tenant;
pub mod user;

// Re-export commonly used types
pub use tenant::{AppConfig, IdentityBackend, OAuth2ServerConfig, StorageConfig};
pub use user::{Claims, UserRole};

// Additional exports for tests and library users
#[allow(unused_imports)]
pub use tenant::{
    ApiKeyConfig, DatabaseBackendConfig, FederatedBackendConfig, IdentityProviderConfig,
    JwkSigningConfig, LdapBackendConfig, MockBackendConfig, MockUser, OAuth2BackendConfig,
    OidcProviderConfig, SamlIdpConfig, Tenant,
};
