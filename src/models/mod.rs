pub mod tenant;
pub mod user;

// Re-export commonly used types
pub use tenant::{AppConfig, IdentityStorage, OAuth2ServerConfig, StorageConfig};
pub use user::{Claims, UserRole};

// Additional exports for tests and library users
#[allow(unused_imports)]
pub use tenant::{
    ApiKeyConfig, DatabaseStorageConfig, IdentityProvider, IdentityProviderConfig,
    JwkEncryptionConfig, JwkSigningConfig, LdapStorageConfig, OidcProviderConfig, SamlIdpConfig,
    Tenant,
};
