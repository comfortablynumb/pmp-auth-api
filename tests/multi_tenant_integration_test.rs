use pmp_auth_api::models::{
    AppConfig, IdentityBackend, IdentityProviderConfig, JwkSigningConfig, MockBackendConfig,
    OAuth2ServerConfig, OidcProviderConfig,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Test configuration loading and validation with OAuth2 provider
#[test]
fn test_create_oauth2_tenant_config() {
    let identity_provider = IdentityProviderConfig {
        oauth2: Some(OAuth2ServerConfig {
            issuer: "https://test.example.com".to_string(),
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint: "/oauth/token".to_string(),
            authorize_endpoint: "/oauth/authorize".to_string(),
            jwks_endpoint: "/.well-known/jwks.json".to_string(),
            access_token_expiration_secs: 3600,
            refresh_token_expiration_secs: 86400,
            signing_key: JwkSigningConfig {
                algorithm: "RS256".to_string(),
                kid: "test-key".to_string(),
                private_key: "/path/to/private.pem".to_string(),
                public_key: "/path/to/public.pem".to_string(),
            },
        }),
        oidc: None,
        saml: None,
    };

    let identity_backend = IdentityBackend::Mock(MockBackendConfig { users: vec![] });

    let mut tenants = HashMap::new();
    tenants.insert(
        "test-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "test-tenant".to_string(),
            name: "Test Tenant".to_string(),
            description: Some("Integration test tenant".to_string()),
            identity_provider,
            identity_backend,
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 1);
    assert!(config.get_tenant("test-tenant").is_some());
}

/// Test multiple tenants with different identity providers
#[test]
fn test_multiple_tenants_different_providers() {
    let mut tenants = HashMap::new();

    // Tenant 1: OAuth2 provider
    tenants.insert(
        "tenant1".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "tenant1".to_string(),
            name: "Tenant 1".to_string(),
            description: None,
            identity_provider: IdentityProviderConfig {
                oauth2: Some(OAuth2ServerConfig {
                    issuer: "https://tenant1.example.com".to_string(),
                    grant_types: vec!["authorization_code".to_string()],
                    token_endpoint: "/oauth/token".to_string(),
                    authorize_endpoint: "/oauth/authorize".to_string(),
                    jwks_endpoint: "/.well-known/jwks.json".to_string(),
                    access_token_expiration_secs: 3600,
                    refresh_token_expiration_secs: 86400,
                    signing_key: JwkSigningConfig {
                        algorithm: "RS256".to_string(),
                        kid: "tenant1-key".to_string(),
                        private_key: "/path/to/tenant1-private.pem".to_string(),
                        public_key: "/path/to/tenant1-public.pem".to_string(),
                    },
                }),
                oidc: None,
                saml: None,
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: true,
        },
    );

    // Tenant 2: OIDC provider
    tenants.insert(
        "tenant2".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "tenant2".to_string(),
            name: "Tenant 2".to_string(),
            description: None,
            identity_provider: IdentityProviderConfig {
                oauth2: Some(OAuth2ServerConfig {
                    issuer: "https://tenant2.example.com".to_string(),
                    grant_types: vec!["authorization_code".to_string()],
                    token_endpoint: "/oauth/token".to_string(),
                    authorize_endpoint: "/oauth/authorize".to_string(),
                    jwks_endpoint: "/.well-known/jwks.json".to_string(),
                    access_token_expiration_secs: 3600,
                    refresh_token_expiration_secs: 86400,
                    signing_key: JwkSigningConfig {
                        algorithm: "RS256".to_string(),
                        kid: "tenant2-key".to_string(),
                        private_key: "/path/to/tenant2-private.pem".to_string(),
                        public_key: "/path/to/tenant2-public.pem".to_string(),
                    },
                }),
                oidc: Some(OidcProviderConfig {
                    issuer: "https://tenant2.example.com".to_string(),
                    userinfo_endpoint: "/oauth/userinfo".to_string(),
                    claims_supported: vec!["sub".to_string(), "email".to_string()],
                    scopes_supported: vec!["openid".to_string(), "profile".to_string()],
                    id_token_expiration_secs: 3600,
                }),
                saml: None,
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 2);

    let tenant1 = config.get_tenant("tenant1").unwrap();
    assert!(tenant1.identity_provider.oauth2.is_some());
    assert!(tenant1.identity_provider.oidc.is_none());

    let tenant2 = config.get_tenant("tenant2").unwrap();
    assert!(tenant2.identity_provider.oauth2.is_some());
    assert!(tenant2.identity_provider.oidc.is_some());
}

/// Test tenant with all identity providers (OAuth2 + OIDC + SAML)
#[test]
fn test_tenant_with_all_providers() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "full-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "full-tenant".to_string(),
            name: "Full Tenant".to_string(),
            description: Some("Tenant with all identity providers".to_string()),
            identity_provider: IdentityProviderConfig {
                oauth2: Some(OAuth2ServerConfig {
                    issuer: "https://full.example.com".to_string(),
                    grant_types: vec!["authorization_code".to_string()],
                    token_endpoint: "/oauth/token".to_string(),
                    authorize_endpoint: "/oauth/authorize".to_string(),
                    jwks_endpoint: "/.well-known/jwks.json".to_string(),
                    access_token_expiration_secs: 3600,
                    refresh_token_expiration_secs: 86400,
                    signing_key: JwkSigningConfig {
                        algorithm: "RS256".to_string(),
                        kid: "full-key".to_string(),
                        private_key: "/path/to/full-private.pem".to_string(),
                        public_key: "/path/to/full-public.pem".to_string(),
                    },
                }),
                oidc: Some(OidcProviderConfig {
                    issuer: "https://full.example.com".to_string(),
                    userinfo_endpoint: "/oauth/userinfo".to_string(),
                    claims_supported: vec!["sub".to_string(), "email".to_string()],
                    scopes_supported: vec!["openid".to_string(), "profile".to_string()],
                    id_token_expiration_secs: 3600,
                }),
                saml: Some(pmp_auth_api::models::SamlIdpConfig {
                    entity_id: "https://full.example.com/saml".to_string(),
                    sso_url: "/saml/sso".to_string(),
                    slo_url: Some("/saml/slo".to_string()),
                    certificate: "dummy-cert".to_string(),
                    private_key: "/path/to/saml-key.pem".to_string(),
                    metadata_endpoint: "/saml/metadata".to_string(),
                    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                        .to_string(),
                }),
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 1);

    let tenant = config.get_tenant("full-tenant").unwrap();
    assert!(tenant.identity_provider.oauth2.is_some());
    assert!(tenant.identity_provider.oidc.is_some());
    assert!(tenant.identity_provider.saml.is_some());
}

/// Test config validation errors
#[test]
fn test_config_validation_errors() {
    // Test 1: No identity provider configured
    let mut tenants = HashMap::new();
    tenants.insert(
        "bad-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "bad-tenant".to_string(),
            name: "Bad Tenant".to_string(),
            description: None,
            identity_provider: IdentityProviderConfig {
                oauth2: None,
                oidc: None,
                saml: None,
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig { tenants };
    let result = config.validate();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("at least one identity provider")
    );

    // Test 2: Empty tenants
    let config = AppConfig {
        tenants: HashMap::new(),
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("at least one tenant"));
}

/// Test Arc-wrapped config (thread safety)
#[test]
fn test_arc_wrapped_config() {
    let mut tenants = HashMap::new();
    tenants.insert(
        "test-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "test-tenant".to_string(),
            name: "Test Tenant".to_string(),
            description: None,
            identity_provider: IdentityProviderConfig {
                oauth2: Some(OAuth2ServerConfig {
                    issuer: "https://test.example.com".to_string(),
                    grant_types: vec!["authorization_code".to_string()],
                    token_endpoint: "/oauth/token".to_string(),
                    authorize_endpoint: "/oauth/authorize".to_string(),
                    jwks_endpoint: "/.well-known/jwks.json".to_string(),
                    access_token_expiration_secs: 3600,
                    refresh_token_expiration_secs: 86400,
                    signing_key: JwkSigningConfig {
                        algorithm: "RS256".to_string(),
                        kid: "test-key".to_string(),
                        private_key: "/path/to/private.pem".to_string(),
                        public_key: "/path/to/public.pem".to_string(),
                    },
                }),
                oidc: None,
                saml: None,
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: true,
        },
    );

    let config = Arc::new(AppConfig { tenants });

    assert!(config.get_tenant("test-tenant").is_some());
    assert!(config.get_tenant("non-existent").is_none());
}

/// Test inactive tenant
#[test]
fn test_inactive_tenant() {
    let mut tenants = HashMap::new();
    tenants.insert(
        "inactive-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "inactive-tenant".to_string(),
            name: "Inactive Tenant".to_string(),
            description: None,
            identity_provider: IdentityProviderConfig {
                oauth2: Some(OAuth2ServerConfig {
                    issuer: "https://inactive.example.com".to_string(),
                    grant_types: vec!["authorization_code".to_string()],
                    token_endpoint: "/oauth/token".to_string(),
                    authorize_endpoint: "/oauth/authorize".to_string(),
                    jwks_endpoint: "/.well-known/jwks.json".to_string(),
                    access_token_expiration_secs: 3600,
                    refresh_token_expiration_secs: 86400,
                    signing_key: JwkSigningConfig {
                        algorithm: "RS256".to_string(),
                        kid: "inactive-key".to_string(),
                        private_key: "/path/to/private.pem".to_string(),
                        public_key: "/path/to/public.pem".to_string(),
                    },
                }),
                oidc: None,
                saml: None,
            },
            identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
            api_keys: None,
            active: false,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("inactive-tenant").unwrap();
    assert!(!tenant.active);
}
