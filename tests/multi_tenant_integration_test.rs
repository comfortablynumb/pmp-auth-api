use pmp_auth_api::models::{
    AppConfig, DatabaseStorageConfig, IdentityStorage, JwkSigningConfig, LdapStorageConfig,
    OAuth2ServerConfig, OidcProviderConfig,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Test configuration loading and validation with OAuth2 provider
#[test]
fn test_create_oauth2_tenant_config() {
    let mut identity_providers = HashMap::new();
    identity_providers.insert(
        "default".to_string(),
        pmp_auth_api::models::IdentityProvider::OAuth2 {
            config: OAuth2ServerConfig {
                issuer: "https://test.example.com".to_string(),
                grant_types: vec!["authorization_code".to_string()],
                token_endpoint: "/oauth/token".to_string(),
                authorize_endpoint: "/oauth/authorize".to_string(),
                jwks_endpoint: "/.well-known/jwks.json".to_string(),
                access_token_expiration_secs: 3600,
                refresh_token_expiration_secs: 86400,
                password_grant_enabled: false,
                signing_key: JwkSigningConfig {
                    algorithm: "RS256".to_string(),
                    kid: "test-key".to_string(),
                    private_key: "/path/to/private.pem".to_string(),
                    public_key: "/path/to/public.pem".to_string(),
                },
                request_parameter_supported: false,
                request_uri_parameter_supported: false,
                require_request_uri_registration: false,
                request_object_signing_alg_values_supported: vec![],
            },
            identity_storage_id: "default".to_string(),
        },
    );

    let mut identity_storage = HashMap::new();
    identity_storage.insert(
        "default".to_string(),
        IdentityStorage::Database(DatabaseStorageConfig {
            connection_url: "postgresql://localhost/test".to_string(),
            db_type: "postgres".to_string(),
            users_table: "users".to_string(),
            id_column: "id".to_string(),
            email_column: "email".to_string(),
            attribute_mappings: HashMap::new(),
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "test-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "test-tenant".to_string(),
            name: "Test Tenant".to_string(),
            description: Some("Integration test tenant".to_string()),
            allowed_origins: vec![],
            identity_providers,
            identity_storage,
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

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
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();
                providers.insert(
                    "default".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://tenant1.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "tenant1-key".to_string(),
                                private_key: "/path/to/tenant1-private.pem".to_string(),
                                public_key: "/path/to/tenant1-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
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
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();
                providers.insert(
                    "oauth2".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://tenant2.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "tenant2-key".to_string(),
                                private_key: "/path/to/tenant2-private.pem".to_string(),
                                public_key: "/path/to/tenant2-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers.insert(
                    "oidc".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://tenant2.example.com".to_string(),
                            userinfo_endpoint: "/oauth/userinfo".to_string(),
                            claims_supported: vec!["sub".to_string(), "email".to_string()],
                            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
                            id_token_expiration_secs: 3600,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 2);

    let tenant1 = config.get_tenant("tenant1").unwrap();
    assert!(tenant1.get_oauth2_provider().is_some());
    assert!(tenant1.get_oidc_provider().is_none());

    let tenant2 = config.get_tenant("tenant2").unwrap();
    assert!(tenant2.get_oauth2_provider().is_some());
    assert!(tenant2.get_oidc_provider().is_some());
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
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();
                providers.insert(
                    "oauth2".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://full.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "full-key".to_string(),
                                private_key: "/path/to/full-private.pem".to_string(),
                                public_key: "/path/to/full-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers.insert(
                    "oidc".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://full.example.com".to_string(),
                            userinfo_endpoint: "/oauth/userinfo".to_string(),
                            claims_supported: vec!["sub".to_string(), "email".to_string()],
                            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
                            id_token_expiration_secs: 3600,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers.insert(
                    "saml".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://full.example.com/saml".to_string(),
                            sso_url: "/saml/sso".to_string(),
                            slo_url: Some("/saml/slo".to_string()),
                            certificate: "dummy-cert".to_string(),
                            private_key: "/path/to/saml-key.pem".to_string(),
                            metadata_endpoint: "/saml/metadata".to_string(),
                            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                                .to_string(),
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 1);

    let tenant = config.get_tenant("full-tenant").unwrap();
    assert!(tenant.get_oauth2_provider().is_some());
    assert!(tenant.get_oidc_provider().is_some());
    assert!(tenant.get_saml_provider().is_some());
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
            allowed_origins: vec![],
            identity_providers: HashMap::new(), // Empty providers map for validation test
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("at least one identity provider"));

    // Test 2: Empty tenants
    let config = AppConfig {
        tenants: HashMap::new(),
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
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
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();
                providers.insert(
                    "default".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://test.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "test-key".to_string(),
                                private_key: "/path/to/private.pem".to_string(),
                                public_key: "/path/to/public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = Arc::new(AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    });

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
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();
                providers.insert(
                    "default".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://inactive.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "inactive-key".to_string(),
                                private_key: "/path/to/private.pem".to_string(),
                                public_key: "/path/to/public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );
                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/test".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: false,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("inactive-tenant").unwrap();
    assert!(!tenant.active);
}

// ============================================================================
// MULTI-PROVIDER TESTS
// Tests for multiple identity providers of the same type in a single tenant
// ============================================================================

/// Test tenant with multiple OAuth2 providers
#[test]
fn test_tenant_with_multiple_oauth2_providers() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "multi-oauth2".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "multi-oauth2".to_string(),
            name: "Multi OAuth2 Tenant".to_string(),
            description: Some("Tenant with multiple OAuth2 providers".to_string()),
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // OAuth2 provider for internal users
                providers.insert(
                    "oauth2-internal".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://internal.example.com".to_string(),
                            grant_types: vec![
                                "authorization_code".to_string(),
                                "password".to_string(),
                            ],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: true,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "internal-key-2024".to_string(),
                                private_key: "/path/to/internal-private.pem".to_string(),
                                public_key: "/path/to/internal-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "internal-db".to_string(),
                    },
                );

                // OAuth2 provider for external users
                providers.insert(
                    "oauth2-external".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://external.example.com".to_string(),
                            grant_types: vec![
                                "authorization_code".to_string(),
                                "client_credentials".to_string(),
                            ],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 7200,
                            refresh_token_expiration_secs: 604800,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "ES256".to_string(),
                                kid: "external-key-2024".to_string(),
                                private_key: "/path/to/external-private.pem".to_string(),
                                public_key: "/path/to/external-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "external-ldap".to_string(),
                    },
                );

                // OAuth2 provider for partners with different settings
                providers.insert(
                    "oauth2-partners".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://partners.example.com".to_string(),
                            grant_types: vec![
                                "authorization_code".to_string(),
                                "refresh_token".to_string(),
                            ],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 1800,
                            refresh_token_expiration_secs: 2592000,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "partners-key-2024".to_string(),
                                private_key: "/path/to/partners-private.pem".to_string(),
                                public_key: "/path/to/partners-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "partners-db".to_string(),
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "internal-db".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/internal_users".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "employees".to_string(),
                        id_column: "employee_id".to_string(),
                        email_column: "work_email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "external-ldap".to_string(),
                    IdentityStorage::Ldap(LdapStorageConfig {
                        url: "ldaps://ldap.example.com:636".to_string(),
                        bind_dn: Some("cn=service,dc=example,dc=com".to_string()),
                        bind_password: Some("password".to_string()),
                        base_dn: "ou=users,dc=example,dc=com".to_string(),
                        user_filter: Some("(uid={username})".to_string()),
                        attributes: Some(vec!["uid".to_string(), "mail".to_string()]),
                        id_attribute: None,
                        email_attribute: None,
                        name_attribute: None,
                        group_base_dn: None,
                        admin_group: None,
                        use_starttls: None,
                    }),
                );
                storage_map.insert(
                    "partners-db".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/partners".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "partner_accounts".to_string(),
                        id_column: "account_id".to_string(),
                        email_column: "contact_email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("multi-oauth2").unwrap();

    // Verify all three OAuth2 providers are accessible
    assert_eq!(tenant.identity_providers.len(), 3);
    assert!(tenant
        .identity_providers
        .contains_key("oauth2-internal"));
    assert!(tenant
        .identity_providers
        .contains_key("oauth2-external"));
    assert!(tenant
        .identity_providers
        .contains_key("oauth2-partners"));

    // Verify each provider has different settings
    if let pmp_auth_api::models::IdentityProvider::OAuth2 { config: cfg, .. } =
        &tenant.identity_providers["oauth2-internal"]
    {
        assert_eq!(cfg.issuer, "https://internal.example.com");
        assert!(cfg.password_grant_enabled);
        assert_eq!(cfg.access_token_expiration_secs, 3600);
    }

    if let pmp_auth_api::models::IdentityProvider::OAuth2 { config: cfg, .. } =
        &tenant.identity_providers["oauth2-external"]
    {
        assert_eq!(cfg.issuer, "https://external.example.com");
        assert!(!cfg.password_grant_enabled);
        assert_eq!(cfg.access_token_expiration_secs, 7200);
        assert_eq!(cfg.signing_key.algorithm, "ES256");
    }

    // Verify storage isolation
    assert_eq!(tenant.identity_storage.len(), 3);
    assert!(tenant.identity_storage.contains_key("internal-db"));
    assert!(tenant.identity_storage.contains_key("external-ldap"));
    assert!(tenant.identity_storage.contains_key("partners-db"));
}

/// Test tenant with multiple OIDC providers
#[test]
fn test_tenant_with_multiple_oidc_providers() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "multi-oidc".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "multi-oidc".to_string(),
            name: "Multi OIDC Tenant".to_string(),
            description: Some("Tenant with multiple OIDC providers".to_string()),
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // Base OAuth2 provider (required for OIDC)
                providers.insert(
                    "oauth2".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://multi-oidc.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "base-key".to_string(),
                                private_key: "/path/to/base-private.pem".to_string(),
                                public_key: "/path/to/base-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "default".to_string(),
                    },
                );

                // OIDC provider for web applications
                providers.insert(
                    "oidc-web".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://web.multi-oidc.example.com".to_string(),
                            userinfo_endpoint: "/oidc/web/userinfo".to_string(),
                            claims_supported: vec![
                                "sub".to_string(),
                                "name".to_string(),
                                "email".to_string(),
                                "email_verified".to_string(),
                                "picture".to_string(),
                            ],
                            scopes_supported: vec![
                                "openid".to_string(),
                                "profile".to_string(),
                                "email".to_string(),
                            ],
                            id_token_expiration_secs: 3600,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "web-users".to_string(),
                    },
                );

                // OIDC provider for mobile applications
                providers.insert(
                    "oidc-mobile".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://mobile.multi-oidc.example.com".to_string(),
                            userinfo_endpoint: "/oidc/mobile/userinfo".to_string(),
                            claims_supported: vec![
                                "sub".to_string(),
                                "email".to_string(),
                                "phone_number".to_string(),
                            ],
                            scopes_supported: vec![
                                "openid".to_string(),
                                "email".to_string(),
                                "phone".to_string(),
                            ],
                            id_token_expiration_secs: 7200,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "mobile-users".to_string(),
                    },
                );

                // OIDC provider for enterprise SSO
                providers.insert(
                    "oidc-enterprise".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://enterprise.multi-oidc.example.com".to_string(),
                            userinfo_endpoint: "/oidc/enterprise/userinfo".to_string(),
                            claims_supported: vec![
                                "sub".to_string(),
                                "email".to_string(),
                                "name".to_string(),
                                "preferred_username".to_string(),
                            ],
                            scopes_supported: vec![
                                "openid".to_string(),
                                "profile".to_string(),
                                "email".to_string(),
                                "groups".to_string(),
                            ],
                            id_token_expiration_secs: 1800,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "enterprise-ldap".to_string(),
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "default".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/multi_oidc".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "web-users".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/web_users".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "web_accounts".to_string(),
                        id_column: "user_id".to_string(),
                        email_column: "email_address".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "mobile-users".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/mobile_users".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "mobile_accounts".to_string(),
                        id_column: "account_id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "enterprise-ldap".to_string(),
                    IdentityStorage::Ldap(LdapStorageConfig {
                        url: "ldaps://enterprise.example.com:636".to_string(),
                        bind_dn: Some("cn=svc-oidc,dc=enterprise,dc=com".to_string()),
                        bind_password: Some("password".to_string()),
                        base_dn: "ou=employees,dc=enterprise,dc=com".to_string(),
                        user_filter: Some("(sAMAccountName={username})".to_string()),
                        attributes: Some(vec!["sAMAccountName".to_string(), "mail".to_string()]),
                        id_attribute: None,
                        email_attribute: None,
                        name_attribute: None,
                        group_base_dn: None,
                        admin_group: None,
                        use_starttls: None,
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("multi-oidc").unwrap();

    // Verify all OIDC providers plus base OAuth2
    assert_eq!(tenant.identity_providers.len(), 4);
    assert!(tenant.identity_providers.contains_key("oidc-web"));
    assert!(tenant.identity_providers.contains_key("oidc-mobile"));
    assert!(tenant
        .identity_providers
        .contains_key("oidc-enterprise"));

    // Verify each OIDC provider has different settings
    if let pmp_auth_api::models::IdentityProvider::Oidc { config: cfg, .. } =
        &tenant.identity_providers["oidc-web"]
    {
        assert_eq!(cfg.issuer, "https://web.multi-oidc.example.com");
        assert_eq!(cfg.id_token_expiration_secs, 3600);
        assert!(cfg.scopes_supported.contains(&"profile".to_string()));
    }

    if let pmp_auth_api::models::IdentityProvider::Oidc { config: cfg, .. } =
        &tenant.identity_providers["oidc-mobile"]
    {
        assert_eq!(cfg.issuer, "https://mobile.multi-oidc.example.com");
        assert_eq!(cfg.id_token_expiration_secs, 7200);
        assert!(cfg.scopes_supported.contains(&"phone".to_string()));
    }

    if let pmp_auth_api::models::IdentityProvider::Oidc { config: cfg, .. } =
        &tenant.identity_providers["oidc-enterprise"]
    {
        assert_eq!(cfg.issuer, "https://enterprise.multi-oidc.example.com");
        assert_eq!(cfg.id_token_expiration_secs, 1800);
        assert!(cfg.scopes_supported.contains(&"groups".to_string()));
    }

    // Verify storage isolation
    assert_eq!(tenant.identity_storage.len(), 4);
}

/// Test tenant with multiple SAML providers
#[test]
fn test_tenant_with_multiple_saml_providers() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "multi-saml".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "multi-saml".to_string(),
            name: "Multi SAML Tenant".to_string(),
            description: Some("Tenant with multiple SAML IdPs".to_string()),
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // SAML IdP for customer portal
                providers.insert(
                    "saml-customers".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://customers.multi-saml.example.com/saml"
                                .to_string(),
                            sso_url: "/saml/customers/sso".to_string(),
                            slo_url: Some("/saml/customers/slo".to_string()),
                            certificate: "customer-cert".to_string(),
                            private_key: "/path/to/saml-customers-key.pem".to_string(),
                            metadata_endpoint: "/saml/customers/metadata".to_string(),
                            name_id_format:
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                                    .to_string(),
                        },
                        identity_storage_id: "customer-db".to_string(),
                    },
                );

                // SAML IdP for partner federation
                providers.insert(
                    "saml-partners".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://partners.multi-saml.example.com/saml".to_string(),
                            sso_url: "/saml/partners/sso".to_string(),
                            slo_url: Some("/saml/partners/slo".to_string()),
                            certificate: "partner-cert".to_string(),
                            private_key: "/path/to/saml-partners-key.pem".to_string(),
                            metadata_endpoint: "/saml/partners/metadata".to_string(),
                            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                                .to_string(),
                        },
                        identity_storage_id: "partner-ldap".to_string(),
                    },
                );

                // SAML IdP for legacy applications
                providers.insert(
                    "saml-legacy".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://legacy.multi-saml.example.com/saml".to_string(),
                            sso_url: "/saml/legacy/sso".to_string(),
                            slo_url: None, // No single logout for legacy apps
                            certificate: "legacy-cert".to_string(),
                            private_key: "/path/to/saml-legacy-key.pem".to_string(),
                            metadata_endpoint: "/saml/legacy/metadata".to_string(),
                            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                                .to_string(),
                        },
                        identity_storage_id: "legacy-ldap".to_string(),
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "customer-db".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/customers".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "customer_accounts".to_string(),
                        id_column: "customer_id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "partner-ldap".to_string(),
                    IdentityStorage::Ldap(LdapStorageConfig {
                        url: "ldaps://partners.example.com:636".to_string(),
                        bind_dn: Some("cn=saml-service,dc=partners,dc=com".to_string()),
                        bind_password: Some("password".to_string()),
                        base_dn: "ou=partners,dc=partners,dc=com".to_string(),
                        user_filter: Some("(uid={username})".to_string()),
                        attributes: Some(vec!["uid".to_string(), "mail".to_string()]),
                        id_attribute: None,
                        email_attribute: None,
                        name_attribute: None,
                        group_base_dn: None,
                        admin_group: None,
                        use_starttls: None,
                    }),
                );
                storage_map.insert(
                    "legacy-ldap".to_string(),
                    IdentityStorage::Ldap(LdapStorageConfig {
                        url: "ldap://legacy.example.com:389".to_string(),
                        bind_dn: Some("cn=legacy-service,dc=legacy,dc=com".to_string()),
                        bind_password: Some("password".to_string()),
                        base_dn: "ou=users,dc=legacy,dc=com".to_string(),
                        user_filter: Some("(cn={username})".to_string()),
                        attributes: Some(vec!["cn".to_string(), "mail".to_string()]),
                        id_attribute: None,
                        email_attribute: None,
                        name_attribute: None,
                        group_base_dn: None,
                        admin_group: None,
                        use_starttls: None,
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("multi-saml").unwrap();

    // Verify all SAML providers
    assert_eq!(tenant.identity_providers.len(), 3);
    assert!(tenant.identity_providers.contains_key("saml-customers"));
    assert!(tenant.identity_providers.contains_key("saml-partners"));
    assert!(tenant.identity_providers.contains_key("saml-legacy"));

    // Verify each SAML provider has different settings
    if let pmp_auth_api::models::IdentityProvider::Saml { config: cfg, .. } =
        &tenant.identity_providers["saml-customers"]
    {
        assert_eq!(
            cfg.entity_id,
            "https://customers.multi-saml.example.com/saml"
        );
        assert_eq!(
            cfg.name_id_format,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        assert!(cfg.slo_url.is_some());
    }

    if let pmp_auth_api::models::IdentityProvider::Saml { config: cfg, .. } =
        &tenant.identity_providers["saml-partners"]
    {
        assert_eq!(cfg.entity_id, "https://partners.multi-saml.example.com/saml");
        assert_eq!(
            cfg.name_id_format,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        );
    }

    if let pmp_auth_api::models::IdentityProvider::Saml { config: cfg, .. } =
        &tenant.identity_providers["saml-legacy"]
    {
        assert_eq!(cfg.entity_id, "https://legacy.multi-saml.example.com/saml");
        assert_eq!(
            cfg.name_id_format,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
        );
        assert!(cfg.slo_url.is_none()); // Legacy doesn't support SLO
    }

    // Verify storage isolation
    assert_eq!(tenant.identity_storage.len(), 3);
}

/// Test tenant with mixed provider types and shared storage
#[test]
fn test_tenant_with_mixed_providers_shared_storage() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "mixed-shared".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "mixed-shared".to_string(),
            name: "Mixed Providers with Shared Storage".to_string(),
            description: Some("Multiple provider types sharing storage backends".to_string()),
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // OAuth2 for API access
                providers.insert(
                    "oauth2-api".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://api.mixed.example.com".to_string(),
                            grant_types: vec![
                                "client_credentials".to_string(),
                                "authorization_code".to_string(),
                            ],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "api-key".to_string(),
                                private_key: "/path/to/api-private.pem".to_string(),
                                public_key: "/path/to/api-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "shared-db".to_string(), // Shared storage
                    },
                );

                // OIDC for web apps
                providers.insert(
                    "oidc-web".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://web.mixed.example.com".to_string(),
                            userinfo_endpoint: "/oidc/userinfo".to_string(),
                            claims_supported: vec![
                                "sub".to_string(),
                                "email".to_string(),
                                "name".to_string(),
                            ],
                            scopes_supported: vec![
                                "openid".to_string(),
                                "profile".to_string(),
                                "email".to_string(),
                            ],
                            id_token_expiration_secs: 3600,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "shared-db".to_string(), // Shared storage
                    },
                );

                // SAML for enterprise SSO
                providers.insert(
                    "saml-sso".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://sso.mixed.example.com/saml".to_string(),
                            sso_url: "/saml/sso".to_string(),
                            slo_url: Some("/saml/slo".to_string()),
                            certificate: "sso-cert".to_string(),
                            private_key: "/path/to/saml-key.pem".to_string(),
                            metadata_endpoint: "/saml/metadata".to_string(),
                            name_id_format:
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                                    .to_string(),
                        },
                        identity_storage_id: "shared-ldap".to_string(), // Different shared storage
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                // Shared database for OAuth2 and OIDC
                storage_map.insert(
                    "shared-db".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/shared_users".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "unified_users".to_string(),
                        id_column: "user_id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                // Shared LDAP for SAML
                storage_map.insert(
                    "shared-ldap".to_string(),
                    IdentityStorage::Ldap(LdapStorageConfig {
                        url: "ldaps://ldap.mixed.example.com:636".to_string(),
                        bind_dn: Some("cn=service,dc=mixed,dc=com".to_string()),
                        bind_password: Some("password".to_string()),
                        base_dn: "ou=users,dc=mixed,dc=com".to_string(),
                        user_filter: Some("(uid={username})".to_string()),
                        attributes: Some(vec!["uid".to_string(), "mail".to_string()]),
                        id_attribute: None,
                        email_attribute: None,
                        name_attribute: None,
                        group_base_dn: None,
                        admin_group: None,
                        use_starttls: None,
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("mixed-shared").unwrap();

    // Verify all provider types are present
    assert_eq!(tenant.identity_providers.len(), 3);
    assert!(tenant.identity_providers.contains_key("oauth2-api"));
    assert!(tenant.identity_providers.contains_key("oidc-web"));
    assert!(tenant.identity_providers.contains_key("saml-sso"));

    // Verify storage is shared appropriately
    assert_eq!(tenant.identity_storage.len(), 2);
    assert!(tenant.identity_storage.contains_key("shared-db"));
    assert!(tenant.identity_storage.contains_key("shared-ldap"));

    // Verify OAuth2 and OIDC share the same storage
    if let pmp_auth_api::models::IdentityProvider::OAuth2 {
        identity_storage_id: oauth_storage,
        ..
    } = &tenant.identity_providers["oauth2-api"]
    {
        if let pmp_auth_api::models::IdentityProvider::Oidc {
            identity_storage_id: oidc_storage,
            ..
        } = &tenant.identity_providers["oidc-web"]
        {
            assert_eq!(oauth_storage, oidc_storage);
            assert_eq!(oauth_storage, "shared-db");
        }
    }

    // Verify SAML uses different storage
    if let pmp_auth_api::models::IdentityProvider::Saml {
        identity_storage_id: saml_storage,
        ..
    } = &tenant.identity_providers["saml-sso"]
    {
        assert_eq!(saml_storage, "shared-ldap");
    }
}

/// Test provider routing and storage resolution
#[test]
fn test_provider_storage_resolution() {
    let mut tenants = HashMap::new();

    tenants.insert(
        "routing-test".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "routing-test".to_string(),
            name: "Provider Routing Test".to_string(),
            description: None,
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // Provider using tenant-specific storage
                providers.insert(
                    "provider-a".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://a.routing.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "a-key".to_string(),
                                private_key: "/path/to/a-private.pem".to_string(),
                                public_key: "/path/to/a-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "storage-a".to_string(),
                    },
                );

                // Provider using different tenant-specific storage
                providers.insert(
                    "provider-b".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://b.routing.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "b-key".to_string(),
                                private_key: "/path/to/b-private.pem".to_string(),
                                public_key: "/path/to/b-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "storage-b".to_string(),
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                storage_map.insert(
                    "storage-a".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/storage_a".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users_a".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map.insert(
                    "storage-b".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/storage_b".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "users_b".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: HashMap::new(),
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("routing-test").unwrap();

    // Test storage resolution for each provider
    let storage_a = config.get_identity_storage("routing-test", "storage-a");
    assert!(storage_a.is_some());

    let storage_b = config.get_identity_storage("routing-test", "storage-b");
    assert!(storage_b.is_some());

    // Verify storages are different
    if let (
        Some(IdentityStorage::Database(db_a)),
        Some(IdentityStorage::Database(db_b)),
    ) = (storage_a, storage_b)
    {
        assert_ne!(db_a.connection_url, db_b.connection_url);
        assert_ne!(db_a.users_table, db_b.users_table);
    }

    // Verify each provider correctly references its storage
    assert_eq!(tenant.identity_providers.len(), 2);
}

/// Test global storage inheritance with multi-provider tenant
#[test]
fn test_global_storage_with_multi_providers() {
    // Global storage shared across tenants
    let mut global_storage = HashMap::new();
    global_storage.insert(
        "global-db".to_string(),
        IdentityStorage::Database(DatabaseStorageConfig {
            connection_url: "postgresql://localhost/global_users".to_string(),
            db_type: "postgres".to_string(),
            users_table: "global_users".to_string(),
            id_column: "id".to_string(),
            email_column: "email".to_string(),
            attribute_mappings: HashMap::new(),
        }),
    );
    global_storage.insert(
        "global-ldap".to_string(),
        IdentityStorage::Ldap(LdapStorageConfig {
            url: "ldaps://global-ldap.example.com:636".to_string(),
            bind_dn: Some("cn=global-service,dc=global,dc=com".to_string()),
            bind_password: Some("password".to_string()),
            base_dn: "ou=users,dc=global,dc=com".to_string(),
            user_filter: Some("(uid={username})".to_string()),
            attributes: Some(vec!["uid".to_string(), "mail".to_string()]),
            id_attribute: None,
            email_attribute: None,
            name_attribute: None,
            group_base_dn: None,
            admin_group: None,
            use_starttls: None,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "global-test".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "global-test".to_string(),
            name: "Global Storage Test".to_string(),
            description: None,
            allowed_origins: vec![],
            identity_providers: {
                let mut providers = HashMap::new();

                // OAuth2 using global database
                providers.insert(
                    "oauth2-global-db".to_string(),
                    pmp_auth_api::models::IdentityProvider::OAuth2 {
                        config: OAuth2ServerConfig {
                            issuer: "https://oauth-global.example.com".to_string(),
                            grant_types: vec!["authorization_code".to_string()],
                            token_endpoint: "/oauth/token".to_string(),
                            authorize_endpoint: "/oauth/authorize".to_string(),
                            jwks_endpoint: "/.well-known/jwks.json".to_string(),
                            access_token_expiration_secs: 3600,
                            refresh_token_expiration_secs: 86400,
                            password_grant_enabled: false,
                            request_parameter_supported: false,
                            request_uri_parameter_supported: false,
                            require_request_uri_registration: false,
                            request_object_signing_alg_values_supported: vec![],
                            signing_key: JwkSigningConfig {
                                algorithm: "RS256".to_string(),
                                kid: "oauth-key".to_string(),
                                private_key: "/path/to/oauth-private.pem".to_string(),
                                public_key: "/path/to/oauth-public.pem".to_string(),
                            },
                        },
                        identity_storage_id: "global-db".to_string(), // Reference global storage
                    },
                );

                // SAML using global LDAP
                providers.insert(
                    "saml-global-ldap".to_string(),
                    pmp_auth_api::models::IdentityProvider::Saml {
                        config: pmp_auth_api::models::SamlIdpConfig {
                            entity_id: "https://saml-global.example.com/saml".to_string(),
                            sso_url: "/saml/sso".to_string(),
                            slo_url: Some("/saml/slo".to_string()),
                            certificate: "saml-cert".to_string(),
                            private_key: "/path/to/saml-key.pem".to_string(),
                            metadata_endpoint: "/saml/metadata".to_string(),
                            name_id_format:
                                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                                    .to_string(),
                        },
                        identity_storage_id: "global-ldap".to_string(), // Reference global storage
                    },
                );

                // OIDC using tenant-specific storage
                providers.insert(
                    "oidc-local".to_string(),
                    pmp_auth_api::models::IdentityProvider::Oidc {
                        config: OidcProviderConfig {
                            issuer: "https://oidc-local.example.com".to_string(),
                            userinfo_endpoint: "/oidc/userinfo".to_string(),
                            claims_supported: vec!["sub".to_string(), "email".to_string()],
                            scopes_supported: vec!["openid".to_string(), "email".to_string()],
                            id_token_expiration_secs: 3600,
                            encryption_key: None,
                            id_token_encryption_alg_values_supported: vec![],
                            id_token_encryption_enc_values_supported: vec![],
                        },
                        identity_storage_id: "local-db".to_string(), // Reference local storage
                    },
                );

                providers
            },
            identity_storage: {
                let mut storage_map = HashMap::new();
                // Tenant-specific storage
                storage_map.insert(
                    "local-db".to_string(),
                    IdentityStorage::Database(DatabaseStorageConfig {
                        connection_url: "postgresql://localhost/tenant_local".to_string(),
                        db_type: "postgres".to_string(),
                        users_table: "local_users".to_string(),
                        id_column: "id".to_string(),
                        email_column: "email".to_string(),
                        attribute_mappings: HashMap::new(),
                    }),
                );
                storage_map
            },
            federation_providers: HashMap::new(),
            api_keys: None,
            active: true,
        },
    );

    let config = AppConfig {
        tenants,
        identity_storage: global_storage,
        storage: pmp_auth_api::models::StorageConfig::Memory,
    };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("global-test").unwrap();

    // Verify providers can access both global and local storage
    let global_db_storage = config.get_identity_storage("global-test", "global-db");
    assert!(global_db_storage.is_some());

    let global_ldap_storage = config.get_identity_storage("global-test", "global-ldap");
    assert!(global_ldap_storage.is_some());

    let local_storage = config.get_identity_storage("global-test", "local-db");
    assert!(local_storage.is_some());

    // Verify tenant has 3 providers using mix of global and local storage
    assert_eq!(tenant.identity_providers.len(), 3);
}
