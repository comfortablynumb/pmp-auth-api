use pmp_auth_api::models::{AppConfig, AuthStrategy, LocalAuthConfig, SecretJwtConfig};
use std::collections::HashMap;
use std::sync::Arc;

/// Test configuration loading and validation
#[test]
fn test_create_multi_tenant_config() {
    let mut strategies = HashMap::new();
    strategies.insert(
        "local".to_string(),
        AuthStrategy::Local(LocalAuthConfig {
            allow_registration: true,
            min_password_length: 8,
            require_email_verification: false,
            jwt_secret: "test-secret".to_string(),
            expiration_secs: 3600,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "test-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "test-tenant".to_string(),
            name: "Test Tenant".to_string(),
            description: Some("Integration test tenant".to_string()),
            auth_strategies: strategies,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 1);
    assert!(config.get_tenant("test-tenant").is_some());
}

/// Test multiple tenants with different strategies
#[test]
fn test_multiple_tenants_different_strategies() {
    let mut tenant1_strategies = HashMap::new();
    tenant1_strategies.insert(
        "local".to_string(),
        AuthStrategy::Local(LocalAuthConfig {
            allow_registration: true,
            min_password_length: 8,
            require_email_verification: false,
            jwt_secret: "tenant1-secret".to_string(),
            expiration_secs: 3600,
        }),
    );

    let mut tenant2_strategies = HashMap::new();
    tenant2_strategies.insert(
        "jwt".to_string(),
        AuthStrategy::SecretJwt(SecretJwtConfig {
            secret: "tenant2-secret".to_string(),
            issuer: Some("tenant2".to_string()),
            audience: None,
            expiration_secs: 7200,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "tenant1".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "tenant1".to_string(),
            name: "Tenant 1".to_string(),
            description: None,
            auth_strategies: tenant1_strategies,
            active: true,
        },
    );
    tenants.insert(
        "tenant2".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "tenant2".to_string(),
            name: "Tenant 2".to_string(),
            description: None,
            auth_strategies: tenant2_strategies,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());
    assert_eq!(config.tenants.len(), 2);

    // Verify tenant1 has local strategy
    assert!(matches!(
        config.get_auth_strategy("tenant1", "local"),
        Some(AuthStrategy::Local(_))
    ));

    // Verify tenant2 has JWT strategy
    assert!(matches!(
        config.get_auth_strategy("tenant2", "jwt"),
        Some(AuthStrategy::SecretJwt(_))
    ));

    // Verify cross-tenant strategy isolation
    assert!(config.get_auth_strategy("tenant1", "jwt").is_none());
    assert!(config.get_auth_strategy("tenant2", "local").is_none());
}

/// Test tenant configuration with multiple strategies
#[test]
fn test_tenant_with_multiple_strategies() {
    let mut strategies = HashMap::new();
    strategies.insert(
        "local".to_string(),
        AuthStrategy::Local(LocalAuthConfig {
            allow_registration: true,
            min_password_length: 8,
            require_email_verification: false,
            jwt_secret: "secret1".to_string(),
            expiration_secs: 3600,
        }),
    );
    strategies.insert(
        "jwt".to_string(),
        AuthStrategy::SecretJwt(SecretJwtConfig {
            secret: "secret2".to_string(),
            issuer: Some("test".to_string()),
            audience: Some(vec!["api".to_string()]),
            expiration_secs: 7200,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "multi-strategy-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "multi-strategy-tenant".to_string(),
            name: "Multi Strategy Tenant".to_string(),
            description: None,
            auth_strategies: strategies,
            active: true,
        },
    );

    let config = AppConfig { tenants };

    assert!(config.validate().is_ok());

    let tenant = config.get_tenant("multi-strategy-tenant").unwrap();
    assert_eq!(tenant.auth_strategies.len(), 2);
    assert!(tenant.auth_strategies.contains_key("local"));
    assert!(tenant.auth_strategies.contains_key("jwt"));
}

/// Test configuration validation errors
#[test]
fn test_config_validation_errors() {
    // Test empty tenants
    let config = AppConfig {
        tenants: HashMap::new(),
    };
    assert!(config.validate().is_err());

    // Test tenant with no strategies
    let mut tenants = HashMap::new();
    tenants.insert(
        "empty-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "empty-tenant".to_string(),
            name: "Empty Tenant".to_string(),
            description: None,
            auth_strategies: HashMap::new(),
            active: true,
        },
    );
    let config = AppConfig { tenants };
    assert!(config.validate().is_err());
}

/// Test Arc-wrapped config (as used in the app)
#[test]
fn test_arc_wrapped_config() {
    let mut strategies = HashMap::new();
    strategies.insert(
        "local".to_string(),
        AuthStrategy::Local(LocalAuthConfig {
            allow_registration: true,
            min_password_length: 8,
            require_email_verification: false,
            jwt_secret: "test-secret".to_string(),
            expiration_secs: 3600,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "test-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "test-tenant".to_string(),
            name: "Test Tenant".to_string(),
            description: None,
            auth_strategies: strategies,
            active: true,
        },
    );

    let config = Arc::new(AppConfig { tenants });

    // Test that Arc-wrapped config works as expected
    assert!(config.get_tenant("test-tenant").is_some());
    assert!(config.get_auth_strategy("test-tenant", "local").is_some());

    // Test that config can be cloned (Arc is cheaply clonable)
    let config_clone = Arc::clone(&config);
    assert!(config_clone.get_tenant("test-tenant").is_some());
}

/// Test inactive tenant flag
#[test]
fn test_inactive_tenant() {
    let mut strategies = HashMap::new();
    strategies.insert(
        "local".to_string(),
        AuthStrategy::Local(LocalAuthConfig {
            allow_registration: true,
            min_password_length: 8,
            require_email_verification: false,
            jwt_secret: "test-secret".to_string(),
            expiration_secs: 3600,
        }),
    );

    let mut tenants = HashMap::new();
    tenants.insert(
        "inactive-tenant".to_string(),
        pmp_auth_api::models::tenant::Tenant {
            id: "inactive-tenant".to_string(),
            name: "Inactive Tenant".to_string(),
            description: None,
            auth_strategies: strategies,
            active: false, // Inactive tenant
        },
    );

    let config = AppConfig { tenants };

    // Config should still validate
    assert!(config.validate().is_ok());

    // Tenant should still be accessible
    let tenant = config.get_tenant("inactive-tenant").unwrap();
    assert!(!tenant.active);
}
