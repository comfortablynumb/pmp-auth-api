mod env_interpolation;

use crate::models::AppConfig;
use env_interpolation::interpolate_env_vars;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Load configuration from a YAML file with environment variable interpolation
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Arc<AppConfig>, String> {
    let path = path.as_ref();
    info!("📄 Loading configuration from: {}", path.display());

    // Read the file
    info!("📖 Reading configuration file...");
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

    info!("🔄 Interpolating environment variables in configuration...");
    // Interpolate environment variables
    let interpolated_contents = interpolate_env_vars(&contents)
        .map_err(|e| format!("Environment variable interpolation failed: {}", e))?;

    info!("🔍 Parsing YAML configuration...");
    // Parse YAML
    let config: AppConfig = serde_yaml::from_str(&interpolated_contents)
        .map_err(|e| format!("Failed to parse YAML config: {}", e))?;

    info!("✔️  Validating configuration...");
    // Validate the configuration
    config.validate()?;

    info!(
        "Configuration loaded successfully with {} tenant(s)",
        config.tenants.len()
    );

    for (tenant_id, tenant) in &config.tenants {
        let mut providers = Vec::new();

        if tenant.identity_provider.oauth2.is_some() {
            providers.push("OAuth2");
        }

        if tenant.identity_provider.oidc.is_some() {
            providers.push("OIDC");
        }

        if tenant.identity_provider.saml.is_some() {
            providers.push("SAML");
        }

        let backend_type = match &tenant.identity_backend {
            crate::models::IdentityBackend::OAuth2(_) => "OAuth2",
            crate::models::IdentityBackend::Ldap(_) => "LDAP",
            crate::models::IdentityBackend::Database(_) => "Database",
            crate::models::IdentityBackend::Federated(_) => "Federated",
            crate::models::IdentityBackend::Mock(_) => "Mock",
        };

        info!(
            "  Tenant '{}' ({}): Providers: [{}], Backend: {}",
            tenant_id,
            tenant.name,
            providers.join(", "),
            backend_type
        );
    }

    Ok(Arc::new(config))
}

/// Load configuration with fallback options
pub fn load_config_with_fallback() -> Result<Arc<AppConfig>, String> {
    info!("🔍 Searching for configuration file...");

    // Try loading from environment variable first
    if let Ok(config_path) = std::env::var("CONFIG_PATH") {
        info!(
            "🎯 CONFIG_PATH environment variable set to: {}",
            config_path
        );
        match load_config(&config_path) {
            Ok(config) => {
                info!("✅ Configuration loaded from CONFIG_PATH");
                return Ok(config);
            }
            Err(e) => {
                warn!(
                    "⚠️  Failed to load config from CONFIG_PATH ({}): {}",
                    config_path, e
                );
                warn!("📂 Falling back to default locations...");
            }
        }
    } else {
        info!("ℹ️  CONFIG_PATH not set, checking default locations...");
    }

    // Try config folder locations first, then fallback to root
    let paths = vec![
        "config/config.yaml",
        "config/config.yml",
        "./config/config.yaml",
        "./config/config.yml",
        "config.yaml",
        "config.yml",
        "./config.yaml",
        "./config.yml",
    ];

    for path in &paths {
        if Path::new(path).exists() {
            info!("📁 Found config file at: {}", path);
            match load_config(path) {
                Ok(config) => {
                    info!("✅ Successfully loaded configuration from: {}", path);
                    return Ok(config);
                }
                Err(e) => {
                    warn!("⚠️  Failed to load config from '{}': {}", path, e);
                    warn!("📂 Trying next location...");
                }
            }
        } else {
            info!("❌ Config file not found at: {}", path);
        }
    }

    // If no config file found, return error with helpful message
    warn!("❌ No valid configuration file found in any location");
    warn!("🔍 Searched locations: {:?}", paths);
    Err(
        "No configuration file found. Please create a config/config.yaml file or set CONFIG_PATH environment variable. \
        See config/config.example.yaml for an example configuration.".to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::tenant::Tenant;
    use crate::models::{
        IdentityBackend, IdentityProviderConfig, JwkSigningConfig, MockBackendConfig,
        OAuth2ServerConfig,
    };
    use std::collections::HashMap;

    #[test]
    fn test_load_valid_config() {
        let yaml = r#"
tenants:
  test-tenant:
    id: test-tenant
    name: "Test Tenant"
    active: true
    identity_provider:
      oauth2:
        issuer: "https://test.example.com"
        grant_types:
          - "authorization_code"
        token_endpoint: "/oauth/token"
        authorize_endpoint: "/oauth/authorize"
        jwks_endpoint: "/.well-known/jwks.json"
        access_token_expiration_secs: 3600
        refresh_token_expiration_secs: 86400
        signing_key:
          algorithm: "RS256"
          kid: "test-key"
          private_key: "/path/to/private.pem"
          public_key: "/path/to/public.pem"
    identity_backend:
      type: mock
      users: []
"#;

        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tenants.len(), 1);
        assert!(config.tenants.contains_key("test-tenant"));

        let tenant = config.get_tenant("test-tenant").unwrap();
        assert_eq!(tenant.name, "Test Tenant");
        assert!(tenant.identity_provider.oauth2.is_some());
    }

    #[test]
    fn test_config_with_env_interpolation() {
        std::env::set_var("TEST_ISSUER", "https://env-test.example.com");
        std::env::set_var("TEST_PORT", "9000");

        let yaml = r#"
tenants:
  test-tenant:
    id: test-tenant
    name: "Test Tenant"
    active: true
    identity_provider:
      oauth2:
        issuer: "${env:TEST_ISSUER}"
        grant_types:
          - "authorization_code"
        token_endpoint: "/oauth/token"
        authorize_endpoint: "/oauth/authorize"
        jwks_endpoint: "/.well-known/jwks.json"
        access_token_expiration_secs: 3600
        refresh_token_expiration_secs: 86400
        signing_key:
          algorithm: "RS256"
          kid: "test-key"
          private_key: "/path/to/private.pem"
          public_key: "/path/to/public.pem"
    identity_backend:
      type: mock
      users: []
"#;

        let interpolated = env_interpolation::interpolate_env_vars(yaml).unwrap();
        let config: AppConfig = serde_yaml::from_str(&interpolated).unwrap();

        let tenant = config.get_tenant("test-tenant").unwrap();
        assert_eq!(
            tenant.identity_provider.oauth2.as_ref().unwrap().issuer,
            "https://env-test.example.com"
        );

        std::env::remove_var("TEST_ISSUER");
        std::env::remove_var("TEST_PORT");
    }

    #[test]
    fn test_config_with_env_default() {
        std::env::remove_var("MISSING_VAR");

        let yaml = r#"
tenants:
  test-tenant:
    id: test-tenant
    name: "Test Tenant"
    active: true
    identity_provider:
      oauth2:
        issuer: "${env:MISSING_VAR:https://default.example.com}"
        grant_types:
          - "authorization_code"
        token_endpoint: "/oauth/token"
        authorize_endpoint: "/oauth/authorize"
        jwks_endpoint: "/.well-known/jwks.json"
        access_token_expiration_secs: 3600
        refresh_token_expiration_secs: 86400
        signing_key:
          algorithm: "RS256"
          kid: "test-key"
          private_key: "/path/to/private.pem"
          public_key: "/path/to/public.pem"
    identity_backend:
      type: mock
      users: []
"#;

        let interpolated = env_interpolation::interpolate_env_vars(yaml).unwrap();
        let config: AppConfig = serde_yaml::from_str(&interpolated).unwrap();

        let tenant = config.get_tenant("test-tenant").unwrap();
        assert_eq!(
            tenant.identity_provider.oauth2.as_ref().unwrap().issuer,
            "https://default.example.com"
        );
    }

    #[test]
    fn test_config_validation_empty_tenants() {
        let config = AppConfig {
            tenants: HashMap::new(),
            storage: crate::models::StorageConfig::Memory,
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one tenant"));
    }

    #[test]
    fn test_config_validation_no_identity_provider() {
        let mut config = AppConfig {
            tenants: HashMap::new(),
            storage: crate::models::StorageConfig::Memory,
        };

        config.tenants.insert(
            "test".to_string(),
            Tenant {
                id: "test".to_string(),
                name: "Test".to_string(),
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

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("at least one identity provider"));
    }

    #[test]
    fn test_config_get_tenant() {
        let mut tenants = HashMap::new();
        tenants.insert(
            "test".to_string(),
            Tenant {
                id: "test".to_string(),
                name: "Test".to_string(),
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
                        password_grant_enabled: false,
                    }),
                    oidc: None,
                    saml: None,
                },
                identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
                api_keys: None,
                active: true,
            },
        );

        let config = AppConfig {
            tenants,
            storage: crate::models::StorageConfig::Memory,
        };

        let tenant = config.get_tenant("test");
        assert!(tenant.is_some());

        let missing_tenant = config.get_tenant("missing");
        assert!(missing_tenant.is_none());
    }
}
