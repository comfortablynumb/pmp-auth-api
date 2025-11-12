use crate::models::AppConfig;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Load configuration from a YAML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Arc<AppConfig>, String> {
    let path = path.as_ref();
    info!("Loading configuration from: {}", path.display());

    // Read the file
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

    // Parse YAML
    let config: AppConfig = serde_yaml::from_str(&contents)
        .map_err(|e| format!("Failed to parse YAML config: {}", e))?;

    // Validate the configuration
    config.validate()?;

    info!(
        "Configuration loaded successfully with {} tenant(s)",
        config.tenants.len()
    );

    for (tenant_id, tenant) in &config.tenants {
        info!(
            "  Tenant '{}' ({}): {} auth strategy(ies)",
            tenant_id,
            tenant.name,
            tenant.auth_strategies.len()
        );
        for strategy_name in tenant.auth_strategies.keys() {
            info!("    - {}", strategy_name);
        }
    }

    Ok(Arc::new(config))
}

/// Load configuration with fallback options
pub fn load_config_with_fallback() -> Result<Arc<AppConfig>, String> {
    // Try loading from environment variable first
    if let Ok(config_path) = std::env::var("CONFIG_PATH") {
        match load_config(&config_path) {
            Ok(config) => return Ok(config),
            Err(e) => warn!(
                "Failed to load config from CONFIG_PATH ({}): {}",
                config_path, e
            ),
        }
    }

    // Try common config file locations
    let paths = vec!["config.yaml", "config.yml", "./config.yaml", "./config.yml"];

    for path in paths {
        if Path::new(path).exists() {
            match load_config(path) {
                Ok(config) => return Ok(config),
                Err(e) => warn!("Failed to load config from '{}': {}", path, e),
            }
        }
    }

    // If no config file found, return error with helpful message
    Err(
        "No configuration file found. Please create a config.yaml file or set CONFIG_PATH environment variable. \
        See config.example.yaml for an example configuration.".to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthStrategy, LocalAuthConfig, Tenant};
    use std::collections::HashMap;

    #[test]
    fn test_load_valid_config() {
        let yaml = r#"
tenants:
  test-tenant:
    id: test-tenant
    name: "Test Tenant"
    active: true
    auth_strategies:
      local:
        type: local
        allow_registration: true
        min_password_length: 8
        jwt_secret: "test-secret"
        expiration_secs: 3600
"#;

        let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.tenants.len(), 1);
        assert!(config.tenants.contains_key("test-tenant"));

        let tenant = config.get_tenant("test-tenant").unwrap();
        assert_eq!(tenant.name, "Test Tenant");
        assert_eq!(tenant.auth_strategies.len(), 1);
    }

    #[test]
    fn test_config_validation_empty_tenants() {
        let config = AppConfig {
            tenants: HashMap::new(),
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one tenant"));
    }

    #[test]
    fn test_config_validation_empty_strategies() {
        let mut config = AppConfig {
            tenants: HashMap::new(),
        };

        config.tenants.insert(
            "test".to_string(),
            Tenant {
                id: "test".to_string(),
                name: "Test".to_string(),
                description: None,
                auth_strategies: HashMap::new(),
                active: true,
            },
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one auth strategy"));
    }

    #[test]
    fn test_config_get_auth_strategy() {
        let mut strategies = HashMap::new();
        strategies.insert(
            "local".to_string(),
            AuthStrategy::Local(LocalAuthConfig {
                allow_registration: true,
                min_password_length: 8,
                require_email_verification: false,
                jwt_secret: "secret".to_string(),
                expiration_secs: 3600,
            }),
        );

        let mut tenants = HashMap::new();
        tenants.insert(
            "test".to_string(),
            Tenant {
                id: "test".to_string(),
                name: "Test".to_string(),
                description: None,
                auth_strategies: strategies,
                active: true,
            },
        );

        let config = AppConfig { tenants };

        let strategy = config.get_auth_strategy("test", "local");
        assert!(strategy.is_some());

        let missing = config.get_auth_strategy("test", "missing");
        assert!(missing.is_none());

        let missing_tenant = config.get_auth_strategy("missing", "local");
        assert!(missing_tenant.is_none());
    }
}
