// OAuth2 Federation Providers
// This module contains implementations for different OAuth2/OIDC providers

mod google;
mod github;

pub use google::GoogleProvider;
pub use github::GitHubProvider;

use crate::auth::federation::{FederationProvider, types::FederationProviderConfig};
use crate::auth::federation::FederationError;
use std::sync::Arc;

/// Create a provider instance based on configuration
pub fn create_provider(
    config: &FederationProviderConfig,
) -> Result<Arc<dyn FederationProvider>, FederationError> {
    match config.provider_type.as_str() {
        "google" => Ok(Arc::new(GoogleProvider::new(config.clone())?)),
        "github" => Ok(Arc::new(GitHubProvider::new(config.clone())?)),
        // Add more providers here:
        // "azure" => Ok(Arc::new(AzureProvider::new(config.clone())?)),
        // "okta" => Ok(Arc::new(OktaProvider::new(config.clone())?)),
        // "auth0" => Ok(Arc::new(Auth0Provider::new(config.clone())?)),
        _ => Err(FederationError::ConfigError(format!(
            "Unknown provider type: {}. Supported types: google, github",
            config.provider_type
        ))),
    }
}

/// Helper function to build authorization URL with query parameters
pub(crate) fn build_auth_url(
    base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    extra_params: &[(&str, &str)],
) -> String {
    let scope_string = scopes.join(" ");
    let mut params = vec![
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &scope_string),
        ("state", state),
        ("response_type", "code"),
    ];

    params.extend_from_slice(extra_params);

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("{}?{}", base_url, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_url() {
        let url = build_auth_url(
            "https://provider.com/oauth/authorize",
            "client123",
            "https://myapp.com/callback",
            &["openid".to_string(), "profile".to_string()],
            "state456",
            &[("prompt", "consent")],
        );

        assert!(url.contains("client_id=client123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback"));
        assert!(url.contains("scope=openid%20profile"));
        assert!(url.contains("state=state456"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn test_create_provider_google() {
        let config = FederationProviderConfig {
            provider_type: "google".to_string(),
            provider_id: "google".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            scopes: None,
            extra: serde_json::json!({}),
        };

        let provider = create_provider(&config);
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().provider_id(), "google");
    }

    #[test]
    fn test_create_provider_github() {
        let config = FederationProviderConfig {
            provider_type: "github".to_string(),
            provider_id: "github".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            scopes: None,
            extra: serde_json::json!({}),
        };

        let provider = create_provider(&config);
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().provider_id(), "github");
    }

    #[test]
    fn test_create_provider_unknown() {
        let config = FederationProviderConfig {
            provider_type: "unknown".to_string(),
            provider_id: "unknown".to_string(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            scopes: None,
            extra: serde_json::json!({}),
        };

        let result = create_provider(&config);
        assert!(result.is_err());
    }
}
