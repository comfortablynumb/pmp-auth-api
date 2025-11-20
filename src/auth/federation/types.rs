// Common types for OAuth2 Federation

use serde::{Deserialize, Serialize};
use std::fmt;

/// Tokens received from external OAuth2 provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderTokens {
    /// Access token from provider
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expiration time in seconds
    pub expires_in: Option<u64>,
    /// Refresh token (if provided)
    pub refresh_token: Option<String>,
    /// Scope granted by provider
    pub scope: Option<String>,
    /// ID token (for OIDC providers)
    pub id_token: Option<String>,
}

/// User information retrieved from external provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUserInfo {
    /// User ID from the provider (e.g., Google's "sub" claim, GitHub's "id")
    pub provider_user_id: String,
    /// Email address
    pub email: String,
    /// Whether email is verified by the provider
    pub email_verified: Option<bool>,
    /// Full name
    pub name: Option<String>,
    /// Given name / First name
    pub given_name: Option<String>,
    /// Family name / Last name
    pub family_name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Username / preferred username
    pub preferred_username: Option<String>,
    /// Locale preference
    pub locale: Option<String>,
    /// Raw profile data from provider (for debugging/logging)
    pub raw_profile: serde_json::Value,
}

/// Federation provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationProviderConfig {
    /// Provider type: "google", "github", "azure", "okta", etc.
    pub provider_type: String,
    /// Provider ID (unique within tenant): "google", "github", "company-okta", etc.
    pub provider_id: String,
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 client secret
    pub client_secret: String,
    /// Authorization endpoint URL (optional - defaults based on provider_type)
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL (optional - defaults based on provider_type)
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint URL (optional - defaults based on provider_type)
    pub userinfo_endpoint: Option<String>,
    /// JWKS endpoint URL for OIDC providers (optional)
    pub jwks_uri: Option<String>,
    /// Scopes to request (optional - defaults based on provider_type)
    pub scopes: Option<Vec<String>>,
    /// Additional provider-specific configuration
    #[serde(default)]
    pub extra: serde_json::Value,
}

/// Errors that can occur during federation
#[derive(Debug)]
pub enum FederationError {
    /// HTTP request failed
    HttpError(reqwest::Error),
    /// JSON parsing failed
    JsonError(serde_json::Error),
    /// Invalid configuration
    ConfigError(String),
    /// Provider returned an error
    ProviderError(String),
    /// Invalid response from provider
    InvalidResponse(String),
    /// Missing required field
    MissingField(String),
}

impl fmt::Display for FederationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FederationError::HttpError(e) => write!(f, "HTTP error: {}", e),
            FederationError::JsonError(e) => write!(f, "JSON error: {}", e),
            FederationError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            FederationError::ProviderError(msg) => write!(f, "Provider error: {}", msg),
            FederationError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            FederationError::MissingField(field) => write!(f, "Missing required field: {}", field),
        }
    }
}

impl std::error::Error for FederationError {}

impl From<reqwest::Error> for FederationError {
    fn from(err: reqwest::Error) -> Self {
        FederationError::HttpError(err)
    }
}

impl From<serde_json::Error> for FederationError {
    fn from(err: serde_json::Error) -> Self {
        FederationError::JsonError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_tokens_serialization() {
        let tokens = ProviderTokens {
            access_token: "access123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: Some("refresh456".to_string()),
            scope: Some("openid profile email".to_string()),
            id_token: Some("id_token789".to_string()),
        };

        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: ProviderTokens = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.access_token, "access123");
        assert_eq!(deserialized.token_type, "Bearer");
        assert_eq!(deserialized.expires_in, Some(3600));
    }

    #[test]
    fn test_provider_user_info() {
        let user_info = ProviderUserInfo {
            provider_user_id: "123456".to_string(),
            email: "user@example.com".to_string(),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            picture: Some("https://example.com/photo.jpg".to_string()),
            preferred_username: Some("testuser".to_string()),
            locale: Some("en-US".to_string()),
            raw_profile: serde_json::json!({"custom": "data"}),
        };

        assert_eq!(user_info.email, "user@example.com");
        assert_eq!(user_info.email_verified, Some(true));
    }

    #[test]
    fn test_federation_error_display() {
        let error = FederationError::ConfigError("Missing client_id".to_string());
        assert_eq!(error.to_string(), "Configuration error: Missing client_id");

        let error = FederationError::MissingField("email".to_string());
        assert_eq!(error.to_string(), "Missing required field: email");
    }
}
