// Google OAuth2/OIDC Provider Implementation

use crate::auth::federation::{FederationProvider, FederationError, ProviderTokens, ProviderUserInfo};
use crate::auth::federation::types::FederationProviderConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Google OAuth2/OIDC Provider
pub struct GoogleProvider {
    config: FederationProviderConfig,
    client: reqwest::Client,
}

/// Google's token response
#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Google's UserInfo response (OIDC)
#[derive(Debug, Deserialize, Serialize)]
struct GoogleUserInfo {
    /// Subject - unique user ID
    sub: String,
    /// Email address
    email: String,
    /// Whether email is verified
    #[serde(default)]
    email_verified: Option<bool>,
    /// Full name
    #[serde(default)]
    name: Option<String>,
    /// Given name
    #[serde(default)]
    given_name: Option<String>,
    /// Family name
    #[serde(default)]
    family_name: Option<String>,
    /// Profile picture URL
    #[serde(default)]
    picture: Option<String>,
    /// Locale
    #[serde(default)]
    locale: Option<String>,
}

impl GoogleProvider {
    /// Google's OAuth2 endpoints
    const AUTHORIZATION_ENDPOINT: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_ENDPOINT: &'static str = "https://oauth2.googleapis.com/token";
    const USERINFO_ENDPOINT: &'static str = "https://www.googleapis.com/oauth2/v3/userinfo";

    /// Create a new Google provider instance
    pub fn new(config: FederationProviderConfig) -> Result<Self, FederationError> {
        if config.client_id.is_empty() {
            return Err(FederationError::ConfigError(
                "Google client_id is required".to_string(),
            ));
        }

        if config.client_secret.is_empty() {
            return Err(FederationError::ConfigError(
                "Google client_secret is required".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                FederationError::ConfigError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { config, client })
    }

    /// Get authorization endpoint (with override support)
    fn get_authorization_endpoint(&self) -> &str {
        self.config
            .authorization_endpoint
            .as_deref()
            .unwrap_or(Self::AUTHORIZATION_ENDPOINT)
    }

    /// Get token endpoint (with override support)
    fn get_token_endpoint(&self) -> &str {
        self.config
            .token_endpoint
            .as_deref()
            .unwrap_or(Self::TOKEN_ENDPOINT)
    }

    /// Get userinfo endpoint (with override support)
    fn get_userinfo_endpoint(&self) -> &str {
        self.config
            .userinfo_endpoint
            .as_deref()
            .unwrap_or(Self::USERINFO_ENDPOINT)
    }
}

#[async_trait]
impl FederationProvider for GoogleProvider {
    fn provider_id(&self) -> &str {
        &self.config.provider_id
    }

    fn provider_name(&self) -> &str {
        "Google"
    }

    fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<String, FederationError> {
        let url = super::build_auth_url(
            self.get_authorization_endpoint(),
            &self.config.client_id,
            redirect_uri,
            scopes,
            state,
            &[
                ("access_type", "offline"), // Request refresh token
                ("prompt", "consent"),      // Force consent to get refresh token
            ],
        );

        debug!("Generated Google authorization URL: {}", url);
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderTokens, FederationError> {
        debug!("Exchanging authorization code with Google");

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("redirect_uri", redirect_uri),
        ];

        let response = self
            .client
            .post(self.get_token_endpoint())
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            warn!("Google token exchange failed: {} - {}", status, error_text);
            return Err(FederationError::ProviderError(format!(
                "Token exchange failed: {} - {}",
                status, error_text
            )));
        }

        let token_response: GoogleTokenResponse = response.json().await?;

        debug!("Successfully exchanged code for Google tokens");

        Ok(ProviderTokens {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
            id_token: token_response.id_token,
        })
    }

    async fn get_user_info(
        &self,
        access_token: &str,
    ) -> Result<ProviderUserInfo, FederationError> {
        debug!("Fetching user info from Google");

        let response = self
            .client
            .get(self.get_userinfo_endpoint())
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            warn!("Google userinfo request failed: {} - {}", status, error_text);
            return Err(FederationError::ProviderError(format!(
                "UserInfo request failed: {} - {}",
                status, error_text
            )));
        }

        let user_info: GoogleUserInfo = response.json().await?;

        debug!("Successfully retrieved user info from Google for user: {}", user_info.sub);

        Ok(ProviderUserInfo {
            provider_user_id: user_info.sub.clone(),
            email: user_info.email.clone(),
            email_verified: user_info.email_verified,
            name: user_info.name.clone(),
            given_name: user_info.given_name.clone(),
            family_name: user_info.family_name.clone(),
            picture: user_info.picture.clone(),
            preferred_username: Some(user_info.email.clone()), // Google doesn't have username, use email
            locale: user_info.locale.clone(),
            raw_profile: serde_json::to_value(&user_info).unwrap_or(serde_json::json!({})),
        })
    }

    fn get_scopes(&self) -> Vec<String> {
        // Use configured scopes or default to standard OpenID Connect scopes
        self.config.scopes.clone().unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> FederationProviderConfig {
        FederationProviderConfig {
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
        }
    }

    #[test]
    fn test_google_provider_creation() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_google_provider_missing_client_id() {
        let mut config = create_test_config();
        config.client_id = String::new();
        let provider = GoogleProvider::new(config);
        assert!(provider.is_err());
    }

    #[test]
    fn test_google_provider_missing_client_secret() {
        let mut config = create_test_config();
        config.client_secret = String::new();
        let provider = GoogleProvider::new(config);
        assert!(provider.is_err());
    }

    #[test]
    fn test_google_authorization_url() {
        let config = create_test_config();
        let provider = GoogleProvider::new(config).unwrap();

        let url = provider
            .authorization_url(
                "state123",
                "https://myapp.com/callback",
                &provider.get_scopes(),
            )
            .unwrap();

        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=openid%20profile%20email"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn test_google_custom_scopes() {
        let mut config = create_test_config();
        config.scopes = Some(vec![
            "openid".to_string(),
            "email".to_string(),
            "https://www.googleapis.com/auth/drive.readonly".to_string(),
        ]);

        let provider = GoogleProvider::new(config).unwrap();
        let scopes = provider.get_scopes();

        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"https://www.googleapis.com/auth/drive.readonly".to_string()));
    }

    #[test]
    fn test_google_custom_endpoints() {
        let mut config = create_test_config();
        config.authorization_endpoint = Some("https://custom.google.com/auth".to_string());
        config.token_endpoint = Some("https://custom.google.com/token".to_string());
        config.userinfo_endpoint = Some("https://custom.google.com/userinfo".to_string());

        let provider = GoogleProvider::new(config).unwrap();

        assert_eq!(
            provider.get_authorization_endpoint(),
            "https://custom.google.com/auth"
        );
        assert_eq!(provider.get_token_endpoint(), "https://custom.google.com/token");
        assert_eq!(
            provider.get_userinfo_endpoint(),
            "https://custom.google.com/userinfo"
        );
    }

    #[test]
    fn test_google_userinfo_parsing() {
        let json = r#"{
            "sub": "1234567890",
            "email": "user@gmail.com",
            "email_verified": true,
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
            "locale": "en"
        }"#;

        let user_info: GoogleUserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(user_info.sub, "1234567890");
        assert_eq!(user_info.email, "user@gmail.com");
        assert_eq!(user_info.email_verified, Some(true));
        assert_eq!(user_info.name, Some("Test User".to_string()));
    }
}
