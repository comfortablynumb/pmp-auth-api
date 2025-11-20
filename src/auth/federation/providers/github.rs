// GitHub OAuth2 Provider Implementation

use crate::auth::federation::{FederationProvider, FederationError, ProviderTokens, ProviderUserInfo};
use crate::auth::federation::types::FederationProviderConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// GitHub OAuth2 Provider
pub struct GitHubProvider {
    config: FederationProviderConfig,
    client: reqwest::Client,
}

/// GitHub's token response
#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    scope: Option<String>,
}

/// GitHub's user response
#[derive(Debug, Deserialize, Serialize)]
struct GitHubUser {
    /// User ID
    id: u64,
    /// Login username
    login: String,
    /// Display name
    #[serde(default)]
    name: Option<String>,
    /// Email (may be null if private)
    #[serde(default)]
    email: Option<String>,
    /// Avatar URL
    #[serde(default)]
    avatar_url: Option<String>,
    /// Location
    #[serde(default)]
    location: Option<String>,
    /// Bio
    #[serde(default)]
    bio: Option<String>,
}

/// GitHub email response
#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    #[allow(dead_code)]
    visibility: Option<String>,
}

impl GitHubProvider {
    /// GitHub's OAuth2 endpoints
    const AUTHORIZATION_ENDPOINT: &'static str = "https://github.com/login/oauth/authorize";
    const TOKEN_ENDPOINT: &'static str = "https://github.com/login/oauth/access_token";
    const USER_ENDPOINT: &'static str = "https://api.github.com/user";
    const USER_EMAILS_ENDPOINT: &'static str = "https://api.github.com/user/emails";

    /// Create a new GitHub provider instance
    pub fn new(config: FederationProviderConfig) -> Result<Self, FederationError> {
        if config.client_id.is_empty() {
            return Err(FederationError::ConfigError(
                "GitHub client_id is required".to_string(),
            ));
        }

        if config.client_secret.is_empty() {
            return Err(FederationError::ConfigError(
                "GitHub client_secret is required".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("pmp-auth-api") // GitHub requires a user agent
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

    /// Get user endpoint (with override support)
    fn get_user_endpoint(&self) -> &str {
        self.config
            .userinfo_endpoint
            .as_deref()
            .unwrap_or(Self::USER_ENDPOINT)
    }

    /// Fetch user's primary verified email from GitHub
    async fn fetch_primary_email(&self, access_token: &str) -> Result<Option<String>, FederationError> {
        let response = self
            .client
            .get(Self::USER_EMAILS_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            // If we can't get emails, it's not a fatal error
            // The user's email might be public on their profile
            debug!("Could not fetch GitHub user emails (may not have user:email scope)");
            return Ok(None);
        }

        let emails: Vec<GitHubEmail> = response.json().await?;

        // Find primary verified email
        let primary_email = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .map(|e| e.email.clone());

        Ok(primary_email)
    }
}

#[async_trait]
impl FederationProvider for GitHubProvider {
    fn provider_id(&self) -> &str {
        &self.config.provider_id
    }

    fn provider_name(&self) -> &str {
        "GitHub"
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
            &[],
        );

        debug!("Generated GitHub authorization URL: {}", url);
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderTokens, FederationError> {
        debug!("Exchanging authorization code with GitHub");

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
            .header("Accept", "application/json") // GitHub returns JSON with this header
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            warn!("GitHub token exchange failed: {} - {}", status, error_text);
            return Err(FederationError::ProviderError(format!(
                "Token exchange failed: {} - {}",
                status, error_text
            )));
        }

        let token_response: GitHubTokenResponse = response.json().await?;

        debug!("Successfully exchanged code for GitHub tokens");

        Ok(ProviderTokens {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: None, // GitHub tokens don't expire
            refresh_token: None, // GitHub doesn't provide refresh tokens
            scope: token_response.scope,
            id_token: None, // GitHub is OAuth2, not OIDC
        })
    }

    async fn get_user_info(
        &self,
        access_token: &str,
    ) -> Result<ProviderUserInfo, FederationError> {
        debug!("Fetching user info from GitHub");

        // Fetch user profile
        let response = self
            .client
            .get(self.get_user_endpoint())
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            warn!("GitHub user request failed: {} - {}", status, error_text);
            return Err(FederationError::ProviderError(format!(
                "User request failed: {} - {}",
                status, error_text
            )));
        }

        let user: GitHubUser = response.json().await?;

        // GitHub email might be null if user has it set to private
        // Try to fetch from emails API if we have the scope
        let email = if user.email.is_none() {
            self.fetch_primary_email(access_token).await?
        } else {
            user.email.clone()
        };

        let email = email.ok_or_else(|| {
            FederationError::MissingField(
                "email - GitHub user has no public email and user:email scope not granted".to_string(),
            )
        })?;

        debug!("Successfully retrieved user info from GitHub for user: {}", user.login);

        Ok(ProviderUserInfo {
            provider_user_id: user.id.to_string(),
            email: email.clone(),
            email_verified: Some(true), // GitHub emails are always verified
            name: user.name.clone(),
            given_name: None, // GitHub doesn't provide separate first/last names
            family_name: None,
            picture: user.avatar_url.clone(),
            preferred_username: Some(user.login.clone()),
            locale: None, // GitHub doesn't provide locale
            raw_profile: serde_json::to_value(&user).unwrap_or(serde_json::json!({})),
        })
    }

    fn get_scopes(&self) -> Vec<String> {
        // Use configured scopes or default to read:user and user:email
        self.config.scopes.clone().unwrap_or_else(|| {
            vec![
                "read:user".to_string(),
                "user:email".to_string(), // Required to get private emails
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> FederationProviderConfig {
        FederationProviderConfig {
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
        }
    }

    #[test]
    fn test_github_provider_creation() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_github_provider_missing_client_id() {
        let mut config = create_test_config();
        config.client_id = String::new();
        let provider = GitHubProvider::new(config);
        assert!(provider.is_err());
    }

    #[test]
    fn test_github_provider_missing_client_secret() {
        let mut config = create_test_config();
        config.client_secret = String::new();
        let provider = GitHubProvider::new(config);
        assert!(provider.is_err());
    }

    #[test]
    fn test_github_authorization_url() {
        let config = create_test_config();
        let provider = GitHubProvider::new(config).unwrap();

        let url = provider
            .authorization_url(
                "state123",
                "https://myapp.com/callback",
                &provider.get_scopes(),
            )
            .unwrap();

        assert!(url.contains("github.com"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=read%3Auser%20user%3Aemail"));
    }

    #[test]
    fn test_github_custom_scopes() {
        let mut config = create_test_config();
        config.scopes = Some(vec![
            "read:user".to_string(),
            "repo".to_string(),
        ]);

        let provider = GitHubProvider::new(config).unwrap();
        let scopes = provider.get_scopes();

        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&"repo".to_string()));
    }

    #[test]
    fn test_github_user_parsing() {
        let json = r#"{
            "id": 123456,
            "login": "testuser",
            "name": "Test User",
            "email": "test@example.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/123456",
            "location": "San Francisco",
            "bio": "Developer"
        }"#;

        let user: GitHubUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, 123456);
        assert_eq!(user.login, "testuser");
        assert_eq!(user.name, Some("Test User".to_string()));
        assert_eq!(user.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_github_email_parsing() {
        let json = r#"[
            {
                "email": "primary@example.com",
                "verified": true,
                "primary": true,
                "visibility": "public"
            },
            {
                "email": "secondary@example.com",
                "verified": true,
                "primary": false,
                "visibility": "private"
            }
        ]"#;

        let emails: Vec<GitHubEmail> = serde_json::from_str(json).unwrap();
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].email, "primary@example.com");
        assert!(emails[0].primary);
        assert!(emails[0].verified);
    }
}
