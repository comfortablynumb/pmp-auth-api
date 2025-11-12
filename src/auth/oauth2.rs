use crate::models::OAuth2Config;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};

/// OAuth2 state data stored during the authorization flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2State {
    pub tenant_id: String,
    pub strategy_name: String,
    pub csrf_token: String,
}

// Global storage for OAuth2 states (in production, use Redis or similar)
lazy_static::lazy_static! {
    static ref OAUTH2_STATES: Arc<Mutex<HashMap<String, OAuth2State>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// Create an OAuth2 client from configuration
pub fn create_oauth2_client(config: &OAuth2Config) -> Result<BasicClient, String> {
    let auth_url =
        AuthUrl::new(config.auth_url.clone()).map_err(|e| format!("Invalid auth URL: {}", e))?;

    let token_url =
        TokenUrl::new(config.token_url.clone()).map_err(|e| format!("Invalid token URL: {}", e))?;

    let client = BasicClient::new(
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| format!("Invalid redirect URI: {}", e))?,
    );

    Ok(client)
}

/// Generate authorization URL for OAuth2 flow
pub fn generate_auth_url(
    config: &OAuth2Config,
    tenant_id: &str,
    strategy_name: &str,
) -> Result<(String, String), String> {
    let client = create_oauth2_client(config)?;

    let mut auth_request = client.authorize_url(CsrfToken::new_random);

    // Add scopes
    for scope in &config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (url, csrf_token) = auth_request.url();

    // Store state for validation
    let state = OAuth2State {
        tenant_id: tenant_id.to_string(),
        strategy_name: strategy_name.to_string(),
        csrf_token: csrf_token.secret().clone(),
    };

    {
        let mut states = OAUTH2_STATES.lock().unwrap();
        states.insert(csrf_token.secret().clone(), state);
    }

    debug!(
        "Generated OAuth2 auth URL for tenant {} strategy {}",
        tenant_id, strategy_name
    );

    Ok((url.to_string(), csrf_token.secret().clone()))
}

/// Validate OAuth2 callback and exchange code for token
pub async fn handle_oauth2_callback(
    config: &OAuth2Config,
    code: &str,
    state: &str,
) -> Result<OAuth2CallbackResult, String> {
    // Validate state
    let oauth_state = {
        let mut states = OAUTH2_STATES.lock().unwrap();
        states
            .remove(state)
            .ok_or_else(|| "Invalid or expired state".to_string())?
    };

    debug!(
        "Processing OAuth2 callback for tenant {} strategy {}",
        oauth_state.tenant_id, oauth_state.strategy_name
    );

    let client = create_oauth2_client(config)?;

    // Exchange code for token
    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!("Failed to exchange authorization code: {}", e);
            format!("Failed to exchange code: {}", e)
        })?;

    let access_token = token_result.access_token().secret().clone();

    // Fetch user info if endpoint is configured
    let user_info = if let Some(userinfo_url) = &config.userinfo_url {
        fetch_user_info(userinfo_url, &access_token).await?
    } else {
        None
    };

    info!(
        "Successfully completed OAuth2 flow for tenant {} strategy {}",
        oauth_state.tenant_id, oauth_state.strategy_name
    );

    Ok(OAuth2CallbackResult {
        access_token,
        user_info,
        tenant_id: oauth_state.tenant_id,
        strategy_name: oauth_state.strategy_name,
    })
}

/// Result of OAuth2 callback processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2CallbackResult {
    pub access_token: String,
    pub user_info: Option<UserInfo>,
    pub tenant_id: String,
    pub strategy_name: String,
}

/// User information from OAuth2 provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Fetch user information from OAuth2 provider
async fn fetch_user_info(
    userinfo_url: &str,
    access_token: &str,
) -> Result<Option<UserInfo>, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to fetch user info: {}", e);
            format!("Failed to fetch user info: {}", e)
        })?;

    if !response.status().is_success() {
        return Err(format!(
            "User info endpoint returned status: {}",
            response.status()
        ));
    }

    let user_data: serde_json::Value = response.json().await.map_err(|e| {
        error!("Failed to parse user info: {}", e);
        format!("Failed to parse user info: {}", e)
    })?;

    // Try to extract common fields
    let id = user_data["id"]
        .as_str()
        .or_else(|| user_data["sub"].as_str())
        .or_else(|| user_data["user_id"].as_str())
        .unwrap_or("unknown")
        .to_string();

    let email = user_data["email"].as_str().map(|s| s.to_string());
    let name = user_data["name"]
        .as_str()
        .or_else(|| user_data["login"].as_str())
        .map(|s| s.to_string());
    let picture = user_data["picture"]
        .as_str()
        .or_else(|| user_data["avatar_url"].as_str())
        .map(|s| s.to_string());

    // Store all fields as extra data
    let extra: HashMap<String, serde_json::Value> = if let Some(obj) = user_data.as_object() {
        obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    } else {
        HashMap::new()
    };

    Ok(Some(UserInfo {
        id,
        email,
        name,
        picture,
        extra,
    }))
}

/// Clear expired OAuth2 states (should be called periodically)
#[allow(dead_code)] // Exported for library use
pub fn cleanup_expired_states() {
    // In a production system, store timestamps with states and clean up old ones
    // For now, this is a placeholder
    debug!("OAuth2 state cleanup called");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_oauth2_config() -> OAuth2Config {
        OAuth2Config {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            userinfo_url: Some("https://www.googleapis.com/oauth2/v3/userinfo".to_string()),
        }
    }

    #[test]
    fn test_create_oauth2_client() {
        let config = create_test_oauth2_config();
        let result = create_oauth2_client(&config);

        assert!(result.is_ok());
    }

    #[test]
    fn test_create_oauth2_client_invalid_auth_url() {
        let mut config = create_test_oauth2_config();
        config.auth_url = "not-a-valid-url".to_string();

        let result = create_oauth2_client(&config);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("auth URL"));
    }

    #[test]
    fn test_create_oauth2_client_invalid_token_url() {
        let mut config = create_test_oauth2_config();
        config.token_url = "not-a-valid-url".to_string();

        let result = create_oauth2_client(&config);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("token URL"));
    }

    #[test]
    fn test_create_oauth2_client_invalid_redirect_uri() {
        let mut config = create_test_oauth2_config();
        config.redirect_uri = "not-a-valid-url".to_string();

        let result = create_oauth2_client(&config);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("redirect URI"));
    }

    #[test]
    fn test_generate_auth_url() {
        let config = create_test_oauth2_config();
        let result = generate_auth_url(&config, "test-tenant", "google");

        assert!(result.is_ok());
        let (auth_url, csrf_token) = result.unwrap();

        // Check that URL contains expected parameters
        assert!(auth_url.contains("client_id=test-client-id"));
        assert!(auth_url.contains("redirect_uri"));
        assert!(auth_url.contains("scope"));
        assert!(auth_url.contains("state"));

        // Check that CSRF token is not empty
        assert!(!csrf_token.is_empty());

        // Verify state was stored
        let states = OAUTH2_STATES.lock().unwrap();
        assert!(states.contains_key(&csrf_token));

        // Verify state content
        let state = states.get(&csrf_token).unwrap();
        assert_eq!(state.tenant_id, "test-tenant");
        assert_eq!(state.strategy_name, "google");
        assert_eq!(state.csrf_token, csrf_token);
    }

    #[test]
    fn test_generate_auth_url_with_multiple_scopes() {
        let config = create_test_oauth2_config();
        let result = generate_auth_url(&config, "tenant1", "provider1");

        assert!(result.is_ok());
        let (auth_url, _) = result.unwrap();

        // Check that scopes are included
        assert!(auth_url.contains("openid"));
        assert!(auth_url.contains("email"));
    }

    #[test]
    fn test_oauth2_state_structure() {
        let state = OAuth2State {
            tenant_id: "test-tenant".to_string(),
            strategy_name: "google-oauth".to_string(),
            csrf_token: "random-csrf-token".to_string(),
        };

        assert_eq!(state.tenant_id, "test-tenant");
        assert_eq!(state.strategy_name, "google-oauth");
        assert_eq!(state.csrf_token, "random-csrf-token");
    }

    #[test]
    fn test_user_info_structure() {
        let mut extra = HashMap::new();
        extra.insert("custom_field".to_string(), serde_json::json!("custom_value"));

        let user_info = UserInfo {
            id: "user123".to_string(),
            email: Some("user@example.com".to_string()),
            name: Some("Test User".to_string()),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            extra,
        };

        assert_eq!(user_info.id, "user123");
        assert_eq!(user_info.email, Some("user@example.com".to_string()));
        assert_eq!(user_info.name, Some("Test User".to_string()));
        assert!(user_info.extra.contains_key("custom_field"));
    }

    #[test]
    fn test_oauth2_callback_result_structure() {
        let result = OAuth2CallbackResult {
            access_token: "test-access-token".to_string(),
            user_info: Some(UserInfo {
                id: "user123".to_string(),
                email: Some("user@example.com".to_string()),
                name: Some("Test User".to_string()),
                picture: None,
                extra: HashMap::new(),
            }),
            tenant_id: "test-tenant".to_string(),
            strategy_name: "google".to_string(),
        };

        assert_eq!(result.access_token, "test-access-token");
        assert_eq!(result.tenant_id, "test-tenant");
        assert_eq!(result.strategy_name, "google");
        assert!(result.user_info.is_some());
    }

    #[test]
    fn test_cleanup_expired_states() {
        // This is just a placeholder test since the function is a no-op
        cleanup_expired_states();
        // Test passes if no panic occurs
    }
}
