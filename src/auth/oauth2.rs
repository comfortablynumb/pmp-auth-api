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

/// Global storage for OAuth2 states (in production, use Redis or similar)
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
pub fn cleanup_expired_states() {
    // In a production system, store timestamps with states and clean up old ones
    // For now, this is a placeholder
    debug!("OAuth2 state cleanup called");
}
