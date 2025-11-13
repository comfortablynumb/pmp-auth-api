// Temporary stub file - old OAuth2 client flow removed
// Will be replaced with OAuth2 authorization server implementation

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2State {
    pub tenant_id: String,
    pub strategy_name: String,
    pub csrf_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuth2CallbackResult {
    pub access_token: String,
    pub user_info: UserInfo,
}

/// Stub: Generate auth URL (removed - was OAuth2 client, now we're the server)
pub fn generate_auth_url(
    _config: &serde_json::Value,
    _tenant_id: &str,
    _strategy_name: &str,
) -> Result<(String, String), String> {
    Err(
        "OAuth2 client flow removed. This service is now an OAuth2 authorization server."
            .to_string(),
    )
}

/// Stub: Handle OAuth2 callback (removed - was OAuth2 client, now we're the server)
pub async fn handle_oauth2_callback(
    _config: &serde_json::Value,
    _code: &str,
    _state: &str,
) -> Result<OAuth2CallbackResult, String> {
    Err(
        "OAuth2 client callback removed. This service is now an OAuth2 authorization server."
            .to_string(),
    )
}
