// OAuth2 Federation - External Identity Provider Integration
// This module allows authenticating users via external OAuth2/OIDC providers
// while always issuing tokens from this authorization server

pub mod providers;
pub mod types;

use crate::AppState;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use providers::{create_provider, GoogleProvider, GitHubProvider};
pub use types::{FederationError, ProviderTokens, ProviderUserInfo};

/// Trait that all federation providers must implement
/// This allows adding new providers (Azure AD, Okta, etc.) easily
#[async_trait]
pub trait FederationProvider: Send + Sync {
    /// Unique identifier for this provider (e.g., "google", "github")
    fn provider_id(&self) -> &str;

    /// Human-readable name (e.g., "Google", "GitHub")
    fn provider_name(&self) -> &str;

    /// Generate the authorization URL to redirect users to
    fn authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<String, FederationError>;

    /// Exchange authorization code for access token
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<ProviderTokens, FederationError>;

    /// Get user information from the provider using access token
    async fn get_user_info(
        &self,
        access_token: &str,
    ) -> Result<ProviderUserInfo, FederationError>;

    /// Optional: Get provider-specific configuration
    fn get_scopes(&self) -> Vec<String> {
        vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
    }
}

/// Federation login request query parameters
#[derive(Debug, Deserialize)]
pub struct FederationLoginQuery {
    /// Optional state to return after authentication
    pub state: Option<String>,
    /// Optional redirect URI for final redirect after getting our tokens
    pub redirect_uri: Option<String>,
}

/// Federation callback query parameters
#[derive(Debug, Deserialize)]
pub struct FederationCallbackQuery {
    /// Authorization code from provider
    pub code: Option<String>,
    /// State parameter for CSRF protection
    pub state: Option<String>,
    /// Error from provider
    pub error: Option<String>,
    /// Error description from provider
    pub error_description: Option<String>,
}

/// Federation state stored in Redis during OAuth2 flow
#[derive(Debug, Serialize, Deserialize)]
struct FederationState {
    pub tenant_id: String,
    pub provider_id: String,
    pub nonce: String,
    pub client_redirect_uri: Option<String>,
    pub client_state: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Initiate federation login flow
/// GET /api/v1/tenant/{tenant_id}/federate/{provider_id}/login
pub async fn federation_login(
    State(state): State<AppState>,
    Path((tenant_id, provider_id)): Path<(String, String)>,
    Query(query): Query<FederationLoginQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Federation login initiated for tenant '{}' with provider '{}'",
        tenant_id, provider_id
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get federation provider configuration
    let provider_config = tenant
        .get_federation_provider(&provider_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "provider_not_found",
                    "error_description": format!("Federation provider '{}' not configured for this tenant", provider_id)
                })),
            )
        })?;

    // Create provider instance
    let provider = create_provider(provider_config).map_err(|e| {
        warn!("Failed to create provider: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to initialize federation provider"
            })),
        )
    })?;

    // Generate state parameter for CSRF protection
    let state_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();

    let federation_state = FederationState {
        tenant_id: tenant_id.clone(),
        provider_id: provider_id.clone(),
        nonce,
        client_redirect_uri: query.redirect_uri,
        client_state: query.state,
        created_at: chrono::Utc::now(),
    };

    // Store state in session storage with 10 minute expiration
    let state_key = format!("federation:state:{}", state_id);
    let mut state_data = std::collections::HashMap::new();
    state_data.insert("tenant_id".to_string(), tenant_id.clone());
    state_data.insert("provider_id".to_string(), provider_id.clone());
    state_data.insert("nonce".to_string(), federation_state.nonce.clone());
    if let Some(ref redirect_uri) = federation_state.client_redirect_uri {
        state_data.insert("client_redirect_uri".to_string(), redirect_uri.clone());
    }
    if let Some(ref client_state) = federation_state.client_state {
        state_data.insert("client_state".to_string(), client_state.clone());
    }

    let session_data = crate::storage::SessionData {
        session_id: state_key.clone(),
        tenant_id: tenant_id.clone(),
        user_id: None,
        client_id: provider_id.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        data: state_data,
    };

    state
        .storage
        .store_session(&state_key, session_data)
        .await
        .map_err(|e| {
            warn!("Failed to store federation state: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?;

    // Build callback URL
    let callback_url = format!(
        "/api/v1/tenant/{}/federate/{}/callback",
        tenant_id, provider_id
    );

    // Generate authorization URL
    let auth_url = provider
        .authorization_url(&state_id, &callback_url, &provider.get_scopes())
        .map_err(|e| {
            warn!("Failed to generate authorization URL: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to generate authorization URL"
                })),
            )
        })?;

    debug!("Redirecting to provider authorization URL: {}", auth_url);

    // Redirect to provider
    Ok(Redirect::temporary(&auth_url))
}

/// Handle federation callback from provider
/// GET /api/v1/tenant/{tenant_id}/federate/{provider_id}/callback
pub async fn federation_callback(
    State(state): State<AppState>,
    Path((tenant_id, provider_id)): Path<(String, String)>,
    Query(query): Query<FederationCallbackQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Federation callback received for tenant '{}' with provider '{}'",
        tenant_id, provider_id
    );

    // Check for error from provider
    if let Some(error) = query.error {
        warn!("Provider returned error: {}", error);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": error,
                "error_description": query.error_description.unwrap_or_else(|| "Provider authentication failed".to_string())
            })),
        ));
    }

    // Get authorization code
    let code = query.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing authorization code"
            })),
        )
    })?;

    // Get state
    let state_id = query.state.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing state parameter"
            })),
        )
    })?;

    // Retrieve and validate state from session storage
    let state_key = format!("federation:state:{}", state_id);
    let session_data = state
        .storage
        .get_session(&state_key)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve federation state: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_state",
                    "error_description": "State parameter not found or expired"
                })),
            )
        })?;

    // Reconstruct federation state from session data
    let federation_state = FederationState {
        tenant_id: session_data.data.get("tenant_id").cloned().unwrap_or_default(),
        provider_id: session_data.data.get("provider_id").cloned().unwrap_or_default(),
        nonce: session_data.data.get("nonce").cloned().unwrap_or_default(),
        client_redirect_uri: session_data.data.get("client_redirect_uri").cloned(),
        client_state: session_data.data.get("client_state").cloned(),
        created_at: session_data.created_at,
    };

    // Validate state belongs to this tenant and provider
    if federation_state.tenant_id != tenant_id || federation_state.provider_id != provider_id {
        warn!("State mismatch: expected tenant '{}' provider '{}', got tenant '{}' provider '{}'",
            tenant_id, provider_id, federation_state.tenant_id, federation_state.provider_id);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_state",
                "error_description": "State validation failed"
            })),
        ));
    }

    // Delete state from session storage (one-time use)
    let _ = state.storage.delete_session(&state_key).await;

    // Get tenant and provider configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    let provider_config = tenant
        .get_federation_provider(&provider_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "provider_not_found" })),
            )
        })?;

    // Create provider instance
    let provider = create_provider(provider_config).map_err(|e| {
        warn!("Failed to create provider: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error" })),
        )
    })?;

    // Build callback URL (same as we used in authorization request)
    let callback_url = format!(
        "/api/v1/tenant/{}/federate/{}/callback",
        tenant_id, provider_id
    );

    // Exchange code for tokens
    let provider_tokens = provider.exchange_code(&code, &callback_url).await.map_err(|e| {
        warn!("Failed to exchange code for tokens: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Failed to exchange authorization code"
            })),
        )
    })?;

    // Get user info from provider
    let provider_user_info = provider
        .get_user_info(&provider_tokens.access_token)
        .await
        .map_err(|e| {
            warn!("Failed to get user info from provider: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_token",
                    "error_description": "Failed to retrieve user information from provider"
                })),
            )
        })?;

    info!(
        "Successfully authenticated user '{}' ({}) via provider '{}'",
        provider_user_info.provider_user_id, provider_user_info.email, provider_id
    );

    // Get or create federated user in our system
    let (oauth2_config, _storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "oauth2_not_configured" })),
        )
    })?;

    let user = state
        .storage
        .get_or_create_federated_user(&tenant_id, &provider_id, &provider_user_info)
        .await
        .map_err(|e| {
            warn!("Failed to get or create federated user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to create user: {}", e)
                })),
            )
        })?;

    // Issue OUR tokens (not the provider's tokens)
    let scope_vec = vec!["openid".to_string(), "profile".to_string(), "email".to_string()];

    let access_token = crate::auth::oauth2_server::generate_access_token(
        &user.id,
        &user.email,
        crate::models::UserRole::from_str(&user.role).unwrap_or(crate::models::UserRole::User),
        &scope_vec,
        &tenant_id,
        "federation", // client_id for federated logins
        oauth2_config,
    )
    .map_err(|e| {
        warn!("Failed to generate access token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error" })),
        )
    })?;

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();
    let session_id = Uuid::new_v4().to_string(); // Generate session ID for logout coordination (REQUIRED)
    let now = chrono::Utc::now();
    let refresh_token_data = crate::storage::RefreshTokenData {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        client_id: "federation".to_string(),
        scope: scope_vec.join(" "),
        created_at: now,
        expires_at: Some(now + chrono::Duration::days(30)),
        session_id: session_id.clone(),
    };

    state
        .storage
        .store_refresh_token(&refresh_token, refresh_token_data)
        .await
        .map_err(|e| {
            warn!("Failed to store refresh token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?;

    // Generate ID token if OIDC is enabled
    let id_token = if let Some((oidc_config, _)) = tenant.get_oidc_provider() {
        Some(
            crate::auth::oidc::generate_id_token(
                &user.id,
                &user.email,
                user.name.clone(),
                "federation",
                None, // nonce
                Some(&access_token),
                None, // authorization_code
                None, // acr
                Some(vec!["federated".to_string()]), // amr
                session_id.clone(), // sid for session management (REQUIRED)
                oauth2_config,
                oidc_config,
            )
            .map_err(|e| {
                warn!("Failed to generate ID token: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "server_error" })),
                )
            })?,
        )
    } else {
        None
    };

    // Build final redirect URL
    let final_redirect = if let Some(client_redirect_uri) = federation_state.client_redirect_uri {
        // Redirect to client application with tokens in fragment
        let mut fragments = vec![
            format!("access_token={}", access_token),
            "token_type=Bearer".to_string(),
            format!("expires_in={}", oauth2_config.access_token_expiration_secs),
            format!("refresh_token={}", refresh_token),
        ];

        if let Some(id_token) = id_token {
            fragments.push(format!("id_token={}", id_token));
        }

        if let Some(client_state) = federation_state.client_state {
            fragments.push(format!("state={}", client_state));
        }

        format!("{}#{}", client_redirect_uri, fragments.join("&"))
    } else {
        // No client redirect URI - return JSON response
        // This is useful for testing or when using federation as an API
        return Ok(Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": oauth2_config.access_token_expiration_secs,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope_vec.join(" "),
        }))
        .into_response());
    };

    debug!("Redirecting to client application: {}", final_redirect);
    Ok(Redirect::temporary(&final_redirect).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_state_serialization() {
        let state = FederationState {
            tenant_id: "test-tenant".to_string(),
            provider_id: "google".to_string(),
            nonce: "nonce123".to_string(),
            client_redirect_uri: Some("https://app.example.com/callback".to_string()),
            client_state: Some("state456".to_string()),
            created_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: FederationState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tenant_id, "test-tenant");
        assert_eq!(deserialized.provider_id, "google");
        assert_eq!(deserialized.nonce, "nonce123");
        assert_eq!(deserialized.client_redirect_uri, Some("https://app.example.com/callback".to_string()));
        assert_eq!(deserialized.client_state, Some("state456".to_string()));
    }

    #[test]
    fn test_federation_state_without_optional_fields() {
        let state = FederationState {
            tenant_id: "test-tenant".to_string(),
            provider_id: "github".to_string(),
            nonce: "nonce789".to_string(),
            client_redirect_uri: None,
            client_state: None,
            created_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: FederationState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tenant_id, "test-tenant");
        assert_eq!(deserialized.provider_id, "github");
        assert_eq!(deserialized.client_redirect_uri, None);
        assert_eq!(deserialized.client_state, None);
    }

    #[test]
    fn test_federation_login_query_parsing() {
        // Test with all fields
        let json = r#"{"state": "abc123", "redirect_uri": "https://example.com"}"#;
        let query: FederationLoginQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.state, Some("abc123".to_string()));
        assert_eq!(query.redirect_uri, Some("https://example.com".to_string()));

        // Test with missing fields
        let json = r#"{}"#;
        let query: FederationLoginQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.state, None);
        assert_eq!(query.redirect_uri, None);
    }

    #[test]
    fn test_federation_callback_query_parsing() {
        // Test successful callback
        let json = r#"{"code": "auth_code_123", "state": "state_456"}"#;
        let query: FederationCallbackQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.code, Some("auth_code_123".to_string()));
        assert_eq!(query.state, Some("state_456".to_string()));
        assert_eq!(query.error, None);

        // Test error callback
        let json = r#"{"error": "access_denied", "error_description": "User denied access"}"#;
        let query: FederationCallbackQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.error, Some("access_denied".to_string()));
        assert_eq!(query.error_description, Some("User denied access".to_string()));
        assert_eq!(query.code, None);
    }
}
