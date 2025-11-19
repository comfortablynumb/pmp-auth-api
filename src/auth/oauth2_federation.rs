// OAuth2 Federation - External Identity Provider Integration
// This module implements OAuth2 client functionality to federate with external IdPs

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// OAuth2 Federation Authorization Request
/// Initiates the OAuth2 flow by redirecting to the external provider
#[derive(Debug, Deserialize)]
pub struct FederationAuthRequest {
    /// OAuth2 provider name (google, github, microsoft, etc.)
    pub provider: String,
    /// OAuth2 client_id that is initiating the federation flow
    pub client_id: String,
    /// Redirect URI to return to after authentication (must match registered client)
    pub redirect_uri: String,
    /// OAuth2 scopes requested
    pub scope: String,
    /// Optional state parameter for CSRF protection
    pub state: Option<String>,
}

/// Federation state stored during OAuth2 flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationStateData {
    /// The OAuth2 client that initiated the flow
    pub client_id: String,
    /// Where to redirect after successful authentication
    pub redirect_uri: String,
    /// Requested OAuth2 scopes
    pub scope: String,
    /// Original state parameter from client
    pub original_state: Option<String>,
    /// User ID (set after authentication)
    pub user_id: Option<String>,
    /// When this state was created
    pub created_at: chrono::DateTime<Utc>,
}

/// OAuth2 Federation Callback Query Parameters
#[derive(Debug, Deserialize)]
pub struct FederationCallbackParams {
    /// Authorization code from provider
    pub code: String,
    /// State parameter for CSRF protection
    pub state: Option<String>,
    /// Error from provider (if any)
    pub error: Option<String>,
    /// Error description from provider
    pub error_description: Option<String>,
}

/// Token response from external OAuth2 provider
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// User profile from external OAuth2 provider
#[derive(Debug, Deserialize, Serialize)]
pub struct ExternalUserProfile {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    #[serde(default)]
    pub verified_email: bool,
}

/// Initiate OAuth2 federation flow
/// GET /api/v1/tenant/{tenant_id}/oauth/federation/authorize
pub async fn federation_authorize(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(params): Query<FederationAuthRequest>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Federation authorization request for tenant '{}' with provider '{}', client_id '{}'",
        tenant_id, params.provider, params.client_id
    );

    // Verify tenant exists
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Verify OAuth2 client exists and redirect_uri matches
    let client = state
        .storage
        .get_oauth2_client(&params.client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Client not found"
                })),
            )
        })?;

    // Verify client belongs to this tenant
    if client.tenant_id != tenant_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "invalid_client",
                "error_description": "Client does not belong to this tenant"
            })),
        ));
    }

    // Verify redirect_uri matches one of the registered URIs
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "redirect_uri does not match any registered redirect URIs"
            })),
        ));
    }

    // Get the OAuth2 backend config
    let oauth2_config = match &tenant.identity_backend {
        crate::models::IdentityBackend::OAuth2(config) => config,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_backend",
                    "error_description": "Tenant is not configured for OAuth2 federation"
                })),
            ))
        }
    };

    // Verify provider matches
    if oauth2_config.provider != params.provider {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_provider",
                "error_description": format!("Provider '{}' does not match configured provider '{}'", params.provider, oauth2_config.provider)
            })),
        ));
    }

    // Get the tenant's OAuth2 server config for the issuer URL
    let tenant_oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "OAuth2 not configured for tenant"
            })),
        )
    })?;

    // Generate unique federation state ID
    let federation_state_id = Uuid::new_v4().to_string();

    // Create federation state data
    let federation_state = FederationStateData {
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params.scope.clone(),
        original_state: params.state.clone(),
        user_id: None,
        created_at: Utc::now(),
    };

    // Store federation state (using SessionData storage with 5-minute expiration)
    let session_data = crate::storage::SessionData {
        session_id: federation_state_id.clone(),
        tenant_id: tenant_id.clone(),
        user_id: None,
        client_id: params.client_id.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        data: {
            let mut map = std::collections::HashMap::new();
            map.insert(
                "federation_state".to_string(),
                serde_json::to_string(&federation_state).map_err(|e| {
                    warn!("Failed to serialize federation state: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "server_error" })),
                    )
                })?,
            );
            map
        },
    };

    state
        .storage
        .store_session(&federation_state_id, session_data)
        .await
        .map_err(|e| {
            warn!("Failed to store federation state: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Failed to store federation state" })),
            )
        })?;

    debug!("Stored federation state with ID: {}", federation_state_id);

    // Build full callback URL using the issuer as base
    let callback_url = format!(
        "{}/api/v1/tenant/{}/oauth/federation/callback",
        tenant_oauth2_config.issuer.trim_end_matches('/'),
        tenant_id
    );

    debug!("Federation callback URL: {}", callback_url);

    // Build authorization URL for external provider
    let mut auth_url = oauth2_config.auth_url.clone();

    // Add query parameters
    let scopes = if oauth2_config.scopes.is_empty() {
        "openid email profile".to_string()
    } else {
        oauth2_config.scopes.join(" ")
    };

    let query_params = [
        ("client_id", oauth2_config.client_id.as_str()),
        ("redirect_uri", callback_url.as_str()),
        ("response_type", "code"),
        ("scope", &scopes),
        ("state", &federation_state_id), // Use federation_state_id as state
    ];

    // Build query string
    let query_string = serde_urlencoded::to_string(&query_params).map_err(|e| {
        warn!("Failed to encode query parameters: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to build authorization URL"
            })),
        )
    })?;

    if auth_url.contains('?') {
        auth_url = format!("{}&{}", auth_url, query_string);
    } else {
        auth_url = format!("{}?{}", auth_url, query_string);
    }

    debug!("Redirecting to: {}", auth_url);

    // Redirect to external provider
    Ok(Redirect::temporary(&auth_url))
}

/// Handle OAuth2 federation callback
/// GET /api/v1/tenant/{tenant_id}/oauth/federation/callback
pub async fn federation_callback(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(params): Query<FederationCallbackParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Federation callback for tenant '{}' with code",
        tenant_id
    );

    // Check for errors from provider
    if let Some(error) = params.error {
        warn!("OAuth2 provider returned error: {}", error);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": error,
                "error_description": params.error_description.unwrap_or_else(|| "OAuth2 provider authentication failed".to_string())
            })),
        ));
    }

    // Retrieve federation state from state parameter
    let federation_state_id = params.state.as_ref().ok_or_else(|| {
        warn!("Missing state parameter in callback");
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing state parameter"
            })),
        )
    })?;

    // Load federation state from storage
    let session_data = state
        .storage
        .get_session(federation_state_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve federation state: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to retrieve session state"
                })),
            )
        })?
        .ok_or_else(|| {
            warn!("Federation state not found: {}", federation_state_id);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired state parameter"
                })),
            )
        })?;

    // Check if session has expired
    if session_data.expires_at < Utc::now() {
        warn!("Federation state expired: {}", federation_state_id);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "State parameter has expired"
            })),
        ));
    }

    // Deserialize federation state
    let federation_state_json = session_data
        .data
        .get("federation_state")
        .ok_or_else(|| {
            warn!("Missing federation_state in session data");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Invalid session state"
                })),
            )
        })?;

    let federation_state: FederationStateData =
        serde_json::from_str(federation_state_json).map_err(|e| {
            warn!("Failed to deserialize federation state: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Invalid session state"
                })),
            )
        })?;

    // Verify tenant exists
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get the OAuth2 backend config
    let oauth2_config = match &tenant.identity_backend {
        crate::models::IdentityBackend::OAuth2(config) => config,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_backend",
                    "error_description": "Tenant is not configured for OAuth2 federation"
                })),
            ))
        }
    };

    // Get the tenant's OAuth2 server config for the issuer URL
    let tenant_oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "OAuth2 not configured for tenant"
            })),
        )
    })?;

    // Exchange authorization code for access token
    // Build full callback URL using the issuer as base (must match what we sent to provider)
    let callback_url = format!(
        "{}/api/v1/tenant/{}/oauth/federation/callback",
        tenant_oauth2_config.issuer.trim_end_matches('/'),
        tenant_id
    );

    let token_request = [
        ("grant_type", "authorization_code"),
        ("code", &params.code),
        ("redirect_uri", &callback_url),
        ("client_id", &oauth2_config.client_id),
        ("client_secret", &oauth2_config.client_secret),
    ];

    let client = Client::new();
    let token_response = client
        .post(&oauth2_config.token_url)
        .form(&token_request)
        .send()
        .await
        .map_err(|e| {
            warn!("Failed to exchange code for token: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "token_exchange_failed",
                    "error_description": "Failed to communicate with OAuth2 provider"
                })),
            )
        })?;

    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        warn!("Token exchange failed: {}", error_text);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "token_exchange_failed",
                "error_description": "OAuth2 provider rejected token exchange"
            })),
        ));
    }

    let token_data: TokenResponse = token_response.json().await.map_err(|e| {
        warn!("Failed to parse token response: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "invalid_token_response",
                "error_description": "Invalid response from OAuth2 provider"
            })),
        )
    })?;

    debug!("Successfully exchanged code for access token");

    // Fetch user profile from provider
    let userinfo_response = client
        .get(&oauth2_config.userinfo_url)
        .bearer_auth(&token_data.access_token)
        .send()
        .await
        .map_err(|e| {
            warn!("Failed to fetch user profile: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "userinfo_failed",
                    "error_description": "Failed to fetch user profile from OAuth2 provider"
                })),
            )
        })?;

    if !userinfo_response.status().is_success() {
        let error_text = userinfo_response.text().await.unwrap_or_default();
        warn!("UserInfo request failed: {}", error_text);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "userinfo_failed",
                "error_description": "OAuth2 provider rejected UserInfo request"
            })),
        ));
    }

    let user_profile: ExternalUserProfile = userinfo_response.json().await.map_err(|e| {
        warn!("Failed to parse user profile: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "invalid_userinfo_response",
                "error_description": "Invalid user profile from OAuth2 provider"
            })),
        )
    })?;

    debug!(
        "Successfully fetched user profile for email: {}",
        user_profile.email
    );

    // Create or update user in local storage
    let user_id = format!("{}_{}", oauth2_config.provider, user_profile.id);

    // Check if user already exists
    let existing_user = state.storage.get_user(&user_id).await.ok();

    if existing_user.is_none() {
        // Create new user
        let new_user = crate::storage::UserData {
            id: user_id.clone(),
            tenant_id: tenant_id.clone(),
            email: user_profile.email.clone(),
            password_hash: String::new(), // No password for federated users
            name: user_profile.name.clone(),
            picture: user_profile.picture.clone(),
            role: "user".to_string(),
            active: true,
            email_verified: user_profile.verified_email,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            attributes: std::collections::HashMap::new(),
        };

        state
            .storage
            .store_user(&user_id, new_user)
            .await
            .map_err(|e| {
                warn!("Failed to create user: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "user_creation_failed",
                        "error_description": "Failed to create user account"
                    })),
                )
            })?;

        info!("Created new federated user: {}", user_id);
    } else {
        info!("User already exists: {}", user_id);
    }

    // Generate authorization code for the client
    let auth_code = Uuid::new_v4().to_string();

    // Verify OAuth2 is configured for tenant
    let _tenant_oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "OAuth2 not configured for tenant"
            })),
        )
    })?;

    // Store authorization code
    let auth_code_data = crate::storage::AuthorizationCodeData {
        tenant_id: tenant_id.clone(),
        client_id: federation_state.client_id.clone(),
        user_id: user_id.clone(),
        redirect_uri: federation_state.redirect_uri.clone(),
        scope: federation_state.scope.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
    };

    state
        .storage
        .store_authorization_code(&auth_code, auth_code_data)
        .await
        .map_err(|e| {
            warn!("Failed to store authorization code: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to generate authorization code"
                })),
            )
        })?;

    // Delete the federation state (one-time use)
    let _ = state.storage.delete_session(federation_state_id).await;

    info!(
        "Successfully authenticated federated user '{}', redirecting to client",
        user_id
    );

    // Build redirect URI with authorization code
    let mut redirect_url = federation_state.redirect_uri.clone();

    // Build query parameters - handle state separately to avoid lifetime issues
    let query_string = if let Some(ref original_state) = federation_state.original_state {
        serde_urlencoded::to_string(&[
            ("code", auth_code.as_str()),
            ("state", original_state.as_str()),
        ])
    } else {
        serde_urlencoded::to_string(&[("code", auth_code.as_str())])
    }
    .map_err(|e| {
        warn!("Failed to encode query parameters: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to build redirect URL"
            })),
        )
    })?;

    if redirect_url.contains('?') {
        redirect_url = format!("{}&{}", redirect_url, query_string);
    } else {
        redirect_url = format!("{}?{}", redirect_url, query_string);
    }

    debug!("Redirecting to client: {}", redirect_url);

    // Redirect back to client application with authorization code
    Ok(Redirect::temporary(&redirect_url).into_response())
}
