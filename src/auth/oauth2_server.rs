// OAuth2 Authorization Server Implementation
// This module implements the OAuth2 authorization server functionality

use crate::auth::identity_backend::{create_identity_backend, BackendError, BackendUser};
use crate::models::{Claims, OAuth2ServerConfig, Tenant, UserRole};
use crate::storage::{
    AuthorizationCodeData as StorageAuthCodeData, RefreshTokenData as StorageRefreshTokenData,
};
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

// OAuth2 server now uses the storage backend for all persistence
// No more in-memory HashMaps!

#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[schema(example = json!({
    "response_type": "code",
    "client_id": "my-client-id",
    "redirect_uri": "https://example.com/callback",
    "scope": "openid profile email",
    "state": "random-state-value",
    "nonce": "random-nonce-value",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256"
}))]
pub struct AuthorizeRequest {
    /// OAuth2 response type (must be "code")
    pub response_type: String,
    /// OAuth2 client identifier
    pub client_id: String,
    /// Callback URI to redirect to after authorization
    pub redirect_uri: String,
    /// Space-separated list of requested scopes
    pub scope: Option<String>,
    /// Opaque value to maintain state between request and callback
    pub state: Option<String>,
    /// OIDC nonce value for replay protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// PKCE code challenge (RFC 7636)
    pub code_challenge: Option<String>,
    /// PKCE code challenge method: "plain" or "S256" (RFC 7636)
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[schema(example = json!({
    "grant_type": "authorization_code",
    "code": "auth-code-here",
    "redirect_uri": "https://example.com/callback",
    "client_id": "my-client-id",
    "client_secret": "my-client-secret",
    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}))]
pub struct TokenRequest {
    /// OAuth2 grant type (authorization_code, refresh_token, client_credentials, password)
    pub grant_type: String,
    /// Authorization code (required for authorization_code grant)
    pub code: Option<String>,
    /// Redirect URI (must match the one used in authorization request)
    pub redirect_uri: Option<String>,
    /// OAuth2 client identifier
    pub client_id: Option<String>,
    /// OAuth2 client secret
    pub client_secret: Option<String>,
    /// Refresh token (required for refresh_token grant)
    pub refresh_token: Option<String>,
    /// Space-separated list of requested scopes
    pub scope: Option<String>,
    /// PKCE code verifier (RFC 7636)
    pub code_verifier: Option<String>,
    /// Resource Owner Password Credentials Grant fields (RFC 6749 Section 4.3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// JWT-based client authentication (RFC 7523)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_assertion_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_assertion: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "refresh-token-here",
    "scope": "openid profile email",
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}))]
pub struct TokenResponse {
    /// JWT access token
    pub access_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Token expiration time in seconds
    pub expires_in: i64,
    /// Refresh token for obtaining new access tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// OpenID Connect ID token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// JWT Client Assertion Claims (RFC 7523)
#[derive(Debug, Deserialize, Serialize)]
struct ClientAssertionClaims {
    /// Issuer - must match client_id
    pub iss: String,
    /// Subject - must match client_id
    pub sub: String,
    /// Audience - must be token endpoint URL
    pub aud: String,
    /// Expiration time
    pub exp: usize,
    /// Issued at time
    pub iat: usize,
    /// JWT ID - for replay prevention
    pub jti: String,
}

/// Logout request (OpenID Connect Session Management)
#[derive(Debug, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[schema(example = json!({
    "id_token_hint": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "post_logout_redirect_uri": "https://example.com/logout",
    "state": "random-state-value"
}))]
pub struct LogoutRequest {
    /// ID token hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_hint: Option<String>,
    /// Logout redirect URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uri: Option<String>,
    /// State parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Logout response
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "message": "Logout successful"
}))]
pub struct LogoutResponse {
    pub message: String,
}

/// OAuth2 Authorization Endpoint
/// GET /api/v1/tenant/{tenant_id}/oauth/authorize
#[utoipa::path(
    get,
    path = "/api/v1/tenant/{tenant_id}/oauth/authorize",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        AuthorizeRequest
    ),
    responses(
        (status = 302, description = "Redirect to callback URI with authorization code"),
        (status = 400, description = "Bad request", body = serde_json::Value),
        (status = 404, description = "Tenant not found", body = serde_json::Value)
    ),
    tag = "OAuth2"
)]
pub async fn oauth2_authorize(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(params): Query<AuthorizeRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "OAuth2 authorize request for tenant '{}', client_id: {}",
        tenant_id, params.client_id
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if OAuth2 is enabled
    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    // Validate response_type
    if params.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_response_type",
                "error_description": "Only 'code' response type is supported"
            })),
        ));
    }

    // Validate grant type is supported
    if !oauth2_config
        .grant_types
        .contains(&"authorization_code".to_string())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unauthorized_client",
                "error_description": "Authorization code flow not enabled"
            })),
        ));
    }

    // Validate client if registered in storage
    let client = validate_client(
        &params.client_id,
        None, // No client secret in authorization request
        None, // No client assertion in authorization request
        None, // No client assertion in authorization request
        &params.redirect_uri,
        "authorization_code",
        &tenant_id,
        &state,
    )
    .await?;

    // Enforce PKCE for public clients
    if let Some(ref client_data) = client {
        if client_data.client_type == crate::storage::OAuth2ClientType::Public {
            // Public clients MUST use PKCE
            if params.code_challenge.is_none() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "PKCE is required for public clients"
                    })),
                ));
            }

            // Public clients MUST use S256 method (not plain)
            if params.code_challenge_method.as_deref() != Some("S256") {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "Public clients must use S256 for PKCE"
                    })),
                ));
            }
        }
    }

    // In a real implementation, this would:
    // 1. Authenticate the user via the identity backend
    // 2. Show a consent screen
    // 3. Generate an authorization code after consent
    //
    // For testing/demo purposes, we use a mock user from the identity backend
    // In production, you would:
    // - Check for existing session (cookie/token)
    // - If no session, redirect to login page
    // - After login, show consent screen
    // - After consent, create authorization code

    // For now, we'll use the first user from the mock backend or a default mock user
    let backend = create_identity_backend(&tenant.identity_backend);
    let user = backend
        .get_user_by_email("demo@example.com")
        .or_else(|_| backend.get_user_by_email("user@example.com"))
        .or_else(|_| backend.get_user_by_email("test@example.com"))
        .map_err(|e| {
            warn!("Failed to get user from identity backend: {}", e);
            info!(
                "No demo user found. Please configure a user in your identity backend or implement proper authentication flow."
            );
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "authentication_required",
                    "error_description": "User authentication required. Please implement login flow."
                })),
            )
        })?;

    info!(
        "User authenticated for OAuth2 flow: {} ({})",
        user.id, user.email
    );

    let auth_code = Uuid::new_v4().to_string();
    let now = Utc::now();

    let code_data = StorageAuthCodeData {
        tenant_id: tenant_id.clone(),
        client_id: params.client_id.clone(),
        user_id: user.id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params
            .scope
            .clone()
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect::<Vec<_>>()
            .join(" "),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(600), // 10 minutes
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        nonce: params.nonce.clone(), // OIDC nonce for replay protection
    };

    // Store authorization code
    state
        .storage
        .store_authorization_code(&auth_code, code_data)
        .await
        .map_err(|e| {
            warn!("Failed to store authorization code: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Failed to store authorization code" })),
            )
        })?;

    // Build redirect URL
    let mut redirect_url = format!("{}?code={}", params.redirect_uri, auth_code);
    if let Some(state) = params.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    debug!("Redirecting to: {}", redirect_url);
    Ok(Redirect::temporary(&redirect_url).into_response())
}

/// OAuth2 Token Endpoint
/// POST /api/v1/tenant/{tenant_id}/oauth/token
///
/// Accepts both application/json and application/x-www-form-urlencoded (RFC 6749)
#[utoipa::path(
    post,
    path = "/api/v1/tenant/{tenant_id}/oauth/token",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier")
    ),
    request_body(content = TokenRequest, description = "Token request (supports application/json and application/x-www-form-urlencoded)", content_type = "application/json"),
    responses(
        (status = 200, description = "Token response", body = TokenResponse),
        (status = 400, description = "Bad request", body = serde_json::Value),
        (status = 401, description = "Unauthorized", body = serde_json::Value),
        (status = 404, description = "Tenant not found", body = serde_json::Value)
    ),
    tag = "OAuth2"
)]
pub async fn oauth2_token(
    Path(tenant_id): Path<String>,
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract parts and body
    let (parts, body) = req.into_parts();

    // Extract Content-Type header from parts
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Extract the request body
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": format!("Failed to read request body: {}", e)
            })),
        )
    })?;

    // Parse the request body based on Content-Type header
    let params: TokenRequest = if content_type.starts_with("application/x-www-form-urlencoded") {
        // Parse as form-urlencoded
        serde_urlencoded::from_bytes(&body_bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": format!("Failed to parse form data: {}", e)
                })),
            )
        })?
    } else {
        // Parse as JSON (default)
        serde_json::from_slice(&body_bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": format!("Failed to parse JSON: {}", e)
                })),
            )
        })?
    };

    info!(
        "OAuth2 token request for tenant '{}', grant_type: {}, content_type: {}",
        tenant_id, params.grant_type, content_type
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if OAuth2 is enabled
    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    match params.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(&tenant_id, oauth2_config, params, &state).await
        }
        "client_credentials" => {
            handle_client_credentials_grant(&tenant_id, oauth2_config, params, &state).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(&tenant_id, oauth2_config, params, &state).await
        }
        "password" => handle_password_grant(&tenant_id, oauth2_config, params, &state).await,
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": format!("Grant type '{}' is not supported", params.grant_type)
            })),
        )),
    }
}

/// Logout Endpoint (OpenID Connect Session Management)
///
/// Supports both GET and POST methods for compatibility.
/// Provides front-channel logout with optional redirect.
///
/// Send back-channel logout notifications to all registered clients
/// This is called internally when a user logs out to notify all relying parties
async fn trigger_backchannel_logout(
    user_id: &str,
    session_id: Option<&str>,
    tenant: &Tenant,
    tenant_id: &str,
    state: &AppState,
) {
    // Get OAuth2 and OIDC config
    let oauth2_config = match &tenant.identity_provider.oauth2 {
        Some(config) => config,
        None => {
            debug!("OAuth2 not enabled for tenant, skipping backchannel logout");
            return;
        }
    };

    let oidc_config = match &tenant.identity_provider.oidc {
        Some(config) => config,
        None => {
            debug!("OIDC not enabled for tenant, skipping backchannel logout");
            return;
        }
    };

    // Get all clients for this tenant
    let clients = match state.storage.list_oauth2_clients(tenant_id).await {
        Ok(clients) => clients,
        Err(e) => {
            warn!("Failed to list OAuth2 clients for backchannel logout: {}", e);
            return;
        }
    };

    // Filter clients that have backchannel_logout_uri configured
    let logout_clients: Vec<_> = clients
        .into_iter()
        .filter(|client| client.backchannel_logout_uri.is_some())
        .collect();

    if logout_clients.is_empty() {
        debug!("No clients configured for backchannel logout");
        return;
    }

    info!(
        "Triggering backchannel logout for {} client(s)",
        logout_clients.len()
    );

    // Send logout notifications to all clients (in parallel)
    let mut tasks = vec![];

    for client in logout_clients {
        let logout_uri = match client.backchannel_logout_uri {
            Some(uri) => uri,
            None => continue,
        };

        // Check if session_id is required but not provided
        if client.backchannel_logout_session_required && session_id.is_none() {
            warn!(
                "Client '{}' requires session_id but none provided, skipping",
                client.client_id
            );
            continue;
        }

        // Generate logout token for this client
        let logout_token = match crate::auth::backchannel_logout::generate_logout_token(
            Some(user_id),
            session_id,
            &client.client_id,
            &oidc_config.issuer,
            oauth2_config,
        ) {
            Ok(token) => token,
            Err((_, json)) => {
                warn!(
                    "Failed to generate logout token for client '{}': {:?}",
                    client.client_id, json
                );
                continue;
            }
        };

        // Spawn async task to send notification
        let client_id = client.client_id.clone();
        tasks.push(tokio::spawn(async move {
            match crate::auth::backchannel_logout::notify_client_logout(&logout_uri, &logout_token)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully sent backchannel logout to client '{}'",
                        client_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to send backchannel logout to client '{}': {}",
                        client_id, e
                    );
                }
            }
        }));
    }

    // Wait for all notifications to complete (with timeout)
    for task in tasks {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
    }
}

/// POST /api/v1/tenant/{tenant_id}/oauth/logout
/// GET /api/v1/tenant/{tenant_id}/oauth/logout
#[utoipa::path(
    post,
    path = "/api/v1/tenant/{tenant_id}/oauth/logout",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier"),
        LogoutRequest
    ),
    responses(
        (status = 200, description = "Logout successful", body = LogoutResponse),
        (status = 302, description = "Redirect to post_logout_redirect_uri"),
        (status = 400, description = "Invalid request", body = serde_json::Value),
        (status = 404, description = "Tenant not found", body = serde_json::Value)
    ),
    tag = "OAuth2"
)]
pub async fn oauth2_logout(
    Path(tenant_id): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<LogoutRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!("Logout request for tenant '{}'", tenant_id);

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Extract user_id and session_id from ID token for backchannel logout
    let mut user_id_for_logout: Option<String> = None;
    let session_id_for_logout: Option<String> = None;

    // Validate ID token hint if provided
    if let Some(ref id_token_hint) = params.id_token_hint {
        // Decode the ID token to extract JTI for revocation
        // Parse JWT without full validation (we just need the JTI)
        let parts: Vec<&str> = id_token_hint.split('.').collect();
        if parts.len() == 3 {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            if let Ok(payload_bytes) = STANDARD.decode(parts[1]) {
                if let Ok(claims) = serde_json::from_slice::<crate::models::Claims>(&payload_bytes)
                {
                    // Extract user_id (sub) for backchannel logout
                    user_id_for_logout = Some(claims.sub.clone());
                    // TODO: Extract session_id (sid) if present in OIDC claims

                    // Revoke the token by its JTI
                    if let Some(jti) = claims.jti {
                        let expires_at = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(1));

                        match state.storage.revoke_token(&jti, expires_at).await {
                            Ok(_) => {
                                info!("Revoked token with JTI '{}' during logout", jti);
                            }
                            Err(e) => {
                                warn!("Failed to revoke token during logout: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    // If post_logout_redirect_uri is provided, validate and redirect
    if let Some(redirect_uri) = params.post_logout_redirect_uri {
        // Validate redirect_uri if we can identify the client from id_token_hint
        let mut is_valid = false;

        if let Some(ref id_token_hint) = params.id_token_hint {
            // Extract client_id from ID token
            let parts: Vec<&str> = id_token_hint.split('.').collect();
            if parts.len() == 3 {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                if let Ok(payload_bytes) = STANDARD.decode(parts[1]) {
                    if let Ok(claims) =
                        serde_json::from_slice::<crate::models::Claims>(&payload_bytes)
                    {
                        // Get client_id from aud claim
                        if let Some(aud) = claims.aud {
                            if let Some(client_id) = aud.first() {
                                // Retrieve client to check allowed redirect URIs
                                if let Ok(Some(client)) =
                                    state.storage.get_oauth2_client(client_id).await
                                {
                                    // Check if redirect_uri is in client's allowed list
                                    is_valid = client.redirect_uris.iter().any(|uri| {
                                        // Allow exact match or prefix match for flexibility
                                        redirect_uri.starts_with(uri)
                                    });

                                    if !is_valid {
                                        warn!(
                                            "Invalid post_logout_redirect_uri '{}' for client '{}'",
                                            redirect_uri, client_id
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // If we couldn't validate (no id_token_hint), allow for now but log warning
        if !is_valid && params.id_token_hint.is_none() {
            warn!(
                "No id_token_hint provided for logout redirect validation, allowing redirect to '{}'",
                redirect_uri
            );
            is_valid = true; // Allow for backward compatibility
        }

        if !is_valid && params.id_token_hint.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "Invalid post_logout_redirect_uri"
                })),
            ));
        }

        let mut redirect_url = redirect_uri.clone();

        // Add state parameter if provided
        if let Some(state_param) = params.state {
            redirect_url.push_str(if redirect_url.contains('?') { "&" } else { "?" });
            redirect_url.push_str(&format!("state={}", state_param));
        }

        info!("Redirecting after logout to: {}", redirect_url);

        // Trigger backchannel logout in background (non-blocking)
        if let Some(user_id) = user_id_for_logout {
            let state_clone = state.clone();
            let tenant_clone = tenant.clone();
            let tenant_id_clone = tenant_id.clone();
            let session_id_clone = session_id_for_logout.clone();
            tokio::spawn(async move {
                trigger_backchannel_logout(
                    &user_id,
                    session_id_clone.as_deref(),
                    &tenant_clone,
                    &tenant_id_clone,
                    &state_clone,
                )
                .await;
            });
        }

        return Ok(Redirect::temporary(&redirect_url).into_response());
    }

    // Trigger backchannel logout in background (non-blocking)
    if let Some(user_id) = user_id_for_logout {
        let state_clone = state.clone();
        let tenant_clone = tenant.clone();
        let tenant_id_clone = tenant_id.clone();
        let session_id_clone = session_id_for_logout.clone();
        tokio::spawn(async move {
            trigger_backchannel_logout(
                &user_id,
                session_id_clone.as_deref(),
                &tenant_clone,
                &tenant_id_clone,
                &state_clone,
            )
            .await;
        });
    }

    // Return JSON response if no redirect
    Ok(Json(LogoutResponse {
        message: "Logout successful".to_string(),
    })
    .into_response())
}

/// Handle authorization code grant
async fn handle_authorization_code_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
    state: &AppState,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let code = params.code.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "Missing code" })),
        )
    })?;

    let redirect_uri = params.redirect_uri.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_request", "error_description": "Missing redirect_uri" }),
            ),
        )
    })?;

    let client_id = params.client_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "Missing client_id" })),
        )
    })?;

    // Validate client if registered in storage
    let _client = validate_client(
        &client_id,
        params.client_secret.as_deref(),
        params.client_assertion_type.as_deref(),
        params.client_assertion.as_deref(),
        &redirect_uri,
        "authorization_code",
        tenant_id,
        state,
    )
    .await?;

    // Retrieve authorization code from storage
    let code_data = state
        .storage
        .get_authorization_code(&code)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve authorization code: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Storage error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_grant", "error_description": "Invalid authorization code" })),
            )
        })?;

    // Validate code hasn't expired
    let now = Utc::now();
    if now > code_data.expires_at {
        // Delete expired code
        let _ = state.storage.delete_authorization_code(&code).await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_grant", "error_description": "Authorization code expired" }),
            ),
        ));
    }

    // Validate redirect_uri matches
    if code_data.redirect_uri != redirect_uri {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant", "error_description": "Redirect URI mismatch" })),
        ));
    }

    // Validate PKCE (RFC 7636) if code_challenge was provided
    if let Some(code_challenge) = &code_data.code_challenge {
        let code_verifier = params.code_verifier.as_ref().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "code_verifier is required when PKCE was used"
                })),
            )
        })?;

        // Validate code_verifier against code_challenge
        let challenge_method = code_data
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");

        if !validate_pkce(code_verifier, code_challenge, challenge_method) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "PKCE validation failed"
                })),
            ));
        }
    }

    // Delete authorization code after use (one-time use)
    state
        .storage
        .delete_authorization_code(&code)
        .await
        .map_err(|e| {
            warn!("Failed to delete authorization code: {}", e);
            // Continue anyway - token generation is more important
        })
        .ok();

    // Parse scope from space-separated string to vector
    let scope_vec: Vec<String> = code_data
        .scope
        .split_whitespace()
        .map(String::from)
        .collect();

    // Get tenant configuration to access identity backend
    let tenant = state.config.get_tenant(tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Retrieve user from identity backend
    let user = get_user_from_backend(&code_data.user_id, tenant).map_err(|e| {
        warn!(
            "Failed to retrieve user '{}' from identity backend: {}",
            code_data.user_id, e
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to retrieve user information"
            })),
        )
    })?;

    info!(
        "Retrieved user from identity backend: {} ({})",
        user.id, user.email
    );

    // Generate tokens
    let access_token = generate_access_token(
        &user.id,
        &user.email,
        user.role,
        &scope_vec,
        tenant_id,
        &code_data.client_id,
        oauth2_config,
    )?;

    let refresh_token = if oauth2_config
        .grant_types
        .contains(&"refresh_token".to_string())
    {
        Some(
            generate_refresh_token(
                &user.id,
                &user.email,
                user.role,
                &scope_vec,
                tenant_id,
                &code_data.client_id,
                oauth2_config,
                state,
            )
            .await?,
        )
    } else {
        None
    };

    // Generate ID token if OIDC scope is requested
    let id_token = if scope_vec.contains(&"openid".to_string()) {
        // Check if OIDC is enabled for this tenant
        if let Some(oidc_config) = &tenant.identity_provider.oidc {
            debug!("Generating ID token for OIDC flow");

            if let Some(ref nonce) = code_data.nonce {
                debug!("Including nonce '{}' in ID token", nonce);
            }

            Some(crate::auth::oidc::generate_id_token(
                &user.id,
                &user.email,
                user.name.clone(),
                &code_data.client_id,
                code_data.nonce.clone(),
                oauth2_config,
                oidc_config,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token,
        scope: Some(code_data.scope),
        id_token,
    }))
}

/// Handle client credentials grant
async fn handle_client_credentials_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
    state: &AppState,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate client credentials
    let client_id = params.client_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "Missing client_id" })),
        )
    })?;

    let client_secret = params.client_secret.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_request", "error_description": "Missing client_secret" }),
            ),
        )
    })?;

    // Validate client if registered in storage
    // For client_credentials, we use a dummy redirect_uri as it's not required for this flow
    let _client = validate_client(
        &client_id,
        Some(&client_secret),
        params.client_assertion_type.as_deref(),
        params.client_assertion.as_deref(),
        "urn:ietf:wg:oauth:2.0:oob", // Out-of-band redirect for client credentials
        "client_credentials",
        tenant_id,
        state,
    )
    .await?;

    let scope = params
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>();

    // Generate access token for the client (not a user)
    let access_token = generate_access_token(
        "client",
        "client@system",
        UserRole::User,
        &scope,
        tenant_id,
        &client_id,
        oauth2_config,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token: None, // Client credentials don't get refresh tokens
        scope: Some(scope.join(" ")),
        id_token: None, // Client credentials don't get ID tokens
    }))
}

/// Handle refresh token grant
async fn handle_refresh_token_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
    state: &AppState,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let refresh_token = params.refresh_token.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_request", "error_description": "Missing refresh_token" }),
            ),
        )
    })?;

    // Retrieve refresh token data from storage
    let token_data = state
        .storage
        .get_refresh_token(&refresh_token)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve refresh token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Storage error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_grant", "error_description": "Invalid refresh token" })),
            )
        })?;

    // Validate token hasn't expired
    let now = Utc::now();
    if let Some(expires_at) = token_data.expires_at {
        if now > expires_at {
            // Delete expired token
            let _ = state.storage.delete_refresh_token(&refresh_token).await;
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": "invalid_grant", "error_description": "Refresh token expired" }),
                ),
            ));
        }
    }

    // Parse scope from space-separated string to vector
    let scope_vec: Vec<String> = token_data
        .scope
        .split_whitespace()
        .map(String::from)
        .collect();

    // Get tenant configuration to access identity backend
    let tenant = state.config.get_tenant(tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Retrieve user from identity backend
    let user = get_user_from_backend(&token_data.user_id, tenant).map_err(|e| {
        warn!(
            "Failed to retrieve user '{}' from identity backend during refresh: {}",
            token_data.user_id, e
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to retrieve user information"
            })),
        )
    })?;

    debug!(
        "Retrieved user from identity backend for token refresh: {} ({})",
        user.id, user.email
    );

    // Generate new access token with real user data
    let access_token = generate_access_token(
        &user.id,
        &user.email,
        user.role,
        &scope_vec,
        tenant_id,
        &token_data.client_id,
        oauth2_config,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token: Some(refresh_token), // Return the same refresh token
        scope: Some(token_data.scope),
        id_token: None, // ID tokens are only issued during initial authorization
    }))
}

/// Handle Resource Owner Password Credentials Grant (RFC 6749 Section 4.3)
///
/// WARNING: This grant type should ONLY be used by trusted first-party applications.
/// It requires the client to handle user credentials directly, which is generally
/// not recommended except for legacy applications or highly trusted scenarios.
///
/// Security considerations:
/// - Only enable for trusted clients
/// - All password grant attempts are logged for security monitoring
/// - Consider requiring additional authentication factors
/// - Rate limit this endpoint to prevent brute-force attacks
async fn handle_password_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
    state: &AppState,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Check if password grant is enabled for this tenant
    if !oauth2_config.password_grant_enabled {
        warn!(
            "Password grant attempted but disabled for tenant '{}'",
            tenant_id
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": "Password grant is disabled for this tenant"
            })),
        ));
    }

    // Extract and validate required parameters
    let username = params.username.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing username parameter"
            })),
        )
    })?;

    let password = params.password.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing password parameter"
            })),
        )
    })?;

    let client_id = params.client_id.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing client_id parameter"
            })),
        )
    })?;

    // Rate limiting for password grant (prevent brute-force attacks)
    let rate_limit_key = format!("password_grant:{}:{}", tenant_id, username);
    let max_attempts = 5; // Maximum 5 attempts
    let window_secs = 300; // Per 5 minutes

    // Check if rate limit exceeded
    if state
        .storage
        .check_rate_limit(&rate_limit_key, max_attempts, window_secs)
        .await
        .unwrap_or(false)
    {
        warn!(
            "Rate limit exceeded for password grant: tenant='{}', username='{}'",
            tenant_id, username
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limit_exceeded",
                "error_description": "Too many authentication attempts. Please try again later."
            })),
        ));
    }

    // Record this attempt
    let _ = state
        .storage
        .record_rate_limit_attempt(&rate_limit_key)
        .await;

    // Validate client
    let client = validate_client(
        client_id,
        params.client_secret.as_deref(),
        params.client_assertion_type.as_deref(),
        params.client_assertion.as_deref(),
        "urn:ietf:wg:oauth:2.0:oob", // Out-of-band redirect for password grant
        "password",
        tenant_id,
        state,
    )
    .await?;

    // Get tenant for identity backend access
    let tenant = state.config.get_tenant(tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "tenant_not_found"})),
        )
    })?;

    // Authenticate user via identity backend
    let backend = crate::auth::identity_backend::create_identity_backend(&tenant.identity_backend);
    let auth_result = backend.authenticate(&username, &password).map_err(|e| {
        warn!(
            "Password grant authentication failed for user '{}': {}",
            username, e
        );
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Invalid username or password"
            })),
        )
    })?;

    if !auth_result.success {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Invalid username or password"
            })),
        ));
    }

    // Parse requested scope
    let requested_scopes: Vec<String> = params
        .scope
        .clone()
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();

    // Validate scopes against client's allowed scopes
    if let Some(ref client_data) = client {
        if !client_data.allowed_scopes.is_empty() {
            for scope in &requested_scopes {
                if !client_data.allowed_scopes.contains(scope) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_scope",
                            "error_description": format!("Scope '{}' not allowed for this client", scope)
                        })),
                    ));
                }
            }
        }
    }

    let user = &auth_result.user;

    // Generate access token
    let access_token = generate_access_token(
        &user.id,
        &user.email,
        user.role,
        &requested_scopes,
        tenant_id,
        client_id,
        oauth2_config,
    )?;

    // Generate refresh token if supported
    let refresh_token = if oauth2_config
        .grant_types
        .contains(&"refresh_token".to_string())
    {
        Some(
            generate_refresh_token(
                &user.id,
                &user.email,
                user.role,
                &requested_scopes,
                tenant_id,
                client_id,
                oauth2_config,
                state,
            )
            .await?,
        )
    } else {
        None
    };

    info!("Password grant successful for user '{}'", username);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token,
        scope: Some(requested_scopes.join(" ")),
        id_token: None, // Password grant doesn't return ID token
    }))
}

/// Generate an access token (JWT)
pub fn generate_access_token(
    user_id: &str,
    email: &str,
    role: UserRole,
    scope: &[String],
    tenant_id: &str,
    client_id: &str,
    config: &OAuth2ServerConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp();
    let exp = now + config.access_token_expiration_secs;

    // Construct issuer URL from config or tenant
    let issuer = format!("/api/v1/tenant/{}", tenant_id);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        exp: exp as usize,
        iss: Some(issuer),
        aud: Some(vec![client_id.to_string()]),
        scope: Some(scope.join(" ")),
        tenant_id: Some(tenant_id.to_string()),
        azp: Some(client_id.to_string()),
        jti: Some(Uuid::new_v4().to_string()),
    };

    let algorithm = match config.signing_key.algorithm.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "error": "server_error", "error_description": "Unsupported algorithm" }),
                ),
            ));
        }
    };

    // Load private key from tenant configuration
    let private_key_pem = load_key_pem(&config.signing_key.private_key).map_err(|e| {
        warn!("Failed to load private key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load signing key" })),
        )
    })?;

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse private key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Invalid signing key format" })),
        )
    })?;

    let mut header = Header::new(algorithm);
    header.kid = Some(config.signing_key.kid.clone());

    encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode JWT: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "error": "server_error", "error_description": "Failed to generate token" }),
            ),
        )
    })
}

/// Generate a refresh token
async fn generate_refresh_token(
    user_id: &str,
    _email: &str,
    _role: UserRole,
    scope: &[String],
    tenant_id: &str,
    client_id: &str,
    config: &OAuth2ServerConfig,
    state: &AppState,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();

    let token_data = StorageRefreshTokenData {
        tenant_id: tenant_id.to_string(),
        client_id: client_id.to_string(),
        user_id: user_id.to_string(),
        scope: scope.join(" "),
        created_at: now,
        expires_at: Some(now + chrono::Duration::seconds(config.refresh_token_expiration_secs)),
    };

    // Store refresh token
    state
        .storage
        .store_refresh_token(&token, token_data)
        .await
        .map_err(|e| {
            warn!("Failed to store refresh token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Failed to store refresh token" })),
            )
        })?;

    Ok(token)
}

/// JWKS Endpoint - returns public keys for token verification
/// GET /api/v1/tenant/{tenant_id}/.well-known/jwks.json
#[utoipa::path(
    get,
    path = "/api/v1/tenant/{tenant_id}/.well-known/jwks.json",
    params(
        ("tenant_id" = String, Path, description = "Tenant identifier")
    ),
    responses(
        (status = 200, description = "JSON Web Key Set", body = serde_json::Value),
        (status = 400, description = "OAuth2 not enabled", body = serde_json::Value),
        (status = 404, description = "Tenant not found", body = serde_json::Value)
    ),
    tag = "OAuth2"
)]
pub async fn jwks(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!("JWKS request for tenant '{}'", tenant_id);

    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    // Load public key and convert to JWK format
    let public_key_pem = load_key_pem(&oauth2_config.signing_key.public_key).map_err(|e| {
        warn!("Failed to load public key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load public key" })),
        )
    })?;

    let jwk = convert_rsa_public_key_to_jwk(
        &public_key_pem,
        &oauth2_config.signing_key.kid,
        &oauth2_config.signing_key.algorithm,
    )
    .map_err(|e| {
        warn!("Failed to convert public key to JWK: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Invalid public key format" })),
        )
    })?;

    Ok(Json(json!({
        "keys": [jwk]
    })))
}

/// Load a key from either a file path or inline PEM
fn load_key_pem(key_config: &str) -> Result<String, String> {
    // Check if it's a file path or inline PEM
    if key_config.starts_with("-----BEGIN") {
        // Inline PEM
        Ok(key_config.to_string())
    } else {
        // File path - try to read it
        std::fs::read_to_string(key_config)
            .map_err(|e| format!("Failed to read key file '{}': {}", key_config, e))
    }
}

/// Convert RSA public key PEM to JWK format
fn convert_rsa_public_key_to_jwk(
    pem: &str,
    kid: &str,
    alg: &str,
) -> Result<serde_json::Value, String> {
    // Validate that the PEM can be parsed as an RSA public key
    DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;

    // Extract the RSA components (modulus n and exponent e) from PEM
    match extract_rsa_components_from_pem(pem) {
        Ok((n, e)) => Ok(json!({
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": alg,
            "n": n,
            "e": e
        })),
        Err(e) => Err(format!("Failed to extract RSA components: {}", e)),
    }
}

/// Extract RSA modulus (n) and exponent (e) from PEM format
fn extract_rsa_components_from_pem(pem: &str) -> Result<(String, String), String> {
    // Parse PEM format
    let pem_lines: Vec<&str> = pem.lines().collect();

    if pem_lines.is_empty() {
        return Err("Empty PEM string".to_string());
    }

    // Find the base64 content between headers
    let start_idx = pem_lines
        .iter()
        .position(|line| line.starts_with("-----BEGIN"))
        .ok_or("Missing BEGIN header")?;

    let end_idx = pem_lines
        .iter()
        .position(|line| line.starts_with("-----END"))
        .ok_or("Missing END header")?;

    if end_idx <= start_idx {
        return Err("Invalid PEM structure".to_string());
    }

    // Concatenate base64 content
    let base64_content: String = pem_lines[(start_idx + 1)..end_idx]
        .iter()
        .map(|s| s.trim())
        .collect();

    // Decode base64
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let der_bytes = STANDARD
        .decode(&base64_content)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Parse DER format (ASN.1) to extract n and e
    // This is a simplified parser for RSA public keys in SubjectPublicKeyInfo format
    parse_rsa_public_key_der(&der_bytes)
}

/// Parse DER-encoded RSA public key to extract modulus (n) and exponent (e)
fn parse_rsa_public_key_der(der: &[u8]) -> Result<(String, String), String> {
    // RSA public key in SubjectPublicKeyInfo format (PKCS#1 wrapped in PKCS#8)
    // We need to extract the modulus (n) and exponent (e)

    // This is a very simplified DER parser for RSA keys
    // In production, you should use a proper ASN.1 parser like the `rsa` or `x509-parser` crate

    // For now, let's look for the RSA public key sequence
    // The structure is roughly:
    // SEQUENCE {
    //   SEQUENCE { algorithm, parameters }
    //   BIT STRING { RSAPublicKey }
    // }
    // Where RSAPublicKey is:
    // SEQUENCE {
    //   modulus INTEGER,
    //   publicExponent INTEGER
    // }

    // Find the BIT STRING containing the RSA public key
    let mut i = 0;
    let len = der.len();

    // Skip the outer SEQUENCE and inner SEQUENCE (algorithm identifier)
    while i < len - 10 {
        if der[i] == 0x03 {
            // BIT STRING tag
            i += 1;

            // Get length
            let bit_string_len = if der[i] & 0x80 == 0 {
                let l = der[i] as usize;
                i += 1;
                l
            } else {
                let num_bytes = (der[i] & 0x7f) as usize;
                i += 1;
                let mut l = 0usize;
                for _ in 0..num_bytes {
                    l = (l << 8) | der[i] as usize;
                    i += 1;
                }
                l
            };

            // Skip unused bits byte
            if i < len && bit_string_len > 0 {
                i += 1;

                // Now we should have the RSA public key SEQUENCE
                if i < len && der[i] == 0x30 {
                    // SEQUENCE tag
                    i += 1;

                    // Skip sequence length
                    if der[i] & 0x80 == 0 {
                        i += 1;
                    } else {
                        let num_bytes = (der[i] & 0x7f) as usize;
                        i += 1 + num_bytes;
                    }

                    // Now parse the modulus INTEGER
                    if i < len && der[i] == 0x02 {
                        i += 1;

                        let (n_bytes, new_i) = read_der_integer(der, i)?;
                        i = new_i;

                        // Parse the exponent INTEGER
                        if i < len && der[i] == 0x02 {
                            i += 1;

                            let (e_bytes, _) = read_der_integer(der, i)?;

                            // Convert to base64url
                            let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
                            let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

                            return Ok((n_b64, e_b64));
                        }
                    }
                }
            }
        }
        i += 1;
    }

    Err("Could not parse RSA public key DER format".to_string())
}

/// Read a DER INTEGER value
fn read_der_integer(der: &[u8], mut i: usize) -> Result<(Vec<u8>, usize), String> {
    let len = der.len();

    // Get length
    let int_len = if i < len && der[i] & 0x80 == 0 {
        let l = der[i] as usize;
        i += 1;
        l
    } else if i < len {
        let num_bytes = (der[i] & 0x7f) as usize;
        i += 1;
        let mut l = 0usize;
        for _ in 0..num_bytes {
            if i >= len {
                return Err("Truncated DER integer".to_string());
            }
            l = (l << 8) | der[i] as usize;
            i += 1;
        }
        l
    } else {
        return Err("Truncated DER integer".to_string());
    };

    if i + int_len > len {
        return Err("DER integer length exceeds buffer".to_string());
    }

    // Skip leading zero byte if present (used for positive integers with high bit set)
    let start = if int_len > 0 && der[i] == 0x00 {
        i + 1
    } else {
        i
    };
    let end = i + int_len;

    let bytes = der[start..end].to_vec();
    Ok((bytes, end))
}

/// Validate PKCE code_verifier against code_challenge (RFC 7636)
fn validate_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    match method {
        "plain" => {
            // Plain method: verifier must equal challenge
            code_verifier == code_challenge
        }
        "S256" => {
            // S256 method: BASE64URL(SHA256(verifier)) must equal challenge
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let hash = hasher.finalize();
            let computed_challenge = URL_SAFE_NO_PAD.encode(hash);

            computed_challenge == code_challenge
        }
        _ => {
            // Unknown method
            warn!("Unknown PKCE method: {}", method);
            false
        }
    }
}

/// Get user from identity backend by user_id
fn get_user_from_backend(user_id: &str, tenant: &Tenant) -> Result<BackendUser, BackendError> {
    let backend = create_identity_backend(&tenant.identity_backend);
    backend.get_user_by_id(user_id)
}

/// Validate JWT-based client authentication (RFC 7523)
async fn validate_client_assertion(
    client_id: &str,
    assertion: &str,
    tenant_id: &str,
    state: &AppState,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    // Get client to retrieve public key or secret
    let client = state
        .storage
        .get_oauth2_client(client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve client for assertion validation: {}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Client authentication failed"
                })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Unknown client"
                })),
            )
        })?;

    // Decode JWT header to determine algorithm
    let header = decode_header(assertion).map_err(|e| {
        warn!(
            "Failed to decode JWT header for client '{}': {}",
            client_id, e
        );
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "Invalid JWT format"
            })),
        )
    })?;

    // Determine algorithm and create appropriate decoding key
    let (algorithm, decoding_key) = match header.alg {
        Algorithm::HS256 => {
            // HMAC with client_secret
            let client_secret = client.client_secret.as_ref().ok_or_else(|| {
                warn!("Client '{}' has no secret for HS256 JWT validation", client_id);
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Client has no secret configured for HS256 assertion"
                    })),
                )
            })?;
            (
                Algorithm::HS256,
                DecodingKey::from_secret(client_secret.as_bytes()),
            )
        }
        Algorithm::RS256 => {
            // RSA signature with public key
            let public_key_pem = client.public_key_pem.as_ref().ok_or_else(|| {
                warn!(
                    "Client '{}' has no public key for RS256 JWT validation",
                    client_id
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Client has no public key configured for RS256 assertion"
                    })),
                )
            })?;

            let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
                warn!(
                    "Failed to parse RSA public key for client '{}': {}",
                    client_id, e
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Invalid RSA public key format"
                    })),
                )
            })?;
            (Algorithm::RS256, key)
        }
        Algorithm::ES256 => {
            // ECDSA signature with public key
            let public_key_pem = client.public_key_pem.as_ref().ok_or_else(|| {
                warn!(
                    "Client '{}' has no public key for ES256 JWT validation",
                    client_id
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Client has no public key configured for ES256 assertion"
                    })),
                )
            })?;

            let key = DecodingKey::from_ec_pem(public_key_pem.as_bytes()).map_err(|e| {
                warn!(
                    "Failed to parse EC public key for client '{}': {}",
                    client_id, e
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Invalid EC public key format"
                    })),
                )
            })?;
            (Algorithm::ES256, key)
        }
        other => {
            warn!(
                "Unsupported JWT algorithm '{:?}' for client '{}'",
                other, client_id
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": format!("Unsupported algorithm: {:?}", other)
                })),
            ));
        }
    };

    // Create validation configuration
    let mut validation = Validation::new(algorithm);
    // Set expected audience (token endpoint)
    validation.set_audience(&[format!("/api/v1/tenant/{}/oauth/token", tenant_id)]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub", "aud", "jti"]);

    // Decode and validate JWT
    let token_data = decode::<ClientAssertionClaims>(assertion, &decoding_key, &validation)
        .map_err(|e| {
            warn!(
                "JWT assertion validation failed for client '{}' with {:?}: {}",
                client_id, algorithm, e
            );
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": format!("JWT assertion validation failed: {}", e)
                })),
            )
        })?;

    let claims = token_data.claims;

    // Validate issuer matches client_id (RFC 7523 Section 3)
    if claims.iss != client_id {
        warn!(
            "JWT assertion iss '{}' does not match client_id '{}'",
            claims.iss, client_id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "JWT assertion issuer does not match client_id"
            })),
        ));
    }

    // Validate subject matches client_id (RFC 7523 Section 3)
    if claims.sub != client_id {
        warn!(
            "JWT assertion sub '{}' does not match client_id '{}'",
            claims.sub, client_id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "JWT assertion subject does not match client_id"
            })),
        ));
    }

    // Check for JWT replay using JTI
    let jti = &claims.jti;

    // Check if this JTI has been used before
    if let Ok(true) = state.storage.is_token_revoked(jti).await {
        warn!(
            "JWT assertion with JTI '{}' has already been used (replay attack)",
            jti
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "JWT assertion has already been used"
            })),
        ));
    }

    // Store JTI to prevent replay attacks
    // Mark it as "used" by revoking it with expiration time from the JWT
    let exp_time = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::minutes(5));

    if let Err(e) = state.storage.revoke_token(jti, exp_time).await {
        warn!("Failed to store JTI for replay prevention: {}", e);
        // Continue anyway - don't fail the request
    }

    info!(
        "Client '{}' successfully authenticated via JWT assertion",
        client_id
    );
    Ok(())
}

/// Validate OAuth2 client (optional - returns Ok with client data if client exists in storage)
/// This allows the system to work without client registration while still supporting it when configured
///
/// Now supports JWT-based client authentication (RFC 7523) via client_assertion parameters
async fn validate_client(
    client_id: &str,
    client_secret: Option<&str>,
    client_assertion_type: Option<&str>,
    client_assertion: Option<&str>,
    redirect_uri: &str,
    grant_type: &str,
    tenant_id: &str,
    state: &AppState,
) -> Result<Option<crate::storage::OAuth2ClientData>, (StatusCode, Json<serde_json::Value>)> {
    // Get client from storage
    let client_opt = state
        .storage
        .get_oauth2_client(client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve OAuth2 client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Storage error" })),
            )
        })?;

    // If no client is registered, skip validation (allow unregistered clients for now)
    // This enables testing without client registration but still validates when clients exist
    let client = match client_opt {
        Some(c) => c,
        None => {
            debug!(
                "OAuth2 client '{}' not registered in storage, skipping validation",
                client_id
            );
            return Ok(None);
        }
    };

    // Check if client is active
    if !client.active {
        warn!("OAuth2 client '{}' is not active", client_id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "Client is not active"
            })),
        ));
    }

    // Handle JWT-based client authentication (RFC 7523)
    if let Some(assertion_type) = client_assertion_type {
        if assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            if let Some(assertion) = client_assertion {
                validate_client_assertion(client_id, assertion, tenant_id, state).await?;
                info!("Client '{}' authenticated via JWT assertion", client_id);
                // JWT assertion is sufficient - skip secret validation and continue with other checks
            } else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "client_assertion is required when client_assertion_type is provided"
                    })),
                ));
            }
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": format!("Unsupported client_assertion_type: {}", assertion_type)
                })),
            ));
        }
    } else if client.client_type == crate::storage::OAuth2ClientType::Confidential {
        // Validate client secret for confidential clients (only if not using JWT assertion)
        let provided_secret = client_secret.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Client secret required for confidential clients"
                })),
            )
        })?;

        let stored_secret = client.client_secret.as_ref().ok_or_else(|| {
            warn!("Confidential client '{}' has no stored secret", client_id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Client configuration error"
                })),
            )
        })?;

        if provided_secret != stored_secret {
            warn!("Invalid client secret for client '{}'", client_id);
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "Invalid client secret"
                })),
            ));
        }
    }

    // Validate grant type is allowed for this client
    if !client.grant_types.contains(&grant_type.to_string()) {
        warn!(
            "Grant type '{}' not allowed for client '{}'",
            grant_type, client_id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized_client",
                "error_description": format!("Grant type '{}' not allowed for this client", grant_type)
            })),
        ));
    }

    // Validate redirect_uri is in client's allowed list
    if !client.redirect_uris.contains(&redirect_uri.to_string()) {
        warn!(
            "Redirect URI '{}' not allowed for client '{}'",
            redirect_uri, client_id
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Redirect URI not allowed for this client"
            })),
        ));
    }

    Ok(Some(client))
}

/// Validate requested scopes against client's allowed scopes
///
/// This function is available for use when scope validation is needed.
/// It can be integrated into the authorize and token endpoints when
/// fine-grained scope control is required.
#[allow(dead_code)]
fn validate_scopes(
    requested_scopes: &[String],
    allowed_scopes: &[String],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for scope in requested_scopes {
        if !allowed_scopes.contains(scope) {
            warn!("Scope '{}' not allowed", scope);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_scope",
                    "error_description": format!("Scope '{}' not allowed", scope)
                })),
            ));
        }
    }

    Ok(())
}

/// Validate PKCE parameters for public clients
///
/// This function ensures public clients use PKCE with S256 method for enhanced security.
/// It can be integrated into validate_client to enforce PKCE requirements.
#[allow(dead_code)]
fn validate_pkce_for_public_client(
    client_type: &crate::storage::OAuth2ClientType,
    code_challenge: &Option<String>,
    code_challenge_method: &Option<String>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Public clients must use PKCE with S256 method
    if *client_type == crate::storage::OAuth2ClientType::Public {
        if code_challenge.is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "PKCE required for public clients"
                })),
            ));
        }

        let method = code_challenge_method.as_deref().unwrap_or("plain");
        if method != "S256" {
            warn!("Public client must use S256 PKCE method, got: {}", method);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "Public clients must use S256 PKCE method"
                })),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_plain() {
        let verifier = "test-verifier-123";
        let challenge = "test-verifier-123";
        assert!(validate_pkce(verifier, challenge, "plain"));

        let wrong_challenge = "wrong-challenge";
        assert!(!validate_pkce(verifier, wrong_challenge, "plain"));
    }

    #[test]
    fn test_pkce_s256() {
        // Test vector from RFC 7636
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(validate_pkce(verifier, challenge, "S256"));

        let wrong_challenge = "wrong-challenge";
        assert!(!validate_pkce(verifier, wrong_challenge, "S256"));
    }

    #[test]
    fn test_pkce_unknown_method() {
        assert!(!validate_pkce("verifier", "challenge", "unknown"));
    }

    // JWT Client Assertion Tests

    #[test]
    fn test_client_assertion_claims_serialization() {
        let claims = ClientAssertionClaims {
            iss: "test-client".to_string(),
            sub: "test-client".to_string(),
            aud: "/api/v1/tenant/demo/oauth/token".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("test-client"));
        assert!(json.contains("/api/v1/tenant/demo/oauth/token"));
    }

    #[test]
    fn test_client_assertion_claims_deserialization() {
        let json = r#"{
            "iss": "test-client",
            "sub": "test-client",
            "aud": "/api/v1/tenant/demo/oauth/token",
            "exp": 1234567890,
            "iat": 1234560000,
            "jti": "unique-id-123"
        }"#;

        let claims: ClientAssertionClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.iss, "test-client");
        assert_eq!(claims.sub, "test-client");
        assert_eq!(claims.aud, "/api/v1/tenant/demo/oauth/token");
        assert_eq!(claims.jti, "unique-id-123");
    }

    #[tokio::test]
    async fn test_validate_client_assertion_valid_jwt() {
        // This test verifies JWT generation for client assertions
        let client_secret = "test-secret-key-123";
        let client_id = "test-client";
        let tenant_id = "demo";

        let claims = ClientAssertionClaims {
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            aud: format!("/api/v1/tenant/{}/oauth/token", tenant_id),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let encoding_key = EncodingKey::from_secret(client_secret.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key).unwrap();

        // Verify token was created
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3); // JWT has 3 parts
    }

    #[test]
    fn test_client_assertion_claims_validation_issuer_mismatch() {
        // Test that iss and client_id mismatch is detected
        let claims = ClientAssertionClaims {
            iss: "different-client".to_string(),
            sub: "test-client".to_string(),
            aud: "/api/v1/tenant/demo/oauth/token".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        // Verify iss doesn't match sub
        assert_ne!(claims.iss, claims.sub);
    }

    #[test]
    fn test_client_assertion_claims_expiration() {
        let now = chrono::Utc::now();
        let expired_time = (now - chrono::Duration::hours(1)).timestamp() as usize;
        let future_time = (now + chrono::Duration::hours(1)).timestamp() as usize;

        let expired_claims = ClientAssertionClaims {
            iss: "test-client".to_string(),
            sub: "test-client".to_string(),
            aud: "/api/v1/tenant/demo/oauth/token".to_string(),
            exp: expired_time,
            iat: expired_time - 60,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let valid_claims = ClientAssertionClaims {
            iss: "test-client".to_string(),
            sub: "test-client".to_string(),
            aud: "/api/v1/tenant/demo/oauth/token".to_string(),
            exp: future_time,
            iat: now.timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        // Verify expiration times
        assert!(expired_claims.exp < now.timestamp() as usize);
        assert!(valid_claims.exp > now.timestamp() as usize);
    }

    // Logout Request/Response Tests

    #[test]
    fn test_logout_request_deserialization_full() {
        let json = r#"{
            "id_token_hint": "eyJhbGc...",
            "post_logout_redirect_uri": "https://app.example.com/goodbye",
            "state": "xyz123"
        }"#;

        let req: LogoutRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id_token_hint, Some("eyJhbGc...".to_string()));
        assert_eq!(
            req.post_logout_redirect_uri,
            Some("https://app.example.com/goodbye".to_string())
        );
        assert_eq!(req.state, Some("xyz123".to_string()));
    }

    #[test]
    fn test_logout_request_deserialization_minimal() {
        let json = r#"{}"#;

        let req: LogoutRequest = serde_json::from_str(json).unwrap();
        assert!(req.id_token_hint.is_none());
        assert!(req.post_logout_redirect_uri.is_none());
        assert!(req.state.is_none());
    }

    #[test]
    fn test_logout_request_with_only_redirect_uri() {
        let json = r#"{
            "post_logout_redirect_uri": "https://app.example.com"
        }"#;

        let req: LogoutRequest = serde_json::from_str(json).unwrap();
        assert!(req.id_token_hint.is_none());
        assert_eq!(
            req.post_logout_redirect_uri,
            Some("https://app.example.com".to_string())
        );
        assert!(req.state.is_none());
    }

    #[test]
    fn test_logout_response_serialization() {
        let response = LogoutResponse {
            message: "Logout successful".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Logout successful"));
        assert!(json.contains("message"));
    }

    // Token Request with Assertion Fields Tests

    #[test]
    fn test_token_request_with_password_grant_fields() {
        let json = r#"{
            "grant_type": "password",
            "username": "user@example.com",
            "password": "secret123",
            "client_id": "my-client",
            "scope": "openid profile"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "password");
        assert_eq!(req.username, Some("user@example.com".to_string()));
        assert_eq!(req.password, Some("secret123".to_string()));
        assert_eq!(req.client_id, Some("my-client".to_string()));
    }

    #[test]
    fn test_token_request_with_client_assertion() {
        let json = r#"{
            "grant_type": "client_credentials",
            "client_id": "my-service",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "client_credentials");
        assert_eq!(
            req.client_assertion_type,
            Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string())
        );
        assert!(req.client_assertion.is_some());
    }

    #[test]
    fn test_token_request_without_optional_fields() {
        let json = r#"{
            "grant_type": "authorization_code",
            "code": "auth_code_123",
            "redirect_uri": "https://app.example.com/callback"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.username.is_none());
        assert!(req.password.is_none());
        assert!(req.client_assertion_type.is_none());
        assert!(req.client_assertion.is_none());
    }
}
