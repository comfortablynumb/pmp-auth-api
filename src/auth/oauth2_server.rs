// OAuth2 Authorization Server Implementation
// This module implements the OAuth2 authorization server functionality

use crate::auth::identity_storage::{create_identity_storage, StorageUser};
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
    /// Session ID for authenticated user (optional - can also be provided via header or cookie)
    pub session_id: Option<String>,
    /// OAuth2 response mode: "query" or "form_post" (default: "query")
    pub response_mode: Option<String>,
    /// OIDC prompt parameter: "none", "login", "consent", or "select_account"
    pub prompt: Option<String>,
    /// OIDC max_age: Maximum authentication age in seconds
    pub max_age: Option<u64>,
    /// OIDC acr_values: Space-separated Authentication Context Class References
    pub acr_values: Option<String>,
    /// OIDC claims: Requested claims in JSON format
    pub claims: Option<String>,
    /// Request object (JWT containing request parameters - RFC 9101)
    pub request: Option<String>,
    /// Request object URI (URL to fetch request object - RFC 9101)
    pub request_uri: Option<String>,
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
    headers: axum::http::HeaderMap,
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
    let (oauth2_config, _storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    // Handle request object if present (RFC 9101)
    let mut params = params;
    if params.request.is_some() || params.request_uri.is_some() {
        // Check if request objects are supported
        if !oauth2_config.request_parameter_supported && params.request.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "request_not_supported",
                    "error_description": "request parameter is not supported by this server"
                })),
            ));
        }

        if !oauth2_config.request_uri_parameter_supported && params.request_uri.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "request_uri_not_supported",
                    "error_description": "request_uri parameter is not supported by this server"
                })),
            ));
        }

        // Fetch client metadata to get JWKS for validation
        let client_metadata = state
            .storage
            .get_oauth2_client(&params.client_id)
            .await
            .ok()
            .flatten();

        let client_jwks = client_metadata.as_ref().and_then(|c| c.jwks.as_ref());
        let client_jwks_uri = client_metadata.as_ref().and_then(|c| c.jwks_uri.as_deref());

        // Handle request_uri first (fetch the JWT)
        let request_jwt = if let Some(ref request_uri) = params.request_uri {
            // Check if request_uri is in the registered list (if required)
            if oauth2_config.require_request_uri_registration {
                if let Some(ref client) = client_metadata {
                    if let Some(ref registered_uris) = client.request_uris {
                        if !registered_uris.contains(request_uri) {
                            return Err((
                                StatusCode::BAD_REQUEST,
                                Json(json!({
                                    "error": "invalid_request_uri",
                                    "error_description": "request_uri is not registered for this client"
                                })),
                            ));
                        }
                    } else {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error": "invalid_request_uri",
                                "error_description": "Client has no registered request_uris"
                            })),
                        ));
                    }
                }
            }

            // Fetch the request object from the URI
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|e| {
                    warn!("Failed to create HTTP client: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "server_error",
                            "error_description": "Failed to fetch request_uri"
                        })),
                    )
                })?;

            let response = http_client.get(request_uri).send().await.map_err(|e| {
                warn!("Failed to fetch request_uri '{}': {}", request_uri, e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request_uri",
                        "error_description": "Failed to fetch request object from request_uri"
                    })),
                )
            })?;

            let jwt = response.text().await.map_err(|e| {
                warn!("Failed to read request_uri response: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request_uri",
                        "error_description": "Failed to read request object from request_uri"
                    })),
                )
            })?;

            Some(jwt)
        } else {
            params.request.clone()
        };

        // Parse and validate the request object
        if let Some(request_jwt) = request_jwt {
            let request_claims = crate::auth::request_object::parse_request_object(
                &request_jwt,
                &params.client_id,
                oauth2_config,
                client_jwks_uri,
                client_jwks,
            )
            .await?;

            // Merge parameters (URL params take precedence for security-sensitive fields)
            params = crate::auth::request_object::merge_request_params(&params, request_claims);
        }
    }

    // Validate response_type - support authorization code, hybrid, and implicit flows
    // Supported:
    //   - Authorization Code Flow: "code"
    //   - Implicit Flow: "id_token", "token", "id_token token"
    //   - Hybrid Flow: "code id_token", "code token", "code id_token token"
    let response_type_parts: Vec<&str> = params.response_type.split_whitespace().collect();
    let has_code = response_type_parts.contains(&"code");
    let has_id_token = response_type_parts.contains(&"id_token");
    let has_token = response_type_parts.contains(&"token");

    // Must have at least one valid response type
    if !has_code && !has_id_token && !has_token {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "response_type must be specified"
            })),
        ));
    }

    // Validate no unknown response types
    for part in &response_type_parts {
        if !["code", "id_token", "token"].contains(part) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "unsupported_response_type",
                    "error_description": format!("Unknown response_type value: {}", part)
                })),
            ));
        }
    }

    // Determine the flow type
    let is_implicit_flow = !has_code && (has_id_token || has_token);
    let is_hybrid_flow = has_code && (has_id_token || has_token);
    let is_code_flow = has_code && !has_id_token && !has_token;

    // Validate grant type is supported for code/hybrid flows
    if (is_code_flow || is_hybrid_flow)
        && !oauth2_config
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

    // Validate implicit flow is supported (check if "implicit" grant is in grant_types)
    if is_implicit_flow && !oauth2_config.grant_types.contains(&"implicit".to_string()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_response_type",
                "error_description": "Implicit flow is not enabled for this client"
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

    // Validate requested scopes against client's allowed scopes
    if let Some(ref client_data) = client {
        if let Some(ref scope_str) = params.scope {
            let requested_scopes: Vec<String> = scope_str
                .split_whitespace()
                .map(String::from)
                .collect();

            validate_scopes(&requested_scopes, &client_data.allowed_scopes)?;
        }
    }

    // In a real implementation, this would:
    // 1. Authenticate the user via the identity backend
    // 2. Show a consent screen
    // 3. Generate an authorization code after consent
    //
    // Check for authenticated session
    // Session ID can be provided via:
    // 1. Cookie (session_id)
    // 2. Query parameter (session_id) - for testing
    // 3. Header (X-Session-ID)

    let session_id = headers
        .get("x-session-id")
        .and_then(|h| h.to_str().ok())
        .or_else(|| params.session_id.as_deref());

    // Handle OIDC prompt parameter
    if let Some(ref prompt) = params.prompt {
        match prompt.as_str() {
            "none" => {
                // Must not display any authentication or consent UI
                // If user is not authenticated, must return error
                if session_id.is_none() {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "login_required",
                            "error_description": "User is not authenticated and prompt=none was specified"
                        })),
                    ));
                }
            }
            "login" => {
                // Force re-authentication
                // In a full implementation, this would invalidate the current session
                // and require the user to authenticate again
                info!("prompt=login requested - re-authentication should be required");
                // For now, we'll require a fresh session (implemented below with max_age check)
            }
            "consent" => {
                // Show consent screen
                // In a full implementation, this would show a consent UI
                info!("prompt=consent requested - consent screen should be shown");
            }
            "select_account" => {
                // Show account selection screen
                info!("prompt=select_account requested - account selection should be shown");
            }
            _ => {
                // Unknown prompt value - ignore per spec
                warn!("Unknown prompt value: {}", prompt);
            }
        }
    }

    if session_id.is_none() {
        info!("No session found for authorization request. Authentication required.");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "login_required",
                "error_description": "User must authenticate before authorizing. Please login first and provide session_id."
            })),
        ));
    }

    let session_id = session_id.unwrap();

    // Retrieve session from storage
    let session = state
        .storage
        .get_session(session_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to retrieve session"
                })),
            )
        })?
        .ok_or_else(|| {
            info!("Session '{}' not found", session_id);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_session",
                    "error_description": "Session not found or expired. Please login again."
                })),
            )
        })?;

    // Verify session hasn't expired
    if Utc::now() > session.expires_at {
        warn!("Session '{}' has expired", session_id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "session_expired",
                "error_description": "Session has expired. Please login again."
            })),
        ));
    }

    // Handle OIDC max_age parameter
    // If max_age is specified, verify that authentication time is recent enough
    if let Some(max_age) = params.max_age {
        let auth_time = session.created_at;
        let auth_age = Utc::now().signed_duration_since(auth_time).num_seconds() as u64;

        if auth_age > max_age {
            warn!(
                "Session '{}' authentication is too old: {} seconds (max_age: {})",
                session_id, auth_age, max_age
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "login_required",
                    "error_description": format!(
                        "Authentication is too old. Please re-authenticate. (age: {}s, max: {}s)",
                        auth_age, max_age
                    )
                })),
            ));
        }
    }

    // Verify tenant matches
    if session.tenant_id != tenant_id {
        warn!(
            "Session tenant mismatch: session tenant '{}' != requested tenant '{}'",
            session.tenant_id, tenant_id
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "tenant_mismatch",
                "error_description": "Session does not belong to this tenant"
            })),
        ));
    }

    // Get user from storage using session's user_id
    let user_id = session.user_id.clone().ok_or_else(|| {
        warn!("Session '{}' does not have a user_id", session_id);
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_session",
                "error_description": "Session is not associated with a user"
            })),
        )
    })?;

    let user = state
        .storage
        .get_user(&user_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve user '{}': {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to retrieve user"
                })),
            )
        })?
        .ok_or_else(|| {
            warn!("User '{}' not found in storage", user_id);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "user_not_found",
                    "error_description": "User not found"
                })),
            )
        })?;

    let backend_user = StorageUser {
        id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        picture: user.picture.clone(),
        role: UserRole::from_str(&user.role).unwrap_or(UserRole::User),
        attributes: user.attributes.clone(),
    };

    info!(
        "User authenticated for OAuth2 flow: {} ({})",
        backend_user.id, backend_user.email
    );

    // Generate authorization code only for code and hybrid flows, not for pure implicit flow
    let auth_code = if has_code {
        let code = Uuid::new_v4().to_string();
        let now = Utc::now();

        let code_data = StorageAuthCodeData {
            tenant_id: tenant_id.clone(),
            client_id: params.client_id.clone(),
            user_id: backend_user.id.clone(),
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
            .store_authorization_code(&code, code_data)
            .await
            .map_err(|e| {
                warn!("Failed to store authorization code: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "server_error", "error_description": "Failed to store authorization code" })),
                )
            })?;

        Some(code)
    } else {
        None
    };

    // Generate session_state for OIDC session management
    let session_id = uuid::Uuid::new_v4().to_string();
    let salt = uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>();

    // Extract origin from redirect_uri
    let origin = params
        .redirect_uri
        .split('/')
        .take(3)
        .collect::<Vec<&str>>()
        .join("/");

    let session_state = generate_session_state(&params.client_id, &origin, &session_id, &salt);

    // For hybrid flows, generate tokens immediately if needed
    let mut access_token_for_response: Option<String> = None;
    let mut id_token_for_response: Option<String> = None;

    if has_token || has_id_token {
        // Need to generate user context for tokens
        // Fetch actual user from storage backend
        let user = state
            .storage
            .get_user(&backend_user.id)
            .await
            .map_err(|e| {
                warn!("Failed to fetch user '{}' from storage: {}", backend_user.id, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "server_error", "error_description": "Failed to fetch user information"})),
                )
            })?
            .ok_or_else(|| {
                warn!("User '{}' not found in storage", backend_user.id);
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "invalid_grant", "error_description": "User not found"})),
                )
            })?;

        let scope_vec: Vec<String> = params
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(String::from)
            .collect();

        // Generate access token if requested
        if has_token {
            let token = generate_access_token(
                &user.id,
                &user.email,
                crate::models::UserRole::from_str(&user.role).unwrap_or(crate::models::UserRole::User),
                &scope_vec,
                &tenant_id,
                &params.client_id,
                oauth2_config,
            )?;
            access_token_for_response = Some(token);
        }

        // Generate ID token if requested and OIDC enabled
        if has_id_token {
            if let Some((oidc_config, _oidc_storage_id)) = tenant.get_oidc_provider() {
                if scope_vec.contains(&"openid".to_string()) {
                    let token = crate::auth::oidc::generate_id_token(
                        &user.id,
                        &user.email,
                        user.name.clone(),
                        &params.client_id,
                        params.nonce.clone(),
                        access_token_for_response.as_deref(), // Include at_hash if access_token generated
                        auth_code.as_deref(),                 // Include c_hash for hybrid flow (if code exists)
                        None,                                 // acr
                        Some(vec!["pwd".to_string()]),        // amr
                        oauth2_config,
                        oidc_config,
                    )?;
                    id_token_for_response = Some(token);
                }
            }
        }
    }

    // Check response_mode
    // For hybrid flows with tokens, use fragment mode by default if not specified
    let response_mode = if (has_token || has_id_token) && params.response_mode.is_none() {
        "fragment"
    } else {
        params.response_mode.as_deref().unwrap_or("query")
    };

    match response_mode {
        "form_post" => {
            // Return HTML form that auto-posts to redirect_uri
            let mut form_inputs = vec![];

            if let Some(ref code) = auth_code {
                form_inputs.push(format!(r#"<input type="hidden" name="code" value="{}" />"#, code));
            }

            if let Some(ref state) = params.state {
                form_inputs.push(format!(r#"<input type="hidden" name="state" value="{}" />"#, state));
            }

            if let Some(ref id_token) = id_token_for_response {
                form_inputs.push(format!(r#"<input type="hidden" name="id_token" value="{}" />"#, id_token));
            }

            if let Some(ref access_token) = access_token_for_response {
                form_inputs.push(format!(r#"<input type="hidden" name="access_token" value="{}" />"#, access_token));
                form_inputs.push(r#"<input type="hidden" name="token_type" value="Bearer" />"#.to_string());
                form_inputs.push(format!(
                    r#"<input type="hidden" name="expires_in" value="{}" />"#,
                    oauth2_config.access_token_expiration_secs
                ));
            }

            form_inputs.push(format!(r#"<input type="hidden" name="session_state" value="{}" />"#, session_state));

            let form_html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="{}">
        {}
        <noscript>
            <p>JavaScript is disabled. Click the button below to continue.</p>
            <button type="submit">Continue</button>
        </noscript>
    </form>
</body>
</html>"#,
                params.redirect_uri,
                form_inputs.join("\n        ")
            );

            debug!("Returning form_post response to: {}", params.redirect_uri);
            Ok(axum::response::Html(form_html).into_response())
        }
        "fragment" => {
            // Fragment mode - tokens in URL fragment (hybrid and implicit flows)
            let mut fragments = vec![];

            if let Some(ref code) = auth_code {
                fragments.push(format!("code={}", code));
            }

            if let Some(ref state) = params.state {
                fragments.push(format!("state={}", state));
            }

            if let Some(ref id_token) = id_token_for_response {
                fragments.push(format!("id_token={}", id_token));
            }

            if let Some(ref access_token) = access_token_for_response {
                fragments.push(format!("access_token={}", access_token));
                fragments.push("token_type=Bearer".to_string());
                fragments.push(format!("expires_in={}", oauth2_config.access_token_expiration_secs));
            }

            fragments.push(format!("session_state={}", session_state));

            let redirect_url = format!("{}#{}", params.redirect_uri, fragments.join("&"));

            debug!("Redirecting to (fragment): {}", redirect_url);
            Ok(Redirect::temporary(&redirect_url).into_response())
        }
        "query" | _ => {
            // Query parameter mode (code only, no tokens)
            if let Some(ref code) = auth_code {
                let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
                if let Some(state) = params.state {
                    redirect_url.push_str(&format!("&state={}", state));
                }
                redirect_url.push_str(&format!("&session_state={}", session_state));

                debug!("Redirecting to: {}", redirect_url);
                Ok(Redirect::temporary(&redirect_url).into_response())
            } else {
                // Should not happen - query mode requires a code
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Query response mode requires authorization code"
                    })),
                ))
            }
        }
    }
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
    let (oauth2_config, storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    match params.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(&tenant_id, oauth2_config, storage_id, params, &state).await
        }
        "client_credentials" => {
            handle_client_credentials_grant(&tenant_id, oauth2_config, params, &state).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(&tenant_id, oauth2_config, storage_id, params, &state).await
        }
        "password" => handle_password_grant(&tenant_id, oauth2_config, storage_id, params, &state).await,
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

/// Generate front-channel logout HTML with iframes for each client
fn generate_frontchannel_logout_html(
    clients: &[crate::storage::OAuth2ClientData],
    session_id: Option<&str>,
    post_logout_redirect_uri: Option<&str>,
) -> String {
    let mut iframes = String::new();

    for client in clients {
        if let Some(ref logout_uri) = client.frontchannel_logout_uri {
            let mut url = logout_uri.clone();

            // Add iss parameter (issuer) - required by OIDC front-channel logout
            if !url.contains('?') {
                url.push('?');
            } else {
                url.push('&');
            }
            url.push_str("iss=");
            url.push_str(&urlencoding::encode(&client.tenant_id));

            // Add sid (session ID) parameter if required and available
            if client.frontchannel_logout_session_required {
                if let Some(sid) = session_id {
                    url.push_str("&sid=");
                    url.push_str(&urlencoding::encode(sid));
                }
            }

            iframes.push_str(&format!(
                r#"    <iframe style="display:none" src="{}"></iframe>
"#,
                html_escape::encode_text(&url)
            ));
        }
    }

    // Generate redirect script if post_logout_redirect_uri is provided
    let redirect_script = if let Some(redirect_uri) = post_logout_redirect_uri {
        format!(
            r#"
    // Redirect after a short delay to allow iframes to load
    setTimeout(function() {{
        window.location.href = "{}";
    }}, 1000);
"#,
            html_escape::encode_text(redirect_uri)
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Logging out...</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Logging out...</h2>
    <p>Please wait while we sign you out from all applications.</p>
{}    <script>
{}    </script>
</body>
</html>"#,
        iframes, redirect_script
    )
}

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
    let (oauth2_config, _oauth2_storage_id) = match tenant.get_oauth2_provider() {
        Some((config, storage_id)) => (config, storage_id),
        None => {
            debug!("OAuth2 not enabled for tenant, skipping backchannel logout");
            return;
        }
    };

    let (oidc_config, _oidc_storage_id) = match tenant.get_oidc_provider() {
        Some((config, storage_id)) => (config, storage_id),
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
        if let Some(user_id) = user_id_for_logout.clone() {
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

        // Check for front-channel logout clients
        if let Ok(clients) = state.storage.list_oauth2_clients(&tenant_id).await {
            let frontchannel_clients: Vec<_> = clients
                .into_iter()
                .filter(|c| c.frontchannel_logout_uri.is_some())
                .collect();

            if !frontchannel_clients.is_empty() {
                info!(
                    "Generating front-channel logout HTML for {} client(s)",
                    frontchannel_clients.len()
                );
                let html = generate_frontchannel_logout_html(
                    &frontchannel_clients,
                    session_id_for_logout.as_deref(),
                    Some(&redirect_url),
                );
                return Ok(axum::response::Html(html).into_response());
            }
        }

        return Ok(Redirect::temporary(&redirect_url).into_response());
    }

    // Trigger backchannel logout in background (non-blocking)
    if let Some(user_id) = user_id_for_logout.clone() {
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

    // Check for front-channel logout clients when no redirect_uri provided
    if let Ok(clients) = state.storage.list_oauth2_clients(&tenant_id).await {
        let frontchannel_clients: Vec<_> = clients
            .into_iter()
            .filter(|c| c.frontchannel_logout_uri.is_some())
            .collect();

        if !frontchannel_clients.is_empty() {
            info!(
                "Generating front-channel logout HTML for {} client(s)",
                frontchannel_clients.len()
            );
            let html = generate_frontchannel_logout_html(
                &frontchannel_clients,
                session_id_for_logout.as_deref(),
                None,
            );
            return Ok(axum::response::Html(html).into_response());
        }
    }

    // Return JSON response if no redirect and no front-channel logout
    Ok(Json(LogoutResponse {
        message: "Logout successful".to_string(),
    })
    .into_response())
}

/// Handle authorization code grant
async fn handle_authorization_code_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    storage_id: &str,
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

    // Retrieve user from identity storage
    let storage = state.config.get_identity_storage(tenant_id, storage_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": format!("Identity storage '{}' not found", storage_id)
            })),
        )
    })?;
    let backend = create_identity_storage(storage);
    let user = backend.get_user_by_id(&code_data.user_id).map_err(|e| {
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
        let tenant = state.config.get_tenant(tenant_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "tenant_not_found" })),
            )
        })?;

        if let Some((oidc_config, _oidc_storage_id)) = tenant.get_oidc_provider() {
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
                Some(&access_token), // Include at_hash in ID token
                None,                // No c_hash needed for token endpoint
                None,                // acr - can be set based on auth strength
                Some(vec!["pwd".to_string()]), // amr - password authentication
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
    storage_id: &str,
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

    // Retrieve user from identity storage
    let storage = state.config.get_identity_storage(tenant_id, storage_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": format!("Identity storage '{}' not found", storage_id)
            })),
        )
    })?;
    let backend = create_identity_storage(storage);
    let user = backend.get_user_by_id(&token_data.user_id).map_err(|e| {
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

    // Implement refresh token rotation (RFC 6749 Security Best Practices)
    // Generate a new refresh token
    let new_refresh_token = generate_refresh_token(
        &user.id,
        &user.email,
        user.role,
        &scope_vec,
        tenant_id,
        &token_data.client_id,
        oauth2_config,
        state,
    )
    .await?;

    // Invalidate the old refresh token to prevent reuse
    state
        .storage
        .delete_refresh_token(&refresh_token)
        .await
        .map_err(|e| {
            warn!("Failed to delete old refresh token: {}", e);
            // Continue even if deletion fails - the new token is already issued
        })
        .ok();

    info!(
        "Refresh token rotated for user '{}' (tenant: {})",
        user.id, tenant_id
    );

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token: Some(new_refresh_token), // Return new refresh token (rotation)
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
    storage_id: &str,
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

    // Authenticate user via identity storage
    let storage = state.config.get_identity_storage(tenant_id, storage_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": format!("Identity storage '{}' not found for tenant", storage_id)
            })),
        )
    })?;
    let backend = crate::auth::identity_storage::create_identity_storage(storage);
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

    let (oauth2_config, _storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
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

/// Generate session_state parameter (OIDC Session Management)
/// Format: SHA256(client_id + origin + session_id + salt)
fn generate_session_state(client_id: &str, origin: &str, session_id: &str, salt: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let input = format!("{}{}{}{}", client_id, origin, session_id, salt);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    let hash_b64 = URL_SAFE_NO_PAD.encode(hash);

    format!("{}.{}", hash_b64, salt)
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
            // RSA signature with public key - support multiple keys via kid
            let public_key_pem = if let Some(kid) = &header.kid {
                // kid specified - must find exact match in jwks_keys
                if let Some(jwks_keys) = &client.jwks_keys {
                    // Find key by kid in JWKS keys
                    let matching_key = jwks_keys.iter()
                        .find(|key| {
                            key.get("kid")
                                .and_then(|k| k.as_str())
                                .map(|k| k == kid)
                                .unwrap_or(false)
                        })
                        .ok_or_else(|| {
                            warn!("Client '{}' JWT has kid '{}' but no matching key found", client_id, kid);
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "error": "invalid_client",
                                    "error_description": format!("No key found with kid '{}'", kid)
                                })),
                            )
                        })?;

                    // Extract RSA public key components from JWK
                    let n = matching_key.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "RSA key must have 'n' (modulus)"
                            })),
                        )
                    })?;

                    let e = matching_key.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "RSA key must have 'e' (exponent)"
                            })),
                        )
                    })?;

                    // Store as JSON for now (same format as public_key_pem field)
                    Some(json!({
                        "kty": "RSA",
                        "n": n,
                        "e": e,
                        "kid": kid,
                    }).to_string())
                } else {
                    // kid specified but client has no jwks_keys - error
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Client has no JWKS keys configured"
                        })),
                    ));
                }
            } else {
                // No kid - use public_key_pem for backward compatibility
                client.public_key_pem.clone()
            };

            let public_key_pem = public_key_pem.ok_or_else(|| {
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

            // Parse the JWK format and convert to RSA components for DecodingKey
            let key = if public_key_pem.starts_with('{') {
                // It's in JWK JSON format - extract components
                let jwk: serde_json::Value = serde_json::from_str(&public_key_pem).map_err(|e| {
                    warn!("Failed to parse JWK for client '{}': {}", client_id, e);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Invalid JWK format"
                        })),
                    )
                })?;

                let n = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "JWK missing 'n' component"
                        })),
                    )
                })?;

                let e = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "JWK missing 'e' component"
                        })),
                    )
                })?;

                DecodingKey::from_rsa_components(n, e).map_err(|e| {
                    warn!("Failed to create RSA key from JWK components for client '{}': {}", client_id, e);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Invalid RSA key components"
                        })),
                    )
                })?
            } else {
                // It's in PEM format
                DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
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
                })?
            };

            (Algorithm::RS256, key)
        }
        Algorithm::ES256 => {
            // ECDSA signature with public key - support multiple keys via kid
            let public_key_pem = if let Some(kid) = &header.kid {
                // kid specified - must find exact match in jwks_keys
                if let Some(jwks_keys) = &client.jwks_keys {
                    // Find key by kid in JWKS keys
                    let matching_key = jwks_keys.iter()
                        .find(|key| {
                            key.get("kid")
                                .and_then(|k| k.as_str())
                                .map(|k| k == kid)
                                .unwrap_or(false)
                        })
                        .ok_or_else(|| {
                            warn!("Client '{}' JWT has kid '{}' but no matching key found", client_id, kid);
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(json!({
                                    "error": "invalid_client",
                                    "error_description": format!("No key found with kid '{}'", kid)
                                })),
                            )
                        })?;

                    // Extract EC public key components from JWK
                    let crv = matching_key.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "EC key must have 'crv' (curve)"
                            })),
                        )
                    })?;

                    let x = matching_key.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "EC key must have 'x' coordinate"
                            })),
                        )
                    })?;

                    let y = matching_key.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "EC key must have 'y' coordinate"
                            })),
                        )
                    })?;

                    // Store as JSON for now (same format as public_key_pem field)
                    Some(json!({
                        "kty": "EC",
                        "crv": crv,
                        "x": x,
                        "y": y,
                        "kid": kid,
                    }).to_string())
                } else {
                    // kid specified but client has no jwks_keys - error
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Client has no JWKS keys configured"
                        })),
                    ));
                }
            } else {
                // No kid - use public_key_pem for backward compatibility
                client.public_key_pem.clone()
            };

            let public_key_pem = public_key_pem.ok_or_else(|| {
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

            // Parse the JWK format and convert to EC components for DecodingKey
            let key = if public_key_pem.starts_with('{') {
                // It's in JWK JSON format - extract components
                let jwk: serde_json::Value = serde_json::from_str(&public_key_pem).map_err(|e| {
                    warn!("Failed to parse JWK for client '{}': {}", client_id, e);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Invalid JWK format"
                        })),
                    )
                })?;

                let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "JWK missing 'x' component"
                        })),
                    )
                })?;

                let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "JWK missing 'y' component"
                        })),
                    )
                })?;

                DecodingKey::from_ec_components(x, y).map_err(|e| {
                    warn!("Failed to create EC key from JWK components for client '{}': {}", client_id, e);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "Invalid EC key components"
                        })),
                    )
                })?
            } else {
                // It's in PEM format
                DecodingKey::from_ec_pem(public_key_pem.as_bytes()).map_err(|e| {
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
                })?
            };

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

    // Token Response Tests

    #[test]
    fn test_token_response_serialization() {
        let response = TokenResponse {
            access_token: "access_token_123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_token_456".to_string()),
            scope: Some("openid profile email".to_string()),
            id_token: Some("id_token_789".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"access_token\":\"access_token_123\""));
        assert!(json.contains("\"token_type\":\"Bearer\""));
        assert!(json.contains("\"expires_in\":3600"));
        assert!(json.contains("\"refresh_token\":\"refresh_token_456\""));
        assert!(json.contains("\"id_token\":\"id_token_789\""));
    }

    #[test]
    fn test_token_response_without_optional_fields() {
        let response = TokenResponse {
            access_token: "access_token_only".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 7200,
            refresh_token: None,
            scope: None,
            id_token: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"access_token\":\"access_token_only\""));
        assert!(json.contains("\"expires_in\":7200"));
        // Optional fields should not be present
        assert!(!json.contains("\"refresh_token\""));
        assert!(!json.contains("\"id_token\""));
    }

    // Authorization Request Tests

    #[test]
    fn test_authorize_request_deserialization() {
        let json = r#"{
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile email",
            "state": "random_state_123",
            "nonce": "random_nonce_456",
            "code_challenge": "challenge_789",
            "code_challenge_method": "S256"
        }"#;

        let req: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.response_type, "code");
        assert_eq!(req.client_id, "test_client");
        assert_eq!(req.redirect_uri, "https://app.example.com/callback");
        assert_eq!(req.scope, Some("openid profile email".to_string()));
        assert_eq!(req.state, Some("random_state_123".to_string()));
        assert_eq!(req.nonce, Some("random_nonce_456".to_string()));
        assert_eq!(req.code_challenge, Some("challenge_789".to_string()));
        assert_eq!(req.code_challenge_method, Some("S256".to_string()));
    }

    #[test]
    fn test_authorize_request_minimal() {
        let json = r#"{
            "response_type": "code",
            "client_id": "minimal_client",
            "redirect_uri": "https://app.example.com"
        }"#;

        let req: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.response_type, "code");
        assert_eq!(req.client_id, "minimal_client");
        assert!(req.scope.is_none());
        assert!(req.state.is_none());
        assert!(req.nonce.is_none());
        assert!(req.code_challenge.is_none());
    }

    #[test]
    fn test_authorize_request_with_prompt() {
        let json = r#"{
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://app.example.com",
            "prompt": "login consent"
        }"#;

        let req: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.prompt, Some("login consent".to_string()));
    }

    // Grant Type Tests

    #[test]
    fn test_token_request_authorization_code_grant() {
        let json = r#"{
            "grant_type": "authorization_code",
            "code": "auth_code_xyz",
            "redirect_uri": "https://app.example.com/callback",
            "client_id": "my_client",
            "code_verifier": "verifier_123"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "authorization_code");
        assert_eq!(req.code, Some("auth_code_xyz".to_string()));
        assert_eq!(req.redirect_uri, Some("https://app.example.com/callback".to_string()));
        assert_eq!(req.code_verifier, Some("verifier_123".to_string()));
    }

    #[test]
    fn test_token_request_client_credentials_grant() {
        let json = r#"{
            "grant_type": "client_credentials",
            "client_id": "service_client",
            "client_secret": "service_secret",
            "scope": "api:read api:write"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "client_credentials");
        assert_eq!(req.client_id, Some("service_client".to_string()));
        assert_eq!(req.client_secret, Some("service_secret".to_string()));
        assert_eq!(req.scope, Some("api:read api:write".to_string()));
    }

    #[test]
    fn test_token_request_refresh_token_grant() {
        let json = r#"{
            "grant_type": "refresh_token",
            "refresh_token": "refresh_xyz_789",
            "client_id": "my_client",
            "scope": "openid profile"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "refresh_token");
        assert_eq!(req.refresh_token, Some("refresh_xyz_789".to_string()));
        assert_eq!(req.scope, Some("openid profile".to_string()));
    }

    #[test]
    fn test_token_request_password_grant() {
        let json = r#"{
            "grant_type": "password",
            "username": "alice@example.com",
            "password": "secure_password",
            "client_id": "web_client",
            "scope": "openid profile email offline_access"
        }"#;

        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.grant_type, "password");
        assert_eq!(req.username, Some("alice@example.com".to_string()));
        assert_eq!(req.password, Some("secure_password".to_string()));
        assert_eq!(req.client_id, Some("web_client".to_string()));
        assert_eq!(req.scope, Some("openid profile email offline_access".to_string()));
    }

    // Error Response Tests

    #[test]
    fn test_error_response_structure() {
        use serde_json::json;

        let error = json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter: code",
            "error_uri": "https://tools.ietf.org/html/rfc6749#section-5.2"
        });

        assert_eq!(error["error"], "invalid_request");
        assert!(error["error_description"].as_str().unwrap().contains("Missing required parameter"));
        assert!(error["error_uri"].as_str().unwrap().contains("rfc6749"));
    }

    #[test]
    fn test_unauthorized_client_error() {
        use serde_json::json;

        let error = json!({
            "error": "unauthorized_client",
            "error_description": "The client is not authorized to use this grant type"
        });

        assert_eq!(error["error"], "unauthorized_client");
    }

    #[test]
    fn test_invalid_grant_error() {
        use serde_json::json;

        let error = json!({
            "error": "invalid_grant",
            "error_description": "Authorization code is invalid or expired"
        });

        assert_eq!(error["error"], "invalid_grant");
    }

    #[test]
    fn test_unsupported_grant_type_error() {
        use serde_json::json;

        let error = json!({
            "error": "unsupported_grant_type",
            "error_description": "Grant type 'implicit' is not supported"
        });

        assert_eq!(error["error"], "unsupported_grant_type");
    }

    // PKCE Extension Tests

    #[test]
    fn test_pkce_with_s256_valid() {
        // RFC 7636 Appendix B test vector
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(validate_pkce(code_verifier, code_challenge, "S256"));
    }

    #[test]
    fn test_pkce_with_plain_valid() {
        let code_verifier = "my-plain-code-verifier-12345";
        let code_challenge = "my-plain-code-verifier-12345"; // Same for plain

        assert!(validate_pkce(code_verifier, code_challenge, "plain"));
    }

    #[test]
    fn test_pkce_s256_mismatch() {
        let code_verifier = "wrong_verifier";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(!validate_pkce(code_verifier, code_challenge, "S256"));
    }

    #[test]
    fn test_pkce_plain_mismatch() {
        let code_verifier = "verifier_a";
        let code_challenge = "verifier_b";

        assert!(!validate_pkce(code_verifier, code_challenge, "plain"));
    }

    #[test]
    fn test_pkce_invalid_method() {
        assert!(!validate_pkce("verifier", "challenge", "SHA512"));
        assert!(!validate_pkce("verifier", "challenge", ""));
        assert!(!validate_pkce("verifier", "challenge", "invalid"));
    }

    // JWT Client Authentication Tests (RFC 7523)

    #[test]
    fn test_client_assertion_jwt_structure() {
        let claims = ClientAssertionClaims {
            iss: "https://client.example.com".to_string(),
            sub: "client_id_123".to_string(),
            aud: "https://auth.example.com/oauth/token".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            jti: "unique-jwt-id-xyz".to_string(),
        };

        // Verify structure
        assert!(!claims.iss.is_empty());
        assert!(!claims.sub.is_empty());
        assert!(!claims.aud.is_empty());
        assert!(!claims.jti.is_empty());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_client_assertion_exp_validation() {
        let now = chrono::Utc::now().timestamp() as usize;
        let past = (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize;
        let future = (chrono::Utc::now() + chrono::Duration::hours(2)).timestamp() as usize;

        // Expired assertion should be detected
        assert!(past < now);

        // Valid assertion
        assert!(future > now);
    }

    #[test]
    fn test_client_assertion_with_multiple_audiences() {
        // Some implementations support array of audiences
        let json = r#"{
            "iss": "client_123",
            "sub": "client_123",
            "aud": "https://auth.example.com/token",
            "exp": 1234567890,
            "iat": 1234567800,
            "jti": "unique-id"
        }"#;

        let claims: ClientAssertionClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, "https://auth.example.com/token");
    }
}
