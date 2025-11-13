// OAuth2 Authorization Server Implementation
// This module implements the OAuth2 authorization server functionality

use crate::models::{AppConfig, Claims, OAuth2ServerConfig, UserRole};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

// In-memory storage for authorization codes (in production, use Redis)
lazy_static::lazy_static! {
    static ref AUTHORIZATION_CODES: Arc<Mutex<HashMap<String, AuthorizationCodeData>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref REFRESH_TOKENS: Arc<Mutex<HashMap<String, RefreshTokenData>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationCodeData {
    code: String,
    client_id: String,
    redirect_uri: String,
    scope: Vec<String>,
    user_id: String,
    user_email: String,
    user_role: UserRole,
    tenant_id: String,
    created_at: i64,
    expires_at: i64,
    /// PKCE code challenge (RFC 7636)
    code_challenge: Option<String>,
    /// PKCE code challenge method: "plain" or "S256"
    code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshTokenData {
    token: String,
    user_id: String,
    user_email: String,
    user_role: UserRole,
    tenant_id: String,
    scope: Vec<String>,
    created_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    /// PKCE code challenge (RFC 7636)
    pub code_challenge: Option<String>,
    /// PKCE code challenge method: "plain" or "S256" (RFC 7636)
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// PKCE code verifier (RFC 7636)
    pub code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// OAuth2 Authorization Endpoint
/// GET /api/v1/tenant/{tenant_id}/oauth/authorize
pub async fn oauth2_authorize(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Query(params): Query<AuthorizeRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "OAuth2 authorize request for tenant '{}', client_id: {}",
        tenant_id, params.client_id
    );

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
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

    // In a real implementation, this would:
    // 1. Authenticate the user via the identity backend
    // 2. Show a consent screen
    // 3. Generate an authorization code after consent
    //
    // For now, we'll create a mock authorization code for demonstration

    let auth_code = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    let code_data = AuthorizationCodeData {
        code: auth_code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params
            .scope
            .clone()
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect(),
        user_id: "mock-user-id".to_string(), // TODO: Get from identity backend
        user_email: "user@example.com".to_string(), // TODO: Get from identity backend
        user_role: UserRole::User,           // TODO: Get from identity backend
        tenant_id: tenant_id.clone(),
        created_at: now,
        expires_at: now + 600, // 10 minutes
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
    };

    // Store authorization code
    {
        let mut codes = AUTHORIZATION_CODES.lock().unwrap();
        codes.insert(auth_code.clone(), code_data);
    }

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
pub async fn oauth2_token(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(params): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "OAuth2 token request for tenant '{}', grant_type: {}",
        tenant_id, params.grant_type
    );

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
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
            handle_authorization_code_grant(&tenant_id, oauth2_config, params).await
        }
        "client_credentials" => {
            handle_client_credentials_grant(&tenant_id, oauth2_config, params).await
        }
        "refresh_token" => handle_refresh_token_grant(&tenant_id, oauth2_config, params).await,
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": format!("Grant type '{}' is not supported", params.grant_type)
            })),
        )),
    }
}

/// Handle authorization code grant
async fn handle_authorization_code_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
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

    // Retrieve and remove authorization code
    let code_data = {
        let mut codes = AUTHORIZATION_CODES.lock().unwrap();
        codes.remove(&code).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_grant", "error_description": "Invalid authorization code" })),
            )
        })?
    };

    // Validate code hasn't expired
    let now = Utc::now().timestamp();
    if now > code_data.expires_at {
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

    // Generate tokens
    let access_token = generate_access_token(
        &code_data.user_id,
        &code_data.user_email,
        code_data.user_role,
        &code_data.scope,
        tenant_id,
        oauth2_config,
    )?;

    let refresh_token = if oauth2_config
        .grant_types
        .contains(&"refresh_token".to_string())
    {
        Some(generate_refresh_token(
            &code_data.user_id,
            &code_data.user_email,
            code_data.user_role,
            &code_data.scope,
            tenant_id,
            oauth2_config,
        )?)
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token,
        scope: Some(code_data.scope.join(" ")),
    }))
}

/// Handle client credentials grant
async fn handle_client_credentials_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate client credentials
    let _client_id = params.client_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "Missing client_id" })),
        )
    })?;

    let _client_secret = params.client_secret.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_request", "error_description": "Missing client_secret" }),
            ),
        )
    })?;

    // TODO: Validate client credentials against a client registry

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
        oauth2_config,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token: None, // Client credentials don't get refresh tokens
        scope: Some(scope.join(" ")),
    }))
}

/// Handle refresh token grant
async fn handle_refresh_token_grant(
    tenant_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    params: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let refresh_token = params.refresh_token.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_request", "error_description": "Missing refresh_token" }),
            ),
        )
    })?;

    // Retrieve refresh token data
    let token_data = {
        let tokens = REFRESH_TOKENS.lock().unwrap();
        tokens.get(&refresh_token).cloned().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_grant", "error_description": "Invalid refresh token" })),
            )
        })?
    };

    // Validate token hasn't expired
    let now = Utc::now().timestamp();
    if now > token_data.expires_at {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant", "error_description": "Refresh token expired" })),
        ));
    }

    // Generate new access token
    let access_token = generate_access_token(
        &token_data.user_id,
        &token_data.user_email,
        token_data.user_role,
        &token_data.scope,
        tenant_id,
        oauth2_config,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs,
        refresh_token: Some(refresh_token), // Return the same refresh token
        scope: Some(token_data.scope.join(" ")),
    }))
}

/// Generate an access token (JWT)
fn generate_access_token(
    user_id: &str,
    email: &str,
    role: UserRole,
    _scope: &[String],
    _tenant_id: &str,
    config: &OAuth2ServerConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp();
    let exp = now + config.access_token_expiration_secs;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        exp: exp as usize,
    };

    // TODO: Add scope to claims
    // TODO: Add tenant_id to claims
    // TODO: Add iss (issuer) claim

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

    // TODO: Load private key from file or environment
    // For now, this will fail - need to implement key loading
    let encoding_key = EncodingKey::from_rsa_pem(b"dummy-key").map_err(|e| {
        warn!("Failed to load signing key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load signing key" })),
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
fn generate_refresh_token(
    user_id: &str,
    email: &str,
    role: UserRole,
    scope: &[String],
    tenant_id: &str,
    config: &OAuth2ServerConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    let token_data = RefreshTokenData {
        token: token.clone(),
        user_id: user_id.to_string(),
        user_email: email.to_string(),
        user_role: role,
        tenant_id: tenant_id.to_string(),
        scope: scope.to_vec(),
        created_at: now,
        expires_at: now + config.refresh_token_expiration_secs,
    };

    // Store refresh token
    {
        let mut tokens = REFRESH_TOKENS.lock().unwrap();
        tokens.insert(token.clone(), token_data);
    }

    Ok(token)
}

/// JWKS Endpoint - returns public keys for token verification
/// GET /api/v1/tenant/{tenant_id}/.well-known/jwks.json
pub async fn jwks(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!("JWKS request for tenant '{}'", tenant_id);

    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
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

    // TODO: Load actual public key and convert to JWK format
    // For now, return a placeholder

    Ok(Json(json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": oauth2_config.signing_key.kid,
                "use": "sig",
                "alg": oauth2_config.signing_key.algorithm,
                "n": "placeholder-modulus",
                "e": "AQAB"
            }
        ]
    })))
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
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
}
