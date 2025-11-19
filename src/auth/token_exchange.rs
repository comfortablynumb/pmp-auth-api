// Token Exchange (RFC 8693)
// This module implements the OAuth 2.0 Token Exchange Protocol

use crate::auth::identity_backend::create_identity_backend;
use crate::auth::oauth2_server::generate_access_token;
use crate::models::Claims;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Form, Json};
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

/// Token Exchange Request (RFC 8693 Section 2.1)
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// REQUIRED - The value "urn:ietf:params:oauth:grant-type:token-exchange"
    pub grant_type: String,
    /// OPTIONAL - A security token representing the identity of the party on behalf of whom the request is being made
    pub subject_token: Option<String>,
    /// REQUIRED if subject_token is present - identifies the type of subject_token
    pub subject_token_type: Option<String>,
    /// OPTIONAL - A security token representing the identity of the acting party
    pub actor_token: Option<String>,
    /// REQUIRED if actor_token is present - identifies the type of actor_token
    pub actor_token_type: Option<String>,
    /// OPTIONAL - The type of the requested security token
    pub requested_token_type: Option<String>,
    /// OPTIONAL - Scope of the requested token
    pub scope: Option<String>,
    /// OPTIONAL - Logical name of the target service or resource
    pub resource: Option<String>,
    /// OPTIONAL - Logical name of the target service audience
    pub audience: Option<String>,
    /// Client credentials (if client is authenticated)
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Token Exchange Response (RFC 8693 Section 2.2)
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The security token issued by the authorization server
    pub access_token: String,
    /// Type of the token issued
    pub issued_token_type: String,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Lifetime in seconds of the access token
    pub expires_in: u64,
    /// Scope of the issued token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Refresh token (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Token type identifiers (RFC 8693 Section 3)
pub mod token_types {
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
    pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
    pub const SAML1: &str = "urn:ietf:params:oauth:token-type:saml1";
    pub const SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
}

/// Token Exchange endpoint
/// POST /api/v1/tenant/{tenant_id}/oauth/token/exchange
pub async fn token_exchange(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Form(request): Form<TokenExchangeRequest>,
) -> Result<Json<TokenExchangeResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Token exchange request for tenant '{}'", tenant_id);

    // Validate grant_type
    if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": "Grant type must be urn:ietf:params:oauth:grant-type:token-exchange"
            })),
        ));
    }

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid_request", "error_description": "Tenant not found" })),
        )
    })?;

    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "OAuth2 not enabled" })),
        )
    })?;

    // Subject token is required
    let subject_token = request.subject_token.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "subject_token is required"
            })),
        )
    })?;

    let subject_token_type = request.subject_token_type.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "subject_token_type is required"
            })),
        )
    })?;

    // Validate subject token type
    if subject_token_type != token_types::ACCESS_TOKEN
        && subject_token_type != token_types::JWT
        && subject_token_type != token_types::ID_TOKEN
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": format!("Unsupported subject_token_type: {}", subject_token_type)
            })),
        ));
    }

    // Validate and extract claims from subject token
    let subject_claims = validate_token(subject_token, oauth2_config, &state).await?;

    debug!(
        "Validated subject token for user: {}",
        subject_claims.sub
    );

    // Handle actor token if present (delegation scenario)
    let _actor_claims = if let Some(actor_token) = &request.actor_token {
        let actor_token_type = request.actor_token_type.as_ref().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "actor_token_type is required when actor_token is present"
                })),
            )
        })?;

        if actor_token_type != token_types::ACCESS_TOKEN
            && actor_token_type != token_types::JWT
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": format!("Unsupported actor_token_type: {}", actor_token_type)
                })),
            ));
        }

        Some(validate_token(actor_token, oauth2_config, &state).await?)
    } else {
        None
    };

    // Determine requested token type (default to access_token)
    let requested_token_type = request
        .requested_token_type
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(token_types::ACCESS_TOKEN);

    if requested_token_type != token_types::ACCESS_TOKEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Only access_token type is currently supported"
            })),
        ));
    }

    // Parse requested scope (or use original scope)
    let scope_vec: Vec<String> = if let Some(scope_str) = &request.scope {
        scope_str.split_whitespace().map(String::from).collect()
    } else {
        subject_claims
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_else(|| vec!["openid".to_string()])
    };

    // Retrieve user from identity backend to get current role
    let backend = create_identity_backend(&tenant.identity_backend);
    let user = backend
        .get_user_by_id(&subject_claims.sub)
        .map_err(|e| {
            warn!("Failed to retrieve user '{}': {}", subject_claims.sub, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to retrieve user"
                })),
            )
        })?;

    // Generate new access token with potentially different scope/audience
    let client_id = request
        .client_id
        .as_deref()
        .or(subject_claims.azp.as_deref())
        .unwrap_or("token-exchange");

    let access_token = generate_access_token(
        &user.id,
        &user.email,
        user.role,
        &scope_vec,
        &tenant_id,
        client_id,
        oauth2_config,
    )
    .map_err(|(status, json)| (status, json))?;

    info!(
        "Successfully exchanged token for user '{}' with scope: {:?}",
        user.id, scope_vec
    );

    Ok(Json(TokenExchangeResponse {
        access_token,
        issued_token_type: token_types::ACCESS_TOKEN.to_string(),
        token_type: "Bearer".to_string(),
        expires_in: oauth2_config.access_token_expiration_secs as u64,
        scope: Some(scope_vec.join(" ")),
        refresh_token: None, // Token exchange doesn't issue refresh tokens by default
    }))
}

/// Validate a token (access token or JWT)
async fn validate_token(
    token: &str,
    oauth2_config: &crate::models::OAuth2ServerConfig,
    state: &AppState,
) -> Result<Claims, (StatusCode, Json<serde_json::Value>)> {
    // Load public key for validation
    let public_key_pem =
        load_key_pem(&oauth2_config.signing_key.public_key).map_err(|e| {
            warn!("Failed to load public key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to load public key"
                })),
            )
        })?;

    let algorithm = match oauth2_config.signing_key.algorithm.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Unsupported algorithm"
                })),
            ))
        }
    };

    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse public key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Invalid public key format"
            })),
        )
    })?;

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.set_required_spec_claims(&["sub", "exp"]);

    // Decode and validate token
    let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        warn!("Token validation failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_token",
                "error_description": "Token validation failed"
            })),
        )
    })?;

    // Check if token is revoked
    if let Some(jti) = &token_data.claims.jti {
        if let Ok(true) = state.storage.is_token_revoked(jti).await {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_token",
                    "error_description": "Token has been revoked"
                })),
            ));
        }
    }

    // Verify token hasn't expired
    let now = Utc::now().timestamp() as usize;
    if token_data.claims.exp < now {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_token",
                "error_description": "Token has expired"
            })),
        ));
    }

    Ok(token_data.claims)
}

/// Load a key from either a file path or inline PEM
fn load_key_pem(key_config: &str) -> Result<String, String> {
    if key_config.starts_with("-----BEGIN") {
        Ok(key_config.to_string())
    } else {
        std::fs::read_to_string(key_config)
            .map_err(|e| format!("Failed to read key file '{}': {}", key_config, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_exchange_request_deserialization() {
        let form = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=abc123&subject_token_type=urn:ietf:params:oauth:token-type:access_token&scope=read%20write";

        // URL decode and parse
        let decoded: Vec<(String, String)> = serde_urlencoded::from_str(form).unwrap();
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn test_token_types() {
        assert_eq!(
            token_types::ACCESS_TOKEN,
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(
            token_types::JWT,
            "urn:ietf:params:oauth:token-type:jwt"
        );
    }
}
