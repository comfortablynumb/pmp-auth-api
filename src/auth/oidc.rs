// OpenID Connect Provider Implementation
// This module implements the OIDC provider functionality on top of OAuth2

use crate::models::{AppConfig, OAuth2ServerConfig, OidcProviderConfig};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// Extended claims for OpenID Connect ID tokens
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcClaims {
    // Standard OIDC claims
    pub iss: String,           // Issuer
    pub sub: String,           // Subject (user ID)
    pub aud: Vec<String>,      // Audience (client IDs)
    pub exp: usize,            // Expiration time
    pub iat: usize,            // Issued at time
    pub auth_time: usize,      // Authentication time
    pub nonce: Option<String>, // Nonce from authorization request

    // Optional standard claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

/// Userinfo response structure
#[derive(Debug, Serialize)]
pub struct UserinfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// OpenID Connect Discovery Endpoint
/// GET /api/v1/tenant/{tenant_id}/.well-known/openid-configuration
pub async fn oidc_discovery(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!("OIDC discovery request for tenant '{}'", tenant_id);

    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if OIDC is enabled
    let oidc_config = tenant.identity_provider.oidc.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oidc_not_enabled" })),
        )
    })?;

    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    // Build the discovery document
    let base_url = format!("/api/v1/tenant/{}", tenant_id);

    Ok(Json(json!({
        "issuer": oidc_config.issuer,
        "authorization_endpoint": format!("{}{}", base_url, oauth2_config.authorize_endpoint),
        "token_endpoint": format!("{}{}", base_url, oauth2_config.token_endpoint),
        "userinfo_endpoint": format!("{}{}", base_url, oidc_config.userinfo_endpoint),
        "jwks_uri": format!("{}{}", base_url, oauth2_config.jwks_endpoint),
        "scopes_supported": oidc_config.scopes_supported,
        "response_types_supported": ["code", "id_token", "token id_token"],
        "grant_types_supported": oauth2_config.grant_types,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [oauth2_config.signing_key.algorithm],
        "claims_supported": oidc_config.claims_supported,
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256", "plain"],
    })))
}

/// OpenID Connect Userinfo Endpoint
/// GET /api/v1/tenant/{tenant_id}/oauth/userinfo
pub async fn oidc_userinfo(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UserinfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    debug!("OIDC userinfo request for tenant '{}'", tenant_id);

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if OIDC is enabled
    tenant.identity_provider.oidc.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oidc_not_enabled" })),
        )
    })?;

    // Extract access token from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing_token" })),
            )
        })?;

    let _token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_token_format" })),
        )
    })?;

    // TODO: Validate the access token
    // For now, we'll decode it without validation (INSECURE - for demonstration only)

    // In a real implementation:
    // 1. Validate the JWT signature
    // 2. Check expiration
    // 3. Verify issuer and audience
    // 4. Look up additional user claims from identity backend

    // Mock user info for demonstration
    let userinfo = UserinfoResponse {
        sub: "mock-user-id".to_string(),
        name: Some("Mock User".to_string()),
        email: Some("user@example.com".to_string()),
        email_verified: Some(true),
        picture: None,
        preferred_username: Some("mockuser".to_string()),
        role: Some("user".to_string()),
    };

    Ok(Json(userinfo))
}

/// Generate an OpenID Connect ID token
#[allow(dead_code)]
pub fn generate_id_token(
    user_id: &str,
    email: &str,
    name: Option<String>,
    client_id: &str,
    nonce: Option<String>,
    oauth2_config: &OAuth2ServerConfig,
    oidc_config: &OidcProviderConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp() as usize;
    let exp = now + oidc_config.id_token_expiration_secs as usize;

    let claims = OidcClaims {
        iss: oidc_config.issuer.clone(),
        sub: user_id.to_string(),
        aud: vec![client_id.to_string()],
        exp,
        iat: now,
        auth_time: now,
        nonce,
        name,
        email: Some(email.to_string()),
        email_verified: Some(true),
        picture: None,
        preferred_username: Some(email.to_string()),
    };

    let algorithm = match oauth2_config.signing_key.algorithm.as_str() {
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
    let encoding_key = EncodingKey::from_rsa_pem(b"dummy-key").map_err(|e| {
        warn!("Failed to load signing key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load signing key" })),
        )
    })?;

    let mut header = Header::new(algorithm);
    header.kid = Some(oauth2_config.signing_key.kid.clone());

    encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode ID token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to generate ID token" })),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_claims_serialization() {
        let claims = OidcClaims {
            iss: "https://example.com".to_string(),
            sub: "user123".to_string(),
            aud: vec!["client1".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567800,
            nonce: Some("abc123".to_string()),
            name: Some("Test User".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            picture: None,
            preferred_username: Some("testuser".to_string()),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"https://example.com\""));
        assert!(json.contains("\"sub\":\"user123\""));
    }

    #[test]
    fn test_userinfo_response_serialization() {
        let userinfo = UserinfoResponse {
            sub: "user123".to_string(),
            name: Some("Test User".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            picture: None,
            preferred_username: Some("testuser".to_string()),
            role: Some("admin".to_string()),
        };

        let json = serde_json::to_string(&userinfo).unwrap();
        assert!(json.contains("\"sub\":\"user123\""));
        assert!(json.contains("\"email\":\"test@example.com\""));
        // picture should not be serialized since it's None
        assert!(!json.contains("\"picture\""));
    }
}
