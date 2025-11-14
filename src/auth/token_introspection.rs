// Token Introspection and Revocation (RFC 7662, RFC 7009)
// Allows resource servers to validate tokens and revoke access

use crate::models::AppConfig;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Token introspection request (RFC 7662)
#[derive(Debug, Deserialize)]
pub struct IntrospectionRequest {
    /// The token to introspect
    pub token: String,
    /// Optional hint about the token type (access_token, refresh_token, etc.)
    pub token_type_hint: Option<String>,
}

/// Token introspection response (RFC 7662)
#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    /// REQUIRED: Whether the token is active
    pub active: bool,
    /// Optional: Space-separated list of scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional: Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional: Username (for user tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional: Token type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Optional: Expiration timestamp (seconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Optional: Issued at timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Optional: Not before timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Optional: Subject (user ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Optional: Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Optional: Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Optional: JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Token revocation request (RFC 7009)
#[derive(Debug, Deserialize)]
pub struct RevocationRequest {
    /// The token to revoke
    pub token: String,
    /// Optional hint about the token type
    pub token_type_hint: Option<String>,
}

/// JWT claims for introspection
#[derive(Debug, Deserialize)]
struct TokenClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    iss: String,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    exp: Option<usize>,
    iat: Option<usize>,
    nbf: Option<usize>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    api_key: Option<bool>,
}

/// Token Introspection Endpoint (RFC 7662)
/// POST /api/v1/tenant/{tenant_id}/oauth/introspect
pub async fn token_introspect(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Token introspection request for tenant '{}', token_type_hint: {:?}",
        tenant_id, request.token_type_hint
    );

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Try to decode and validate the token
    // We'll try different signing keys (OAuth2, API keys, etc.)
    let introspection_result = introspect_token(&request.token, tenant, &tenant_id);

    match introspection_result {
        Ok(response) => {
            info!(
                "Token introspection successful for tenant '{}': active={}",
                tenant_id, response.active
            );
            Ok(Json(response))
        }
        Err(_) => {
            // Token is invalid - return inactive
            debug!("Token introspection failed - returning inactive");
            Ok(Json(IntrospectionResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }))
        }
    }
}

/// Introspect a token and return metadata
fn introspect_token(
    token: &str,
    tenant: &crate::models::Tenant,
    _tenant_id: &str,
) -> Result<IntrospectionResponse, String> {
    // Try OAuth2 signing key first
    if let Some(oauth2_config) = &tenant.identity_provider.oauth2 {
        let key_result = decode_with_key(token, &oauth2_config.signing_key.public_key);

        if let Ok(claims) = key_result {
            // Check if token is expired
            let now = chrono::Utc::now().timestamp() as usize;
            if let Some(exp) = claims.exp {
                if exp < now {
                    return Ok(IntrospectionResponse {
                        active: false,
                        scope: claims.scope.clone(),
                        client_id: claims.client_id.clone(),
                        username: None,
                        token_type: Some("Bearer".to_string()),
                        exp: Some(exp as u64),
                        iat: claims.iat.map(|i| i as u64),
                        nbf: claims.nbf.map(|n| n as u64),
                        sub: Some(claims.sub.clone()),
                        aud: extract_audience(&claims.aud),
                        iss: Some(claims.iss.clone()),
                        jti: claims.jti.clone(),
                    });
                }
            }

            // Check if token is revoked (check API_KEYS storage for API keys)
            if claims.api_key == Some(true) && is_api_key_revoked(&claims.sub) {
                return Ok(IntrospectionResponse {
                    active: false,
                    scope: claims.scope.clone(),
                    client_id: claims.client_id.clone(),
                    username: None,
                    token_type: Some("Bearer".to_string()),
                    exp: claims.exp.map(|e| e as u64),
                    iat: claims.iat.map(|i| i as u64),
                    nbf: claims.nbf.map(|n| n as u64),
                    sub: Some(claims.sub.clone()),
                    aud: extract_audience(&claims.aud),
                    iss: Some(claims.iss.clone()),
                    jti: claims.jti.clone(),
                });
            }

            // Token is active
            return Ok(IntrospectionResponse {
                active: true,
                scope: claims.scope.clone(),
                client_id: claims.client_id.clone(),
                username: None, // Could be extracted from claims if needed
                token_type: Some("Bearer".to_string()),
                exp: claims.exp.map(|e| e as u64),
                iat: claims.iat.map(|i| i as u64),
                nbf: claims.nbf.map(|n| n as u64),
                sub: Some(claims.sub.clone()),
                aud: extract_audience(&claims.aud),
                iss: Some(claims.iss.clone()),
                jti: claims.jti.clone(),
            });
        }
    }

    // Try API key signing key
    if let Some(api_key_config) = &tenant.api_keys {
        let key_result = decode_with_key(token, &api_key_config.signing_key.public_key);

        if let Ok(claims) = key_result {
            // Check expiration
            let now = chrono::Utc::now().timestamp() as usize;
            if let Some(exp) = claims.exp {
                if exp < now {
                    return Ok(IntrospectionResponse {
                        active: false,
                        scope: claims.scope.clone(),
                        client_id: claims.client_id.clone(),
                        username: None,
                        token_type: Some("Bearer".to_string()),
                        exp: Some(exp as u64),
                        iat: claims.iat.map(|i| i as u64),
                        nbf: claims.nbf.map(|n| n as u64),
                        sub: Some(claims.sub.clone()),
                        aud: extract_audience(&claims.aud),
                        iss: Some(claims.iss.clone()),
                        jti: claims.jti.clone(),
                    });
                }
            }

            // Check revocation
            if is_api_key_revoked(&claims.sub) {
                return Ok(IntrospectionResponse {
                    active: false,
                    scope: claims.scope.clone(),
                    client_id: claims.client_id.clone(),
                    username: None,
                    token_type: Some("Bearer".to_string()),
                    exp: claims.exp.map(|e| e as u64),
                    iat: claims.iat.map(|i| i as u64),
                    nbf: claims.nbf.map(|n| n as u64),
                    sub: Some(claims.sub.clone()),
                    aud: extract_audience(&claims.aud),
                    iss: Some(claims.iss.clone()),
                    jti: claims.jti.clone(),
                });
            }

            // Active API key
            return Ok(IntrospectionResponse {
                active: true,
                scope: claims.scope.clone(),
                client_id: claims.client_id.clone(),
                username: None,
                token_type: Some("Bearer".to_string()),
                exp: claims.exp.map(|e| e as u64),
                iat: claims.iat.map(|i| i as u64),
                nbf: claims.nbf.map(|n| n as u64),
                sub: Some(claims.sub.clone()),
                aud: extract_audience(&claims.aud),
                iss: Some(claims.iss.clone()),
                jti: claims.jti.clone(),
            });
        }
    }

    Err("Token validation failed with all available keys".to_string())
}

/// Decode JWT with a public key
fn decode_with_key(token: &str, _public_key_pem: &str) -> Result<TokenClaims, String> {
    // TODO: Load actual public key from PEM and validate signature
    // For now, try to decode without validation (just parse the claims)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    // Decode payload (second part)
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload_bytes = STANDARD
        .decode(parts[1])
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let claims: TokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("JSON parse error: {}", e))?;

    Ok(claims)
}

/// Check if an API key is revoked
fn is_api_key_revoked(key_id: &str) -> bool {
    use crate::auth::api_keys::API_KEYS;

    if let Ok(keys) = API_KEYS.lock() {
        if let Some(key_metadata) = keys.get(key_id) {
            return key_metadata.revoked;
        }
    }

    false
}

/// Extract audience from JWT claims
fn extract_audience(aud: &Option<serde_json::Value>) -> Option<String> {
    match aud {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Array(arr)) => {
            // Join multiple audiences with space
            let audiences: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if audiences.is_empty() {
                None
            } else {
                Some(audiences.join(" "))
            }
        }
        _ => None,
    }
}

/// Token Revocation Endpoint (RFC 7009)
/// POST /api/v1/tenant/{tenant_id}/oauth/revoke
pub async fn token_revoke(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<RevocationRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Token revocation request for tenant '{}', token_type_hint: {:?}",
        tenant_id, request.token_type_hint
    );

    // Get tenant configuration
    let _tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Try to parse the token to get the subject (key ID for API keys)
    let parts: Vec<&str> = request.token.split('.').collect();
    if parts.len() == 3 {
        // Decode payload
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        if let Ok(payload_bytes) = STANDARD.decode(parts[1]) {
            if let Ok(claims) = serde_json::from_slice::<TokenClaims>(&payload_bytes) {
                // Check if this is an API key
                if claims.api_key == Some(true) {
                    // Revoke the API key
                    use crate::auth::api_keys::API_KEYS;

                    if let Ok(mut keys) = API_KEYS.lock() {
                        if let Some(key_metadata) = keys.get_mut(&claims.sub) {
                            key_metadata.revoked = true;
                            info!("API key '{}' revoked successfully", claims.sub);
                        }
                    }
                } else {
                    // For regular OAuth2 tokens, we would add to a revocation list
                    // For now, just log it
                    warn!(
                        "Token revocation requested for OAuth2 token (not yet implemented): {}",
                        claims.sub
                    );
                    // TODO: Add to revocation list in database
                }
            }
        }
    }

    // RFC 7009: Always return 200 OK, even if token was invalid or already revoked
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_introspection_request_deserialization() {
        let json = r#"{"token": "abc123", "token_type_hint": "access_token"}"#;
        let req: IntrospectionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "abc123");
        assert_eq!(req.token_type_hint, Some("access_token".to_string()));
    }

    #[test]
    fn test_introspection_response_serialization() {
        let response = IntrospectionResponse {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("client-123".to_string()),
            username: Some("user@example.com".to_string()),
            token_type: Some("Bearer".to_string()),
            exp: Some(1234567890),
            iat: Some(1234560000),
            nbf: None,
            sub: Some("user-id-123".to_string()),
            aud: Some("api-audience".to_string()),
            iss: Some("https://auth.example.com".to_string()),
            jti: Some("jwt-id-123".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"scope\":\"read write\""));
        assert!(json.contains("\"client_id\":\"client-123\""));
    }

    #[test]
    fn test_inactive_token_response() {
        let response = IntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, "{\"active\":false}");
    }

    #[test]
    fn test_extract_audience_string() {
        let aud = Some(serde_json::Value::String("api-audience".to_string()));
        assert_eq!(extract_audience(&aud), Some("api-audience".to_string()));
    }

    #[test]
    fn test_extract_audience_array() {
        let aud = Some(serde_json::Value::Array(vec![
            serde_json::Value::String("api1".to_string()),
            serde_json::Value::String("api2".to_string()),
        ]));
        assert_eq!(extract_audience(&aud), Some("api1 api2".to_string()));
    }
}
