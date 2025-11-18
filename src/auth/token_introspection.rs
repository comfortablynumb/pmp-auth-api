// Token Introspection and Revocation (RFC 7662, RFC 7009)
// Allows resource servers to validate tokens and revoke access

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
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
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Token introspection request for tenant '{}', token_type_hint: {:?}",
        tenant_id, request.token_type_hint
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Try to decode and validate the token
    // We'll try different signing keys (OAuth2, API keys, etc.)
    let introspection_result = introspect_token(&request.token, tenant, &tenant_id, &state).await;

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
async fn introspect_token(
    token: &str,
    tenant: &crate::models::Tenant,
    _tenant_id: &str,
    state: &AppState,
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

            // Check if token is revoked using storage backend
            if let Some(jti) = &claims.jti {
                match state.storage.is_token_revoked(jti).await {
                    Ok(true) => {
                        debug!("Token with JTI '{}' is revoked", jti);
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
                    Ok(false) => {
                        // Token not revoked, continue
                    }
                    Err(e) => {
                        warn!("Failed to check token revocation status: {}", e);
                        // Continue - don't fail on storage errors
                    }
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

/// Decode JWT with a public key and validate signature
fn decode_with_key(token: &str, public_key_pem: &str) -> Result<TokenClaims, String> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    // Load the public key from PEM (either file path or inline PEM)
    let public_key_content = load_key_pem(public_key_pem)?;

    // Create decoding key from RSA public key PEM
    let decoding_key = DecodingKey::from_rsa_pem(public_key_content.as_bytes())
        .map_err(|e| format!("Failed to parse public key: {}", e))?;

    // Set up validation parameters
    // We'll accept multiple algorithms and let the JWT header determine which one
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp"]); // Require expiration claim
    validation.validate_exp = false; // We'll manually validate expiration to control the response

    // Try to decode and validate the token
    let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;

    Ok(token_data.claims)
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
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<RevocationRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Token revocation request for tenant '{}', token_type_hint: {:?}",
        tenant_id, request.token_type_hint
    );

    // Get tenant configuration
    let _tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Try to parse the token to get the JTI for revocation
    let parts: Vec<&str> = request.token.split('.').collect();
    if parts.len() == 3 {
        // Decode payload
        use base64::{engine::general_purpose::STANDARD, Engine as _};
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
                } else if let Some(jti) = claims.jti {
                    // For OAuth2 tokens, store revocation in the database
                    let expires_at = claims
                        .exp
                        .and_then(|exp| chrono::DateTime::from_timestamp(exp as i64, 0))
                        .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(30));

                    match state.storage.revoke_token(&jti, expires_at).await {
                        Ok(_) => {
                            info!("Token with JTI '{}' revoked successfully", jti);
                        }
                        Err(e) => {
                            warn!("Failed to revoke token with JTI '{}': {}", jti, e);
                            // Continue - RFC 7009 says always return 200 OK
                        }
                    }
                } else {
                    warn!("Token has no JTI claim, cannot revoke: {}", claims.sub);
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
