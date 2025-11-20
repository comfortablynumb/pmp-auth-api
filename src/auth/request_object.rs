// Request Object (RFC 9101)
// This module implements support for passing authorization request parameters as JWTs

use crate::auth::oauth2_server::AuthorizeRequest;
use crate::models::OAuth2ServerConfig;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

/// Request object claims (RFC 9101)
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestObjectClaims {
    /// Issuer (client_id)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (authorization server)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// Response type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    /// Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Redirect URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// State
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// PKCE code challenge
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// PKCE code challenge method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// Response mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    /// Prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Max age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// ACR values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
    /// Claims (as JSON string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<String>,
    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
    /// Issued at time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    /// Not before time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Parse and validate a request object JWT
pub async fn parse_request_object(
    request_jwt: &str,
    client_id: &str,
    oauth2_config: &OAuth2ServerConfig,
    client_jwks_uri: Option<&str>,
    client_jwks: Option<&serde_json::Value>,
) -> Result<RequestObjectClaims, (StatusCode, Json<serde_json::Value>)> {
    info!("Parsing request object for client '{}'", client_id);

    // Get the public key for validation
    // Try client's JWKS first, then fall back to client assertion key
    let public_key_pem = if let Some(jwks) = client_jwks {
        // Extract first key from JWKS
        extract_public_key_from_jwks(jwks)?
    } else if let Some(jwks_uri) = client_jwks_uri {
        // Fetch JWKS from URI
        fetch_jwks_and_extract_key(jwks_uri).await?
    } else {
        // For testing or when client doesn't have JWKS, use server's public key
        // In production, this should require client JWKS
        warn!(
            "Client '{}' has no JWKS configured, using server public key for request object validation",
            client_id
        );
        load_key_pem(&oauth2_config.signing_key.public_key)?
    };

    // Decode JWT header to get algorithm
    let header = jsonwebtoken::decode_header(request_jwt).map_err(|e| {
        warn!("Failed to decode request object header: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request_object",
                "error_description": "Invalid request object format"
            })),
        )
    })?;

    let algorithm = header.alg;

    // Create decoding key
    let decoding_key = match algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
                warn!("Failed to parse RSA public key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to parse public key"
                    })),
                )
            })?
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(public_key_pem.as_bytes()).map_err(|e| {
                warn!("Failed to parse EC public key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to parse public key"
                    })),
                )
            })?
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request_object",
                    "error_description": format!("Unsupported algorithm: {:?}", algorithm)
                })),
            ));
        }
    };

    // Set up validation
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["iss"]); // Most claims are optional in request objects

    // Decode and validate
    let token_data = decode::<RequestObjectClaims>(request_jwt, &decoding_key, &validation)
        .map_err(|e| {
            warn!("Request object validation failed: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request_object",
                    "error_description": "Request object validation failed"
                })),
            )
        })?;

    let claims = token_data.claims;

    // Validate issuer matches client_id
    if let Some(ref iss) = claims.iss {
        if iss != client_id {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request_object",
                    "error_description": "Request object issuer does not match client_id"
                })),
            ));
        }
    }

    // Validate client_id in claims matches
    if let Some(ref claim_client_id) = claims.client_id {
        if claim_client_id != client_id {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request_object",
                    "error_description": "Request object client_id does not match"
                })),
            ));
        }
    }

    debug!(
        "Successfully validated request object for client '{}'",
        client_id
    );

    Ok(claims)
}

/// Fetch JWKS from URI and extract public key
async fn fetch_jwks_and_extract_key(
    jwks_uri: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| {
            warn!("Failed to create HTTP client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to fetch client JWKS"
                })),
            )
        })?;

    let response = client.get(jwks_uri).send().await.map_err(|e| {
        warn!("Failed to fetch JWKS from {}: {}", jwks_uri, e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": "Failed to fetch client JWKS"
            })),
        )
    })?;

    let jwks: serde_json::Value = response.json().await.map_err(|e| {
        warn!("Failed to parse JWKS response: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": "Invalid JWKS format"
            })),
        )
    })?;

    extract_public_key_from_jwks(&jwks)
}

/// Extract public key from JWKS
fn extract_public_key_from_jwks(
    jwks: &serde_json::Value,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client_metadata",
                    "error_description": "JWKS must contain 'keys' array"
                })),
            )
        })?;

    if keys.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": "JWKS keys array is empty"
            })),
        ));
    }

    // Use the first key for now
    let key = &keys[0];

    // Convert JWK to PEM format
    // This is a simplified version - in production, use a proper JWK to PEM converter
    jwk_to_pem(key)
}

/// Convert JWK to PEM format
fn jwk_to_pem(
    jwk: &serde_json::Value,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    // First, try x5c (certificate chain) if present
    if let Some(x5c) = jwk.get("x5c").and_then(|c| c.as_array()) {
        if let Some(cert) = x5c.first().and_then(|c| c.as_str()) {
            return Ok(format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                cert
            ));
        }
    }

    // Get key type
    let kty = jwk
        .get("kty")
        .and_then(|k| k.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client_metadata",
                    "error_description": "JWK must contain 'kty' field"
                })),
            )
        })?;

    match kty {
        "RSA" => {
            // Extract n and e for RSA public key
            let n_str = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": "RSA JWK must contain 'n' parameter"
                        })),
                    )
                })?;

            let e_str = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": "RSA JWK must contain 'e' parameter"
                        })),
                    )
                })?;

            // Decode base64url encoded values
            let n_bytes = URL_SAFE_NO_PAD.decode(n_str).map_err(|e| {
                warn!("Failed to decode RSA modulus: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid base64url encoding in 'n' parameter"
                    })),
                )
            })?;

            let e_bytes = URL_SAFE_NO_PAD.decode(e_str).map_err(|e| {
                warn!("Failed to decode RSA exponent: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid base64url encoding in 'e' parameter"
                    })),
                )
            })?;

            // Convert to BigNum
            let n = BigNum::from_slice(&n_bytes).map_err(|e| {
                warn!("Failed to create BigNum from modulus: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid RSA modulus"
                    })),
                )
            })?;

            let e = BigNum::from_slice(&e_bytes).map_err(|e| {
                warn!("Failed to create BigNum from exponent: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid RSA exponent"
                    })),
                )
            })?;

            // Build RSA public key
            let rsa = Rsa::from_public_components(n, e).map_err(|e| {
                warn!("Failed to construct RSA public key: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Failed to construct RSA public key"
                    })),
                )
            })?;

            // Convert to PKey and then to PEM
            let pkey = PKey::from_rsa(rsa).map_err(|e| {
                warn!("Failed to create PKey from RSA: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to create public key"
                    })),
                )
            })?;

            let pem = pkey.public_key_to_pem().map_err(|e| {
                warn!("Failed to convert RSA key to PEM: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to encode public key"
                    })),
                )
            })?;

            String::from_utf8(pem).map_err(|e| {
                warn!("Failed to convert PEM to string: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Invalid PEM encoding"
                    })),
                )
            })
        }
        "EC" => {
            // Extract crv, x, and y for EC public key
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": "EC JWK must contain 'crv' parameter"
                        })),
                    )
                })?;

            let x_str = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": "EC JWK must contain 'x' parameter"
                        })),
                    )
                })?;

            let y_str = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": "EC JWK must contain 'y' parameter"
                        })),
                    )
                })?;

            // Map curve name to Nid
            let nid = match crv {
                "P-256" | "prime256v1" => Nid::X9_62_PRIME256V1,
                "P-384" | "secp384r1" => Nid::SECP384R1,
                "P-521" | "secp521r1" => Nid::SECP521R1,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_client_metadata",
                            "error_description": format!("Unsupported EC curve: {}", crv)
                        })),
                    ));
                }
            };

            // Decode coordinates
            let x_bytes = URL_SAFE_NO_PAD.decode(x_str).map_err(|e| {
                warn!("Failed to decode EC x coordinate: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid base64url encoding in 'x' parameter"
                    })),
                )
            })?;

            let y_bytes = URL_SAFE_NO_PAD.decode(y_str).map_err(|e| {
                warn!("Failed to decode EC y coordinate: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid base64url encoding in 'y' parameter"
                    })),
                )
            })?;

            // Convert to BigNum
            let x = BigNum::from_slice(&x_bytes).map_err(|e| {
                warn!("Failed to create BigNum from x coordinate: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid EC x coordinate"
                    })),
                )
            })?;

            let y = BigNum::from_slice(&y_bytes).map_err(|e| {
                warn!("Failed to create BigNum from y coordinate: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid EC y coordinate"
                    })),
                )
            })?;

            // Create EC group and key
            let group = EcGroup::from_curve_name(nid).map_err(|e| {
                warn!("Failed to create EC group: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to create EC group"
                    })),
                )
            })?;

            let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(|e| {
                warn!("Failed to create EC key from coordinates: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "Invalid EC public key coordinates"
                    })),
                )
            })?;

            // Convert to PKey and then to PEM
            let pkey = PKey::from_ec_key(ec_key).map_err(|e| {
                warn!("Failed to create PKey from EC key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to create public key"
                    })),
                )
            })?;

            let pem = pkey.public_key_to_pem().map_err(|e| {
                warn!("Failed to convert EC key to PEM: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to encode public key"
                    })),
                )
            })?;

            String::from_utf8(pem).map_err(|e| {
                warn!("Failed to convert PEM to string: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Invalid PEM encoding"
                    })),
                )
            })
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": format!("Unsupported key type: {}", kty)
            })),
        )),
    }
}

/// Load a key from either a file path or inline PEM
fn load_key_pem(key_config: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    if key_config.starts_with("-----BEGIN") {
        Ok(key_config.to_string())
    } else {
        std::fs::read_to_string(key_config).map_err(|e| {
            warn!("Failed to read key file '{}': {}", key_config, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to load public key"
                })),
            )
        })
    }
}

/// Merge request object claims with URL parameters
/// URL parameters take precedence for client_id and redirect_uri (security)
pub fn merge_request_params(
    url_params: &AuthorizeRequest,
    request_claims: RequestObjectClaims,
) -> AuthorizeRequest {
    AuthorizeRequest {
        // client_id and redirect_uri from URL take precedence (security requirement)
        client_id: url_params.client_id.clone(),
        redirect_uri: url_params.redirect_uri.clone(),

        // Other parameters from request object, fallback to URL params
        response_type: request_claims
            .response_type
            .unwrap_or_else(|| url_params.response_type.clone()),
        scope: request_claims
            .scope
            .or_else(|| url_params.scope.clone()),
        state: request_claims
            .state
            .or_else(|| url_params.state.clone()),
        nonce: request_claims
            .nonce
            .or_else(|| url_params.nonce.clone()),
        code_challenge: request_claims
            .code_challenge
            .or_else(|| url_params.code_challenge.clone()),
        code_challenge_method: request_claims
            .code_challenge_method
            .or_else(|| url_params.code_challenge_method.clone()),
        session_id: url_params.session_id.clone(),
        response_mode: request_claims
            .response_mode
            .or_else(|| url_params.response_mode.clone()),
        prompt: request_claims
            .prompt
            .or_else(|| url_params.prompt.clone()),
        max_age: request_claims
            .max_age
            .or(url_params.max_age),
        acr_values: request_claims
            .acr_values
            .or_else(|| url_params.acr_values.clone()),
        claims: request_claims
            .claims
            .or_else(|| url_params.claims.clone()),
        // Request object already processed, set to None
        request: None,
        request_uri: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_object_claims_serialization() {
        let claims = RequestObjectClaims {
            iss: Some("client-123".to_string()),
            aud: Some(serde_json::Value::String("https://auth.example.com".to_string())),
            response_type: Some("code".to_string()),
            client_id: Some("client-123".to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            scope: Some("openid profile".to_string()),
            state: Some("state123".to_string()),
            nonce: Some("nonce123".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            response_mode: Some("query".to_string()),
            prompt: Some("consent".to_string()),
            max_age: Some(3600),
            acr_values: None,
            claims: None,
            exp: Some(1234567890),
            iat: Some(1234567800),
            nbf: None,
            jti: Some("req-123".to_string()),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"client-123\""));
        assert!(json.contains("\"response_type\":\"code\""));
    }

    #[test]
    fn test_merge_request_params_url_precedence() {
        let url_params = AuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "url-client".to_string(),
            redirect_uri: "https://url.example.com/callback".to_string(),
            scope: Some("openid".to_string()),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            response_mode: None,
            prompt: None,
            max_age: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
        };

        let request_claims = RequestObjectClaims {
            iss: Some("request-client".to_string()),
            aud: None,
            response_type: Some("code id_token".to_string()),
            client_id: Some("request-client".to_string()),
            redirect_uri: Some("https://request.example.com/callback".to_string()),
            scope: Some("openid profile email".to_string()),
            state: Some("request-state".to_string()),
            nonce: Some("request-nonce".to_string()),
            code_challenge: Some("request-challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            response_mode: Some("form_post".to_string()),
            prompt: Some("consent".to_string()),
            max_age: Some(3600),
            acr_values: None,
            claims: None,
            exp: None,
            iat: None,
            nbf: None,
            jti: None,
        };

        let merged = merge_request_params(&url_params, request_claims);

        // URL params take precedence for security-sensitive parameters
        assert_eq!(merged.client_id, "url-client");
        assert_eq!(merged.redirect_uri, "https://url.example.com/callback");

        // Request object params are used for other parameters
        assert_eq!(merged.response_type, "code id_token");
        assert_eq!(merged.scope, Some("openid profile email".to_string()));
        assert_eq!(merged.state, Some("request-state".to_string()));
        assert_eq!(merged.nonce, Some("request-nonce".to_string()));
        assert_eq!(merged.code_challenge, Some("request-challenge".to_string()));
        assert_eq!(merged.response_mode, Some("form_post".to_string()));
    }
}
