// Back-Channel Logout Implementation (RFC 8965)
// This module implements server-initiated logout notifications to clients

use crate::models::OAuth2ServerConfig;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

/// Logout Token Claims (RFC 8965 Section 2.4)
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    /// Issuer - must be the same as in ID tokens
    pub iss: String,
    /// Subject - user identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience - client_id(s) that should process this logout
    pub aud: Vec<String>,
    /// Issued at time
    pub iat: usize,
    /// JWT ID - unique identifier for this logout token
    pub jti: String,
    /// Events claim - MUST contain logout event
    pub events: LogoutEvents,
    /// Session ID (sid) - from the original authentication session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

/// Logout events structure
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutEvents {
    /// The back-channel logout event
    #[serde(rename = "http://schemas.openid.net/event/backchannel-logout")]
    pub backchannel_logout: serde_json::Value,
}

/// Back-channel logout request to send to client
#[derive(Debug, Serialize)]
pub struct BackchannelLogoutRequest {
    /// The logout token (JWT)
    pub logout_token: String,
}

/// Generate a logout token (RFC 8965)
pub fn generate_logout_token(
    user_id: Option<&str>,
    session_id: Option<&str>,
    client_id: &str,
    issuer: &str,
    oauth2_config: &OAuth2ServerConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp() as usize;
    let jti = uuid::Uuid::new_v4().to_string();

    // RFC 8965 Section 2.6: Either sub or sid MUST be present
    if user_id.is_none() && session_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Either user_id or session_id must be provided"
            })),
        ));
    }

    let claims = LogoutTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.map(|s| s.to_string()),
        aud: vec![client_id.to_string()],
        iat: now,
        jti,
        events: LogoutEvents {
            backchannel_logout: json!({}),
        },
        sid: session_id.map(|s| s.to_string()),
    };

    // Load private key for signing
    let private_key_pem = load_key_pem(&oauth2_config.signing_key.private_key).map_err(|e| {
        warn!("Failed to load private key for logout token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to load signing key"
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

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse private key for logout token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Invalid signing key format"
            })),
        )
    })?;

    let mut header = Header::new(algorithm);
    header.kid = Some(oauth2_config.signing_key.kid.clone());

    encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode logout token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "Failed to generate logout token"
            })),
        )
    })
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

/// Send logout notification to a client's backchannel logout URI
pub async fn notify_client_logout(
    backchannel_logout_uri: &str,
    logout_token: &str,
) -> Result<(), String> {
    debug!(
        "Sending logout notification to: {}",
        backchannel_logout_uri
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .post(backchannel_logout_uri)
        .form(&[("logout_token", logout_token)])
        .send()
        .await
        .map_err(|e| format!("Failed to send logout request: {}", e))?;

    if response.status().is_success() {
        info!(
            "Successfully sent logout notification to {}",
            backchannel_logout_uri
        );
        Ok(())
    } else {
        warn!(
            "Logout notification to {} failed with status: {}",
            backchannel_logout_uri,
            response.status()
        );
        Err(format!(
            "Logout notification failed with status: {}",
            response.status()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::JwkSigningConfig;

    #[test]
    fn test_logout_token_claims_serialization() {
        let claims = LogoutTokenClaims {
            iss: "https://example.com".to_string(),
            sub: Some("user123".to_string()),
            aud: vec!["client1".to_string()],
            iat: 1234567890,
            jti: "logout-123".to_string(),
            events: LogoutEvents {
                backchannel_logout: json!({}),
            },
            sid: Some("session-456".to_string()),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"https://example.com\""));
        assert!(json.contains("\"sub\":\"user123\""));
        assert!(json.contains("\"sid\":\"session-456\""));
        assert!(json.contains("http://schemas.openid.net/event/backchannel-logout"));
    }

    #[test]
    fn test_generate_logout_token_requires_sub_or_sid() {
        let oauth2_config = OAuth2ServerConfig {
            issuer: "https://example.com".to_string(),
            grant_types: vec!["authorization_code".to_string()],
            token_endpoint: "/oauth/token".to_string(),
            authorize_endpoint: "/oauth/authorize".to_string(),
            jwks_endpoint: "/.well-known/jwks.json".to_string(),
            access_token_expiration_secs: 3600,
            refresh_token_expiration_secs: 86400,
            password_grant_enabled: false,
            signing_key: JwkSigningConfig {
                algorithm: "RS256".to_string(),
                kid: "test-key".to_string(),
                private_key: "/path/to/key.pem".to_string(),
                public_key: "/path/to/pub.pem".to_string(),
            },
        };

        // Should fail when both user_id and session_id are None
        let result = generate_logout_token(None, None, "client1", "https://example.com", &oauth2_config);
        assert!(result.is_err());
    }
}
