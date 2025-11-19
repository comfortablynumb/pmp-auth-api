// OpenID Connect Provider Implementation
// This module implements the OIDC provider functionality on top of OAuth2

use crate::auth::identity_backend::create_identity_backend;
use crate::models::{Claims, OAuth2ServerConfig, OidcProviderConfig};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::{debug, info, warn};

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

    // Hash claims (for hybrid/implicit flows)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>, // Access token hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>, // Code hash

    // Authentication context claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>, // Authentication Context Class Reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>, // Authentication Methods References
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>, // Authorized party (client_id if different from aud)

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
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!("OIDC discovery request for tenant '{}'", tenant_id);

    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
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
        // Standard OIDC Discovery metadata (RFC 8414)
        "issuer": oidc_config.issuer,
        "authorization_endpoint": format!("{}{}", base_url, oauth2_config.authorize_endpoint),
        "token_endpoint": format!("{}{}", base_url, oauth2_config.token_endpoint),
        "userinfo_endpoint": format!("{}{}", base_url, oidc_config.userinfo_endpoint),
        "jwks_uri": format!("{}{}", base_url, oauth2_config.jwks_endpoint),

        // Token endpoints
        "revocation_endpoint": format!("{}/oauth/revoke", base_url),
        "introspection_endpoint": format!("{}/oauth/introspect", base_url),

        // Device authorization endpoint (RFC 8628)
        "device_authorization_endpoint": format!("{}/oauth/device/authorize", base_url),

        // Dynamic client registration (RFC 7591)
        "registration_endpoint": format!("{}/oauth/register", base_url),

        // Session management
        "end_session_endpoint": format!("{}/oauth/logout", base_url),
        "check_session_iframe": format!("{}/oauth/check_session_iframe", base_url),

        // Supported features
        "scopes_supported": oidc_config.scopes_supported,
        "response_types_supported": ["code", "code id_token", "code token", "code id_token token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": oauth2_config.grant_types,
        "subject_types_supported": ["public"],

        // Token signing and encryption
        "id_token_signing_alg_values_supported": [&oauth2_config.signing_key.algorithm],
        "userinfo_signing_alg_values_supported": [&oauth2_config.signing_key.algorithm],
        "id_token_encryption_alg_values_supported": [],
        "id_token_encryption_enc_values_supported": [],

        // Claims
        "claims_supported": oidc_config.claims_supported,
        "claims_parameter_supported": false,

        // Authentication
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],

        // PKCE (RFC 7636)
        "code_challenge_methods_supported": ["S256", "plain"],

        // Request object support (RFC 9101)
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "request_object_signing_alg_values_supported": [],

        // ACR (Authentication Context Class Reference)
        "acr_values_supported": [],

        // Additional metadata
        "service_documentation": "https://github.com/comfortablynumb/pmp-auth-api",
        "ui_locales_supported": ["en-US"],
        "op_policy_uri": format!("{}/policy", base_url),
        "op_tos_uri": format!("{}/terms", base_url),

        // Back-Channel Logout (RFC 8965)
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    })))
}

/// OpenID Connect Userinfo Endpoint
/// GET /api/v1/tenant/{tenant_id}/oauth/userinfo
///
/// Returns user information in JSON format by default, or as signed JWT if requested
/// via Accept: application/jwt header
pub async fn oidc_userinfo(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    debug!("OIDC userinfo request for tenant '{}'", tenant_id);

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
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

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_token_format" })),
        )
    })?;

    // Get OAuth2 config for token validation
    let oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oauth2_not_enabled" })),
        )
    })?;

    // Load public key for token validation
    let public_key_pem = load_key_pem(&oauth2_config.signing_key.public_key).map_err(|e| {
        warn!("Failed to load public key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load public key" })),
        )
    })?;

    // Validate JWT signature and decode claims
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

    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse public key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Invalid public key format" })),
        )
    })?;

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.set_required_spec_claims(&["sub", "exp"]);

    // Decode and validate the token
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

    info!(
        "Token validated successfully for user: {}",
        token_data.claims.sub
    );

    // Retrieve user information from identity backend
    let backend = create_identity_backend(&tenant.identity_backend);
    let user = backend
        .get_user_by_id(&token_data.claims.sub)
        .map_err(|e| {
            warn!("Failed to retrieve user from backend: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to retrieve user information"
                })),
            )
        })?;

    // Build userinfo response with real user data
    let userinfo = UserinfoResponse {
        sub: user.id,
        name: user.name,
        email: Some(user.email.clone()),
        email_verified: Some(true), // Could be retrieved from user attributes
        picture: user.picture,
        preferred_username: Some(user.email),
        role: Some(format!("{:?}", user.role)),
    };

    // Check if client wants signed JWT response (via Accept header)
    let accept_header = headers
        .get("Accept")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if accept_header.contains("application/jwt") {
        // Return signed JWT
        debug!("Returning signed JWT userinfo for user: {}", userinfo.sub);

        // Get OIDC config for JWT signing
        let oidc_config = tenant.identity_provider.oidc.as_ref().unwrap(); // Already validated above

        let now = Utc::now().timestamp() as usize;
        let exp = now + 300; // 5 minutes validity

        // Create claims from userinfo
        let claims = OidcClaims {
            iss: oidc_config.issuer.clone(),
            sub: userinfo.sub.clone(),
            aud: vec![tenant_id.clone()], // Could be more specific
            exp,
            iat: now,
            auth_time: now,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: None,
            azp: None,
            name: userinfo.name.clone(),
            email: userinfo.email.clone(),
            email_verified: userinfo.email_verified,
            picture: userinfo.picture.clone(),
            preferred_username: userinfo.preferred_username.clone(),
        };

        // Load private key
        let private_key_pem = load_key_pem(&oauth2_config.signing_key.private_key).map_err(|e| {
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
        header.kid = Some(oauth2_config.signing_key.kid.clone());

        let jwt = encode(&header, &claims, &encoding_key).map_err(|e| {
            warn!("Failed to encode userinfo JWT: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error", "error_description": "Failed to generate userinfo JWT" })),
            )
        })?;

        // Return JWT with proper content-type
        use axum::response::IntoResponse;
        Ok((
            [(axum::http::header::CONTENT_TYPE, "application/jwt")],
            jwt,
        )
            .into_response())
    } else {
        // Return JSON (default)
        debug!("Returning JSON userinfo for user: {}", userinfo.sub);
        use axum::response::IntoResponse;
        Ok(Json(userinfo).into_response())
    }
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

/// Calculate hash for at_hash or c_hash claims
/// According to OIDC spec, hash is the left-most half of the hash of the octets
/// of the ASCII representation of the value, using the hash algorithm specified
/// by the ID token's signing algorithm
fn calculate_hash(value: &str, algorithm: &Algorithm) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let hash_bytes = match algorithm {
        Algorithm::RS256 | Algorithm::HS256 | Algorithm::ES256 => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hasher.finalize().to_vec()
        }
        Algorithm::RS384 | Algorithm::HS384 | Algorithm::ES384 => {
            let mut hasher = Sha384::new();
            hasher.update(value.as_bytes());
            hasher.finalize().to_vec()
        }
        Algorithm::RS512 | Algorithm::HS512 => {
            let mut hasher = Sha512::new();
            hasher.update(value.as_bytes());
            hasher.finalize().to_vec()
        }
        _ => {
            // For unsupported algorithms, default to SHA256
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hasher.finalize().to_vec()
        }
    };

    // Take the left-most half of the hash
    let half_len = hash_bytes.len() / 2;
    let hash_half = &hash_bytes[..half_len];

    // Base64url encode
    URL_SAFE_NO_PAD.encode(hash_half)
}

/// Generate an OpenID Connect ID token
pub fn generate_id_token(
    user_id: &str,
    email: &str,
    name: Option<String>,
    client_id: &str,
    nonce: Option<String>,
    access_token: Option<&str>,
    authorization_code: Option<&str>,
    acr_values: Option<String>,
    amr_values: Option<Vec<String>>,
    oauth2_config: &OAuth2ServerConfig,
    oidc_config: &OidcProviderConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp() as usize;
    let exp = now + oidc_config.id_token_expiration_secs as usize;

    // Determine algorithm first (needed for hash calculation)
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

    // Calculate at_hash and c_hash if access_token or code provided
    let at_hash = access_token.map(|token| calculate_hash(token, &algorithm));
    let c_hash = authorization_code.map(|code| calculate_hash(code, &algorithm));

    // Determine azp (authorized party) - only include if different from first audience
    // This is typically used in multi-client scenarios
    let azp = None; // Can be set to client_id if needed for specific flows

    let claims = OidcClaims {
        iss: oidc_config.issuer.clone(),
        sub: user_id.to_string(),
        aud: vec![client_id.to_string()],
        exp,
        iat: now,
        auth_time: now,
        nonce,
        at_hash,
        c_hash,
        acr: acr_values,
        amr: amr_values,
        azp,
        name,
        email: Some(email.to_string()),
        email_verified: Some(true),
        picture: None,
        preferred_username: Some(email.to_string()),
    };

    // Load private key from tenant configuration
    let private_key_pem = load_key_pem(&oauth2_config.signing_key.private_key).map_err(|e| {
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
    header.kid = Some(oauth2_config.signing_key.kid.clone());

    encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode ID token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to generate ID token" })),
        )
    })
}

/// OIDC Session Management - Check Session iFrame endpoint
/// Returns an HTML page with JavaScript that monitors session state
/// Reference: OpenID Connect Session Management 1.0
pub async fn check_session_iframe(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    debug!("Check session iframe request for tenant '{}'", tenant_id);

    // Verify tenant exists and has OIDC enabled
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    let _oidc_config = tenant.identity_provider.oidc.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oidc_not_enabled" })),
        )
    })?;

    // Generate the HTML page with JavaScript for session monitoring
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>OIDC Session Management</title>
    <meta charset="utf-8">
</head>
<body>
<script>
    // OpenID Connect Session Management 1.0 - OP iframe
    // This iframe receives session state checks from the RP

    var targetOrigin = '*'; // Should be restricted to RP origin in production
    var currentSessionState = null;

    // Calculate session state based on client_id, origin, and OP session
    function getSessionState(clientId, origin) {
        // Get the OP session cookie
        var opBrowserState = getOpBrowserState();

        if (!opBrowserState) {
            return 'changed'; // No session
        }

        // Calculate session state hash
        // Format: client_id + ' ' + origin + ' ' + opBrowserState + salt
        var salt = generateSalt();
        var sessionStr = clientId + ' ' + origin + ' ' + opBrowserState + ' ' + salt;

        // Hash the session string
        return sha256(sessionStr) + '.' + salt;
    }

    // Get OP browser state from cookie
    function getOpBrowserState() {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = cookies[i].trim();
            if (cookie.startsWith('session_state=')) {
                return cookie.substring('session_state='.length);
            }
        }
        return null;
    }

    // Generate a random salt
    function generateSalt() {
        var array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, function(byte) {
            return ('0' + byte.toString(16)).slice(-2);
        }).join('');
    }

    // Simple SHA-256 implementation (in production, use WebCrypto API)
    function sha256(str) {
        // This is a placeholder - in production use:
        // crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            var char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16);
    }

    // Handle messages from RP
    window.addEventListener('message', function(e) {
        // Parse the message
        var message = e.data;
        var parts = message.split(' ');

        if (parts.length !== 2) {
            postMessage('error', e.origin);
            return;
        }

        var clientId = parts[0];
        var sessionState = parts[1];

        // Calculate current session state
        var currentState = getSessionState(clientId, e.origin);

        // Compare with provided session state
        var stat = 'changed';
        if (sessionState === currentState) {
            stat = 'unchanged';
        }

        // Send response back to RP
        postMessage(stat, e.origin);
    }, false);

    function postMessage(stat, targetOrigin) {
        parent.postMessage(stat, targetOrigin);
    }

    // Set up periodic session check
    var checkInterval = 3000; // Check every 3 seconds
    setInterval(function() {
        // Notify parent to check session
        // This is a simplified version - full spec requires more complex state management
    }, checkInterval);
</script>
</body>
</html>"#;

    // Return HTML response with proper content type
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        ),
        (axum::http::header::CACHE_CONTROL, "no-store"),
        (axum::http::header::PRAGMA, "no-cache")],
        html,
    )
        .into_response())
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
            at_hash: Some("abc123hash".to_string()),
            c_hash: None,
            acr: Some("urn:mace:incommon:iap:silver".to_string()),
            amr: Some(vec!["pwd".to_string(), "mfa".to_string()]),
            azp: None,
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
