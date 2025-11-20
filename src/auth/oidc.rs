// OpenID Connect Provider Implementation
// This module implements the OIDC provider functionality on top of OAuth2

use crate::auth::identity_storage::create_identity_storage_with_backend;
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
    #[serde(skip_serializing_if = "Option::is_none")]
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

    // Session management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>, // Session ID (for logout coordination)

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
#[derive(Debug, Serialize, Deserialize)]
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
    let (oidc_config, _oidc_storage_id) = tenant.get_oidc_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oidc_not_enabled" })),
        )
    })?;

    let (oauth2_config, _oauth2_storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
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
        "response_types_supported": [
            "code",
            "code id_token",
            "code token",
            "code id_token token",
            "id_token",
            "token",
            "id_token token"
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": oauth2_config.grant_types,
        "subject_types_supported": ["public"],

        // Token signing and encryption
        "id_token_signing_alg_values_supported": [&oauth2_config.signing_key.algorithm],
        "userinfo_signing_alg_values_supported": [&oauth2_config.signing_key.algorithm],
        "id_token_encryption_alg_values_supported": oidc_config.id_token_encryption_alg_values_supported,
        "id_token_encryption_enc_values_supported": oidc_config.id_token_encryption_enc_values_supported,

        // Claims
        "claims_supported": oidc_config.claims_supported,
        "claims_parameter_supported": false,

        // Authentication
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],

        // PKCE (RFC 7636)
        "code_challenge_methods_supported": ["S256", "plain"],

        // Request object support (RFC 9101)
        "request_parameter_supported": oauth2_config.request_parameter_supported,
        "request_uri_parameter_supported": oauth2_config.request_uri_parameter_supported,
        "require_request_uri_registration": oauth2_config.require_request_uri_registration,
        "request_object_signing_alg_values_supported": oauth2_config.request_object_signing_alg_values_supported,

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

        // Front-Channel Logout (OpenID Connect Front-Channel Logout 1.0)
        "frontchannel_logout_supported": true,
        "frontchannel_logout_session_supported": true,
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

    // Check if OIDC is enabled and get storage_id
    let (_oidc_config, oidc_storage_id) = tenant.get_oidc_provider().ok_or_else(|| {
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
    let (oauth2_config, _oauth2_storage_id) = tenant.get_oauth2_provider().ok_or_else(|| {
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
    validation.validate_aud = false; // Don't validate audience for UserInfo endpoint
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

    // Retrieve user information from identity storage
    let identity_storage_config = state.config.get_identity_storage(&tenant_id, oidc_storage_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": format!("Identity storage '{}' not found", oidc_storage_id)
            })),
        )
    })?;

    // Check if we're using a test/memory URL - if so, use storage backend directly
    let is_memory_url = match identity_storage_config {
        crate::models::IdentityStorage::Database(db_config) => {
            db_config.connection_url.starts_with("memory://") || db_config.connection_url.starts_with("test://")
        }
        _ => false,
    };

    let user = if is_memory_url {
        // Direct lookup via StorageBackend for tests
        let user_data = state
            .storage
            .get_user(&token_data.claims.sub)
            .await
            .map_err(|e| {
                warn!("Failed to retrieve user '{}': {}", token_data.claims.sub, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to retrieve user information"
                    })),
                )
            })?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": "user_not_found",
                        "error_description": "User not found"
                    })),
                )
            })?;

        // Convert to StorageUser
        crate::auth::identity_storage::StorageUser {
            id: user_data.id,
            email: user_data.email,
            name: user_data.name,
            picture: user_data.picture,
            role: crate::models::UserRole::from_str(&user_data.role).unwrap_or(crate::models::UserRole::User),
            attributes: user_data.attributes,
        }
    } else {
        // Use identity storage for non-test environments
        let backend = create_identity_storage_with_backend(identity_storage_config, state.storage.clone(), &tenant_id);
        backend
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
            })?
    };

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
        let (oidc_config, _oidc_storage_id) = tenant.get_oidc_provider().unwrap(); // Already validated above

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
            sid: None, // No session ID for signed userinfo response
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
/// session_id is REQUIRED for proper session management
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
    session_id: String,
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
        sid: Some(session_id),
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

    let signed_id_token = encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode ID token: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to generate ID token" })),
        )
    })?;

    // Check if encryption is configured
    if let Some(ref encryption_config) = oidc_config.encryption_key {
        // Encrypt the signed ID token using JWE
        debug!("Encrypting ID token for client '{}'", client_id);
        crate::auth::id_token_encryption::encrypt_id_token(&signed_id_token, encryption_config)
    } else {
        // Return the signed ID token without encryption
        Ok(signed_id_token)
    }
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

    let (_oidc_config, _oidc_storage_id) = tenant.get_oidc_provider().ok_or_else(|| {
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
    async function getSessionState(clientId, origin) {
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
        var hash = await sha256(sessionStr);
        return hash + '.' + salt;
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

    // SHA-256 implementation using WebCrypto API
    async function sha256(str) {
        const msgBuffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');
        return hashHex;
    }

    // Handle messages from RP
    window.addEventListener('message', async function(e) {
        // Parse the message
        var message = e.data;
        var parts = message.split(' ');

        if (parts.length !== 2) {
            postMessage('error', e.origin);
            return;
        }

        var clientId = parts[0];
        var sessionState = parts[1];

        // Calculate current session state (async because of WebCrypto)
        var currentState = await getSessionState(clientId, e.origin);

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
            sid: None,
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

    // ID Token Claims Tests

    #[test]
    fn test_oidc_claims_with_all_fields() {
        let claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_id_12345".to_string(),
            aud: vec!["client_123".to_string(), "client_456".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567700,
            nonce: Some("nonce_xyz".to_string()),
            at_hash: Some("at_hash_abc".to_string()),
            c_hash: Some("c_hash_def".to_string()),
            acr: Some("urn:mace:incommon:iap:silver".to_string()),
            amr: Some(vec!["pwd".to_string(), "mfa".to_string()]),
            azp: Some("client_123".to_string()),
            name: Some("Alice Smith".to_string()),
            email: Some("alice@example.com".to_string()),
            email_verified: Some(true),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            preferred_username: Some("alice".to_string()),
            sid: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"https://auth.example.com\""));
        assert!(json.contains("\"sub\":\"user_id_12345\""));
        assert!(json.contains("\"nonce\":\"nonce_xyz\""));
        assert!(json.contains("\"at_hash\":\"at_hash_abc\""));
        assert!(json.contains("\"c_hash\":\"c_hash_def\""));
        assert!(json.contains("\"name\":\"Alice Smith\""));
        assert!(json.contains("\"email_verified\":true"));
    }

    #[test]
    fn test_oidc_claims_minimal() {
        // Minimal ID token with only required claims
        let claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec!["client_123".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567800,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: None,
            azp: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"iss\":\"https://auth.example.com\""));
        assert!(json.contains("\"sub\":\"user_123\""));
        assert!(json.contains("\"aud\""));
        // Optional fields should not be present
        assert!(!json.contains("\"nonce\""));
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"email\""));
    }

    #[test]
    fn test_oidc_claims_deserialization() {
        let json = r#"{
            "iss": "https://auth.example.com",
            "sub": "user_456",
            "aud": ["client_abc"],
            "exp": 1234567890,
            "iat": 1234567800,
            "auth_time": 1234567800,
            "nonce": "test_nonce",
            "email": "user@example.com",
            "email_verified": true
        }"#;

        let claims: OidcClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.sub, "user_456");
        assert_eq!(claims.aud.len(), 1);
        assert_eq!(claims.aud[0], "client_abc");
        assert_eq!(claims.nonce, Some("test_nonce".to_string()));
        assert_eq!(claims.email, Some("user@example.com".to_string()));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn test_oidc_claims_multiple_audiences() {
        let claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec![
                "client_1".to_string(),
                "client_2".to_string(),
                "client_3".to_string(),
            ],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567800,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: None,
            azp: Some("client_1".to_string()), // azp should match first audience
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        assert_eq!(claims.aud.len(), 3);
        assert_eq!(claims.azp, Some("client_1".to_string()));
    }

    // Authentication Context and Methods Tests

    #[test]
    fn test_oidc_acr_values() {
        // Test Authentication Context Class Reference values
        let acr_values = vec![
            "urn:mace:incommon:iap:bronze",
            "urn:mace:incommon:iap:silver",
            "urn:mace:incommon:iap:gold",
        ];

        for acr in acr_values {
            let claims = OidcClaims {
                iss: "https://auth.example.com".to_string(),
                sub: "user_123".to_string(),
                aud: vec!["client_123".to_string()],
                exp: 1234567890,
                iat: 1234567800,
                auth_time: 1234567800,
                nonce: None,
                at_hash: None,
                c_hash: None,
                acr: Some(acr.to_string()),
                amr: None,
                azp: None,
                name: None,
                email: None,
                email_verified: None,
                picture: None,
                preferred_username: None,
            sid: None,
            };

            assert!(claims.acr.unwrap().contains("urn:mace:incommon:iap"));
        }
    }

    #[test]
    fn test_oidc_amr_values() {
        // Test Authentication Methods References
        let claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec!["client_123".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567800,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: Some(vec![
                "pwd".to_string(),      // Password
                "mfa".to_string(),      // Multi-factor authentication
                "otp".to_string(),      // One-time password
                "hwk".to_string(),      // Hardware key
            ]),
            azp: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        let amr = claims.amr.unwrap();
        assert_eq!(amr.len(), 4);
        assert!(amr.contains(&"pwd".to_string()));
        assert!(amr.contains(&"mfa".to_string()));
        assert!(amr.contains(&"otp".to_string()));
        assert!(amr.contains(&"hwk".to_string()));
    }

    // Userinfo Response Tests

    #[test]
    fn test_userinfo_response_minimal() {
        let userinfo = UserinfoResponse {
            sub: "user_123".to_string(),
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            role: None,
        };

        let json = serde_json::to_string(&userinfo).unwrap();
        assert!(json.contains("\"sub\":\"user_123\""));
        // No optional fields should be present
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"email\""));
        assert!(!json.contains("\"role\""));
    }

    #[test]
    fn test_userinfo_response_with_all_fields() {
        let userinfo = UserinfoResponse {
            sub: "user_456".to_string(),
            name: Some("Bob Johnson".to_string()),
            email: Some("bob@example.com".to_string()),
            email_verified: Some(true),
            picture: Some("https://example.com/bob.jpg".to_string()),
            preferred_username: Some("bobby".to_string()),
            role: Some("user".to_string()),
        };

        let json = serde_json::to_string(&userinfo).unwrap();
        assert!(json.contains("\"sub\":\"user_456\""));
        assert!(json.contains("\"name\":\"Bob Johnson\""));
        assert!(json.contains("\"email\":\"bob@example.com\""));
        assert!(json.contains("\"email_verified\":true"));
        assert!(json.contains("\"picture\":\"https://example.com/bob.jpg\""));
        assert!(json.contains("\"preferred_username\":\"bobby\""));
        assert!(json.contains("\"role\":\"user\""));
    }

    #[test]
    fn test_userinfo_response_deserialization() {
        let json = r#"{
            "sub": "user_789",
            "name": "Charlie Brown",
            "email": "charlie@example.com",
            "email_verified": false
        }"#;

        let userinfo: UserinfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(userinfo.sub, "user_789");
        assert_eq!(userinfo.name, Some("Charlie Brown".to_string()));
        assert_eq!(userinfo.email, Some("charlie@example.com".to_string()));
        assert_eq!(userinfo.email_verified, Some(false));
    }

    // Hash Claims Tests (at_hash, c_hash)

    #[test]
    fn test_oidc_hash_claims() {
        // at_hash and c_hash should be present when access_token/code are issued
        let claims_with_hashes = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec!["client_123".to_string()],
            exp: 1234567890,
            iat: 1234567800,
            auth_time: 1234567800,
            nonce: Some("nonce_123".to_string()),
            at_hash: Some("access_token_hash".to_string()),
            c_hash: Some("code_hash".to_string()),
            acr: None,
            amr: None,
            azp: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        assert!(claims_with_hashes.at_hash.is_some());
        assert!(claims_with_hashes.c_hash.is_some());
        assert_eq!(claims_with_hashes.at_hash.unwrap(), "access_token_hash");
        assert_eq!(claims_with_hashes.c_hash.unwrap(), "code_hash");
    }

    // Timestamp Validation Tests

    #[test]
    fn test_oidc_timestamp_validation() {
        let now = chrono::Utc::now().timestamp() as usize;
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize;
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize;

        let claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec!["client_123".to_string()],
            exp: future,
            iat: past,
            auth_time: past,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: None,
            azp: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        // Verify timestamps are logical
        assert!(claims.iat < now);
        assert!(claims.exp > now);
        assert!(claims.auth_time <= claims.iat);
        assert!(claims.iat < claims.exp);
    }

    #[test]
    fn test_oidc_expired_token() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize;
        let now = chrono::Utc::now().timestamp() as usize;

        let expired_claims = OidcClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user_123".to_string(),
            aud: vec!["client_123".to_string()],
            exp: past,  // Expired
            iat: past - 3600,
            auth_time: past - 3600,
            nonce: None,
            at_hash: None,
            c_hash: None,
            acr: None,
            amr: None,
            azp: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            preferred_username: None,
            sid: None,
        };

        // Token is expired
        assert!(expired_claims.exp < now);
    }
}
