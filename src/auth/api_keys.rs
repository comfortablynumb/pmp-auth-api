// API Key Management Implementation
// This module handles long-lived JWT tokens for machine-to-machine authentication

use crate::models::ApiKeyConfig;
use crate::storage::ApiKeyData;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyClaims {
    pub sub: String,        // API Key ID
    pub iss: String,        // Issuer
    pub aud: Vec<String>,   // Audience
    pub exp: Option<usize>, // Expiration (None for no expiration)
    pub iat: usize,         // Issued at
    pub scope: String,      // Space-separated scopes
    pub api_key: bool,      // Flag to identify as API key
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in_days: Option<i64>, // None = no expiration
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub api_key: String, // The actual JWT token (only shown once)
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used: Option<i64>,
    pub revoked: bool,
}

/// Create a new API key
/// POST /api/v1/tenant/{tenant_id}/api-keys/create
pub async fn create_api_key(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Creating API key '{}' for tenant '{}'",
        request.name, tenant_id
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if API keys are enabled
    let api_key_config = tenant.api_keys.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "api_keys_not_enabled" })),
        )
    })?;

    if !api_key_config.enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "api_keys_disabled" })),
        ));
    }

    // Validate scopes
    for scope in &request.scopes {
        if !api_key_config.allowed_scopes.contains(scope) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_scope",
                    "error_description": format!("Scope '{}' is not allowed", scope)
                })),
            ));
        }
    }

    let key_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    // Calculate expiration
    let expires_at = if let Some(days) = request.expires_in_days {
        Some(now + (days * 86400))
    } else if api_key_config.expiration_secs > 0 {
        Some(now + api_key_config.expiration_secs)
    } else {
        None // No expiration
    };

    // Create metadata
    let created_at_dt = DateTime::from_timestamp(now, 0).unwrap_or_else(|| Utc::now());
    let expires_at_dt = expires_at.and_then(|ts| DateTime::from_timestamp(ts, 0));

    let metadata = ApiKeyData {
        id: key_id.clone(),
        tenant_id: tenant_id.clone(),
        name: request.name.clone(),
        scopes: request.scopes.clone(),
        created_at: created_at_dt,
        expires_at: expires_at_dt,
        last_used: None,
        revoked: false,
    };

    // Store metadata
    state
        .storage
        .store_api_key(&key_id, metadata.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "storage_error",
                    "error_description": format!("Failed to store API key: {}", e)
                })),
            )
        })?;

    // Generate the API key token
    let api_key_token = generate_api_key_token(
        &key_id,
        &request.scopes,
        expires_at,
        &tenant_id,
        api_key_config,
    )?;

    info!("API key created: {}", key_id);

    Ok(Json(CreateApiKeyResponse {
        id: key_id,
        name: request.name,
        api_key: api_key_token,
        scopes: request.scopes,
        created_at: now,
        expires_at,
    }))
}

/// List API keys for a tenant
/// GET /api/v1/tenant/{tenant_id}/api-keys/list
pub async fn list_api_keys(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<ApiKeyInfo>>, (StatusCode, Json<serde_json::Value>)> {
    debug!("Listing API keys for tenant '{}'", tenant_id);

    // Verify tenant exists
    state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    let keys = state.storage.list_api_keys(&tenant_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "storage_error",
                "error_description": format!("Failed to list API keys: {}", e)
            })),
        )
    })?;

    let tenant_keys: Vec<ApiKeyInfo> = keys
        .into_iter()
        .map(|k| ApiKeyInfo {
            id: k.id,
            name: k.name,
            scopes: k.scopes,
            created_at: k.created_at.timestamp(),
            expires_at: k.expires_at.map(|dt| dt.timestamp()),
            last_used: k.last_used.map(|dt| dt.timestamp()),
            revoked: k.revoked,
        })
        .collect();

    Ok(Json(tenant_keys))
}

/// Revoke an API key
/// POST /api/v1/tenant/{tenant_id}/api-keys/{key_id}/revoke
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Path((tenant_id, key_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    info!("Revoking API key '{}' for tenant '{}'", key_id, tenant_id);

    // Verify tenant exists
    state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get the key
    let mut key = state.storage.get_api_key(&key_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "storage_error",
                "error_description": format!("Failed to get API key: {}", e)
            })),
        )
    })?.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "api_key_not_found" })),
        )
    })?;

    // Verify key belongs to this tenant
    if key.tenant_id != tenant_id {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))));
    }

    key.revoked = true;

    state.storage.update_api_key(&key_id, key).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "storage_error",
                "error_description": format!("Failed to revoke API key: {}", e)
            })),
        )
    })?;

    info!("API key revoked: {}", key_id);

    Ok(Json(json!({
        "success": true,
        "message": "API key revoked successfully"
    })))
}

/// Generate an API key JWT token
fn generate_api_key_token(
    key_id: &str,
    scopes: &[String],
    expires_at: Option<i64>,
    tenant_id: &str,
    config: &ApiKeyConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp() as usize;

    let claims = ApiKeyClaims {
        sub: key_id.to_string(),
        iss: format!("pmp-auth-api/{}", tenant_id),
        aud: vec![tenant_id.to_string()],
        exp: expires_at.map(|t| t as usize),
        iat: now,
        scope: scopes.join(" "),
        api_key: true,
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
        warn!("Failed to load API key signing key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to load signing key" })),
        )
    })?;

    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse API key signing key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Invalid signing key format" })),
        )
    })?;

    let mut header = Header::new(algorithm);
    header.kid = Some(config.signing_key.kid.clone());

    encode(&header, &claims, &encoding_key).map_err(|e| {
        warn!("Failed to encode API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "server_error", "error_description": "Failed to generate API key" })),
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

/// Validate an API key (for middleware use)
pub async fn validate_api_key(
    token: &str,
    tenant_id: &str,
    config: &ApiKeyConfig,
    storage: &std::sync::Arc<dyn crate::storage::StorageBackend>,
) -> Result<ApiKeyData, (StatusCode, String)> {
    // Determine algorithm
    let algorithm = match config.signing_key.algorithm.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unsupported algorithm".to_string(),
            ))
        }
    };

    // Load public key for validation
    let public_key_pem = load_key_pem(&config.signing_key.public_key).map_err(|e| {
        warn!("Failed to load public key for API key validation: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load public key".to_string(),
        )
    })?;

    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
        warn!("Failed to parse public key for API key validation: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid public key format".to_string(),
        )
    })?;

    // Set up validation
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[tenant_id]);
    validation.set_required_spec_claims(&["sub", "iat", "aud"]);
    validation.validate_exp = true;

    // Decode and validate the JWT
    let token_data = decode::<ApiKeyClaims>(token, &decoding_key, &validation).map_err(|e| {
        warn!("API key validation failed: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid API key".to_string())
    })?;

    // Verify it's an API key token (not a regular access token)
    if !token_data.claims.api_key {
        warn!("Token is not an API key");
        return Err((
            StatusCode::UNAUTHORIZED,
            "Token is not an API key".to_string(),
        ));
    }

    // Extract key_id from sub claim
    let key_id = &token_data.claims.sub;

    // Fetch API key metadata from storage
    let api_key_data = storage
        .get_api_key(key_id)
        .await
        .map_err(|e| {
            warn!("Failed to fetch API key from storage: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch API key".to_string(),
            )
        })?
        .ok_or_else(|| {
            warn!("API key '{}' not found in storage", key_id);
            (StatusCode::UNAUTHORIZED, "API key not found".to_string())
        })?;

    // Check if key is revoked
    if api_key_data.revoked {
        warn!("API key '{}' has been revoked", key_id);
        return Err((StatusCode::UNAUTHORIZED, "API key has been revoked".to_string()));
    }

    // Check if key has expired
    if let Some(expires_at) = api_key_data.expires_at {
        if Utc::now() > expires_at {
            warn!("API key '{}' has expired", key_id);
            return Err((StatusCode::UNAUTHORIZED, "API key has expired".to_string()));
        }
    }

    // Verify tenant_id matches
    if api_key_data.tenant_id != tenant_id {
        warn!(
            "API key '{}' tenant mismatch: expected '{}', got '{}'",
            key_id, tenant_id, api_key_data.tenant_id
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "API key tenant mismatch".to_string(),
        ));
    }

    debug!("API key '{}' validated successfully", key_id);
    Ok(api_key_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_claims_serialization() {
        let claims = ApiKeyClaims {
            sub: "key-123".to_string(),
            iss: "pmp-auth-api/test-tenant".to_string(),
            aud: vec!["test-tenant".to_string()],
            exp: Some(1234567890),
            iat: 1234567800,
            scope: "api:read api:write".to_string(),
            api_key: true,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"api_key\":true"));
        assert!(json.contains("\"scope\":\"api:read api:write\""));
    }

    #[test]
    fn test_api_key_metadata() {
        let metadata = ApiKeyMetadata {
            id: "key-123".to_string(),
            tenant_id: "test-tenant".to_string(),
            name: "Test API Key".to_string(),
            scopes: vec!["api:read".to_string()],
            created_at: 1234567800,
            expires_at: None,
            last_used: None,
            revoked: false,
        };

        assert_eq!(metadata.id, "key-123");
        assert!(!metadata.revoked);
        assert!(metadata.expires_at.is_none());
    }
}
