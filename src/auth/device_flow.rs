// Device Authorization Grant (RFC 8628)
// For devices with limited input capabilities (smart TVs, IoT devices, etc.)

use crate::models::AppConfig;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};
use uuid::Uuid;

// In-memory storage for device codes (TODO: Move to storage backend)
use lazy_static::lazy_static;

lazy_static! {
    static ref DEVICE_CODES: Arc<Mutex<HashMap<String, DeviceCodeData>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref USER_CODE_TO_DEVICE_CODE: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

/// Device code data
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DeviceCodeData {
    device_code: String,
    user_code: String,
    tenant_id: String,
    client_id: String,
    scope: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    status: DeviceCodeStatus,
    user_id: Option<String>,
}

/// Device code status
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum DeviceCodeStatus {
    Pending,
    Authorized,
    Denied,
    Expired,
}

/// Device Authorization Request (RFC 8628)
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
}

/// Device Authorization Response (RFC 8628)
#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

/// Device Token Request (RFC 8628)
#[derive(Debug, Deserialize)]
pub struct DeviceTokenRequest {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

/// Device verification request (from user on verification page)
#[derive(Debug, Deserialize)]
pub struct DeviceVerificationRequest {
    pub user_code: String,
}

/// Device confirmation request (user authorizes the device)
#[derive(Debug, Deserialize)]
pub struct DeviceConfirmationRequest {
    pub user_code: String,
    pub user_id: String,
    pub authorized: bool,
}

/// Device Authorization Endpoint (RFC 8628 Section 3.1)
/// POST /api/v1/tenant/{tenant_id}/oauth/device/authorize
pub async fn device_authorize(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<DeviceAuthorizationRequest>,
) -> Result<Json<DeviceAuthorizationResponse>, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Device authorization request for tenant '{}', client '{}'",
        tenant_id, request.client_id
    );

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Verify OAuth2 is configured
    let _oauth2_config = tenant.identity_provider.oauth2.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": "OAuth2 not configured for this tenant"
            })),
        )
    })?;

    // Generate device code and user code
    let device_code = Uuid::new_v4().to_string();
    let user_code = generate_user_code();

    // Calculate expiration (default: 15 minutes)
    let created_at = chrono::Utc::now();
    let expires_in = 900; // 15 minutes in seconds
    let expires_at = created_at + chrono::Duration::seconds(expires_in as i64);

    // Store device code
    let device_data = DeviceCodeData {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        tenant_id: tenant_id.clone(),
        client_id: request.client_id.clone(),
        scope: request.scope.clone(),
        created_at,
        expires_at,
        status: DeviceCodeStatus::Pending,
        user_id: None,
    };

    {
        let mut codes = DEVICE_CODES.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock device codes: {}", e)
                })),
            )
        })?;

        let mut mapping = USER_CODE_TO_DEVICE_CODE.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock user code mapping: {}", e)
                })),
            )
        })?;

        codes.insert(device_code.clone(), device_data);
        mapping.insert(user_code.clone(), device_code.clone());
    }

    // Build verification URI
    let base_url = tenant
        .identity_provider
        .oauth2
        .as_ref()
        .map(|o| extract_base_url(&o.issuer))
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let verification_uri = format!("{}/device", base_url);
    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));

    info!(
        "Device authorization created for tenant '{}': user_code={}",
        tenant_id, user_code
    );

    Ok(Json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: expires_in as u64,
        interval: 5, // Poll every 5 seconds
    }))
}

/// Device Token Endpoint (RFC 8628 Section 3.4)
/// POST /api/v1/tenant/{tenant_id}/oauth/device/token
pub async fn device_token(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<DeviceTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Device token request for tenant '{}', device_code '{}'",
        tenant_id, request.device_code
    );

    // Validate grant type
    if request.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unsupported_grant_type",
                "error_description": "Grant type must be urn:ietf:params:oauth:grant-type:device_code"
            })),
        ));
    }

    // Get tenant configuration
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get device code data
    let device_data = {
        let codes = DEVICE_CODES.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock device codes: {}", e)
                })),
            )
        })?;

        codes.get(&request.device_code).cloned()
    };

    let device_data = device_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Invalid device code"
            })),
        )
    })?;

    // Verify client_id matches
    if device_data.client_id != request.client_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Client ID mismatch"
            })),
        ));
    }

    // Check expiration
    if chrono::Utc::now() > device_data.expires_at {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "expired_token",
                "error_description": "Device code has expired"
            })),
        ));
    }

    // Check status
    match device_data.status {
        DeviceCodeStatus::Pending => {
            // Still waiting for user authorization
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "authorization_pending",
                    "error_description": "User has not yet authorized the device"
                })),
            ));
        }
        DeviceCodeStatus::Denied => {
            // User denied authorization
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "access_denied",
                    "error_description": "User denied authorization"
                })),
            ));
        }
        DeviceCodeStatus::Expired => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "expired_token",
                    "error_description": "Device code has expired"
                })),
            ));
        }
        DeviceCodeStatus::Authorized => {
            // User authorized, proceed with token generation
        }
    }

    let user_id = device_data.user_id.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "server_error",
                "error_description": "User ID not set despite authorization"
            })),
        )
    })?;

    // Generate tokens
    let oauth2_config = tenant.identity_provider.oauth2.as_ref().unwrap();

    // TODO: Fetch actual user from identity backend
    let user_email = format!("{}@device-flow", user_id);
    let user_role = crate::models::UserRole::User;

    let scope_vec: Vec<String> = device_data
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let access_token = crate::auth::oauth2_server::generate_access_token(
        &user_id,
        &user_email,
        user_role,
        &scope_vec,
        &tenant_id,
        oauth2_config,
    )?;

    let refresh_token = Uuid::new_v4().to_string();

    // Clean up device code (one-time use)
    {
        let mut codes = DEVICE_CODES.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock device codes: {}", e)
                })),
            )
        })?;

        let mut mapping = USER_CODE_TO_DEVICE_CODE.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock user code mapping: {}", e)
                })),
            )
        })?;

        codes.remove(&request.device_code);
        mapping.remove(&device_data.user_code);
    }

    info!(
        "Device token issued for tenant '{}', user '{}'",
        tenant_id, user_id
    );

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": oauth2_config.access_token_expiration_secs,
        "refresh_token": refresh_token,
        "scope": device_data.scope
    })))
}

/// Device Verification Endpoint (checks if user code is valid)
/// POST /api/v1/tenant/{tenant_id}/oauth/device/verify
pub async fn device_verify(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<DeviceVerificationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Device verification request for tenant '{}', user_code '{}'",
        tenant_id, request.user_code
    );

    // Normalize user code (remove spaces, uppercase)
    let user_code = request.user_code.replace(' ', "").to_uppercase();

    // Get tenant configuration
    let _tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get device code from user code
    let device_code = {
        let mapping = USER_CODE_TO_DEVICE_CODE.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock user code mapping: {}", e)
                })),
            )
        })?;

        mapping.get(&user_code).cloned()
    };

    let device_code = device_code.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "invalid_user_code",
                "error_description": "Invalid or expired user code"
            })),
        )
    })?;

    // Get device data
    let device_data = {
        let codes = DEVICE_CODES.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock device codes: {}", e)
                })),
            )
        })?;

        codes.get(&device_code).cloned()
    };

    let device_data = device_data.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "invalid_user_code",
                "error_description": "Device code not found"
            })),
        )
    })?;

    // Check expiration
    if chrono::Utc::now() > device_data.expires_at {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "expired_token",
                "error_description": "User code has expired"
            })),
        ));
    }

    info!(
        "Device verification successful for tenant '{}', user_code '{}'",
        tenant_id, user_code
    );

    Ok(Json(json!({
        "valid": true,
        "client_id": device_data.client_id,
        "scope": device_data.scope
    })))
}

/// Device Confirmation Endpoint (user authorizes the device)
/// POST /api/v1/tenant/{tenant_id}/oauth/device/confirm
pub async fn device_confirm(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<DeviceConfirmationRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    debug!(
        "Device confirmation request for tenant '{}', user_code '{}', authorized={}",
        tenant_id, request.user_code, request.authorized
    );

    // Normalize user code
    let user_code = request.user_code.replace(' ', "").to_uppercase();

    // Get tenant configuration
    let _tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Get device code from user code
    let device_code = {
        let mapping = USER_CODE_TO_DEVICE_CODE.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock user code mapping: {}", e)
                })),
            )
        })?;

        mapping.get(&user_code).cloned()
    };

    let device_code = device_code.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "invalid_user_code",
                "error_description": "Invalid or expired user code"
            })),
        )
    })?;

    // Update device code status
    {
        let mut codes = DEVICE_CODES.lock().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": format!("Failed to lock device codes: {}", e)
                })),
            )
        })?;

        let device_data = codes.get_mut(&device_code).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "invalid_user_code",
                    "error_description": "Device code not found"
                })),
            )
        })?;

        // Update status and user_id
        device_data.status = if request.authorized {
            DeviceCodeStatus::Authorized
        } else {
            DeviceCodeStatus::Denied
        };

        if request.authorized {
            device_data.user_id = Some(request.user_id.clone());
        }
    }

    let status_text = if request.authorized {
        "authorized"
    } else {
        "denied"
    };

    info!(
        "Device {} for tenant '{}', user_code '{}'",
        status_text, tenant_id, user_code
    );

    Ok(StatusCode::OK)
}

/// Generate a user-friendly user code
/// Format: XXXX-XXXX (8 characters, uppercase letters and numbers, no ambiguous characters)
fn generate_user_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No I, O, 0, 1 to avoid confusion
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let code: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect();

    format!("{}-{}", &code[0..4], &code[4..8])
}

/// Extract base URL from issuer
fn extract_base_url(issuer: &str) -> String {
    issuer
        .trim_end_matches('/')
        .split('/')
        .take(3)
        .collect::<Vec<&str>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_user_code() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9); // XXXX-XXXX
        assert_eq!(code.chars().nth(4), Some('-'));
        assert!(code.chars().all(|c| c.is_alphanumeric() || c == '-'));
    }

    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("https://auth.example.com/tenant/test"),
            "https://auth.example.com"
        );
        assert_eq!(
            extract_base_url("http://localhost:3000"),
            "http://localhost:3000"
        );
    }
}
