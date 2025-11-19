// Dynamic Client Registration (RFC 7591)
// This module implements the OAuth 2.0 Dynamic Client Registration Protocol

use crate::storage::{OAuth2ClientData, OAuth2ClientType};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

/// Client Registration Request (RFC 7591 Section 2)
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    /// Array of redirection URIs
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Client type: "confidential" or "public"
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Grant types the client will use
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Response types the client will use
    #[serde(default)]
    pub response_types: Vec<String>,
    /// Client name (human-readable)
    pub client_name: Option<String>,
    /// Client URI (homepage)
    pub client_uri: Option<String>,
    /// Logo URI
    pub logo_uri: Option<String>,
    /// Scope values that the client can use
    #[serde(default)]
    pub scope: Option<String>,
    /// Contacts (email addresses)
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Terms of Service URI
    pub tos_uri: Option<String>,
    /// Policy URI
    pub policy_uri: Option<String>,
    /// JWKS URI for client public keys
    pub jwks_uri: Option<String>,
    /// JWK Set (inline public keys)
    pub jwks: Option<serde_json::Value>,
    /// Software ID
    pub software_id: Option<String>,
    /// Software version
    pub software_version: Option<String>,
    /// Back-channel logout URI (RFC 8965)
    pub backchannel_logout_uri: Option<String>,
    /// Whether backchannel logout requires session_id
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// Front-channel logout URI (OIDC Front-Channel Logout)
    pub frontchannel_logout_uri: Option<String>,
    /// Whether front-channel logout requires session_id
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
}

/// Client Registration Response (RFC 7591 Section 3.2.1)
#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    /// Unique client identifier
    pub client_id: String,
    /// Client secret (only for confidential clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Time at which the client_secret will expire (0 = no expiration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,
    /// Array of redirection URIs
    pub redirect_uris: Vec<String>,
    /// Grant types
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub grant_types: Vec<String>,
    /// Response types
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub response_types: Vec<String>,
    /// Client name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Client URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    /// Token endpoint authentication method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// Scope values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// JWKS URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Back-channel logout URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    /// Whether backchannel logout requires session_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    /// Front-channel logout URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    /// Whether front-channel logout requires session_id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
}

/// Register a new OAuth2 client
/// POST /api/v1/tenant/{tenant_id}/oauth/register
pub async fn register_client(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<Json<ClientRegistrationResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Client registration request for tenant '{}'", tenant_id);

    // Verify tenant exists
    let _tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid_client_metadata", "error_description": "Tenant not found" })),
        )
    })?;

    // Validate request
    if request.redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_redirect_uri",
                "error_description": "At least one redirect_uri is required"
            })),
        ));
    }

    // Validate redirect URIs (must be HTTPS for production, except localhost)
    for uri in &request.redirect_uris {
        if !uri.starts_with("https://")
            && !uri.starts_with("http://localhost")
            && !uri.starts_with("http://127.0.0.1")
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_redirect_uri",
                    "error_description": format!("Redirect URI must use HTTPS: {}", uri)
                })),
            ));
        }
    }

    // Generate client credentials
    let client_id = format!("client_{}", Uuid::new_v4());
    let client_secret = Some(generate_client_secret());

    // Determine client type based on token_endpoint_auth_method
    let client_type = match request.token_endpoint_auth_method.as_deref() {
        Some("none") => OAuth2ClientType::Public,
        _ => OAuth2ClientType::Confidential,
    };

    // Default grant types if not specified
    let grant_types = if request.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        request.grant_types.clone()
    };

    // Default response types if not specified
    let response_types = if request.response_types.is_empty() {
        vec!["code".to_string()]
    } else {
        request.response_types.clone()
    };

    // Parse scope
    let allowed_scopes: Vec<String> = request
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_else(|| vec!["openid".to_string(), "profile".to_string(), "email".to_string()]);

    // Extract public key from JWKS if provided (backward compatibility - first key)
    let public_key_pem = if let Some(jwks) = &request.jwks {
        extract_public_key_from_jwks(jwks)?
    } else {
        None
    };

    // Store all JWKS keys if provided
    let jwks_keys = request.jwks.as_ref().and_then(|jwks| {
        jwks.get("keys")
            .and_then(|k| k.as_array())
            .map(|keys| keys.clone())
    });

    // Create client data
    let client_data = OAuth2ClientData {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
        tenant_id: tenant_id.clone(),
        name: request.client_name.clone().unwrap_or_else(|| client_id.clone()),
        description: None,
        redirect_uris: request.redirect_uris.clone(),
        allowed_scopes,
        grant_types: grant_types.clone(),
        response_types: response_types.clone(),
        client_type,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        active: true,
        public_key_pem,
        jwks_uri: request.jwks_uri.clone(),
        jwks_keys,
        token_endpoint_auth_method: request.token_endpoint_auth_method.clone(),
        backchannel_logout_uri: request.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: request.backchannel_logout_session_required,
        frontchannel_logout_uri: request.frontchannel_logout_uri.clone(),
        frontchannel_logout_session_required: request.frontchannel_logout_session_required,
    };

    // Store client in database
    state
        .storage
        .store_oauth2_client(&client_id, client_data)
        .await
        .map_err(|e| {
            warn!("Failed to create OAuth2 client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to register client"
                })),
            )
        })?;

    info!("Successfully registered client '{}'", client_id);

    // Return registration response
    Ok(Json(ClientRegistrationResponse {
        client_id,
        client_secret,
        client_secret_expires_at: Some(0), // No expiration
        redirect_uris: request.redirect_uris,
        grant_types,
        response_types,
        client_name: request.client_name,
        client_uri: request.client_uri,
        token_endpoint_auth_method: request.token_endpoint_auth_method,
        scope: request.scope,
        jwks_uri: request.jwks_uri,
        backchannel_logout_uri: request.backchannel_logout_uri,
        backchannel_logout_session_required: if request.backchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
        frontchannel_logout_uri: request.frontchannel_logout_uri,
        frontchannel_logout_session_required: if request.frontchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
    }))
}

/// Generate a secure client secret
fn generate_client_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Get client configuration (RFC 7592 Section 2)
/// GET /api/v1/tenant/{tenant_id}/oauth/register/{client_id}
pub async fn get_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientRegistrationResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Get client request for client '{}' in tenant '{}'", client_id, tenant_id);

    // Verify tenant exists
    let _tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid_client_metadata", "error_description": "Tenant not found" })),
        )
    })?;

    // Retrieve client from storage
    let client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "invalid_client_id", "error_description": "Client not found" })),
            )
        })?;

    // Verify client belongs to this tenant
    if client.tenant_id != tenant_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "invalid_client_id", "error_description": "Client does not belong to this tenant" })),
        ));
    }

    // Return client configuration (without secret)
    Ok(Json(ClientRegistrationResponse {
        client_id: client.client_id,
        client_secret: None, // Don't return secret on read
        client_secret_expires_at: Some(0),
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        client_name: Some(client.name),
        client_uri: None,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        scope: Some(client.allowed_scopes.join(" ")),
        jwks_uri: client.jwks_uri,
        backchannel_logout_uri: client.backchannel_logout_uri,
        backchannel_logout_session_required: if client.backchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
        frontchannel_logout_uri: client.frontchannel_logout_uri,
        frontchannel_logout_session_required: if client.frontchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
    }))
}

/// Update client configuration (RFC 7592 Section 2)
/// PUT /api/v1/tenant/{tenant_id}/oauth/register/{client_id}
pub async fn update_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<Json<ClientRegistrationResponse>, (StatusCode, Json<serde_json::Value>)> {
    info!("Update client request for client '{}' in tenant '{}'", client_id, tenant_id);

    // Verify tenant exists
    let _tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid_client_metadata", "error_description": "Tenant not found" })),
        )
    })?;

    // Retrieve existing client
    let mut client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "invalid_client_id", "error_description": "Client not found" })),
            )
        })?;

    // Verify client belongs to this tenant
    if client.tenant_id != tenant_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "invalid_client_id", "error_description": "Client does not belong to this tenant" })),
        ));
    }

    // Update fields
    if !request.redirect_uris.is_empty() {
        // Validate redirect URIs
        for uri in &request.redirect_uris {
            if !uri.starts_with("https://")
                && !uri.starts_with("http://localhost")
                && !uri.starts_with("http://127.0.0.1")
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_redirect_uri",
                        "error_description": format!("Redirect URI must use HTTPS: {}", uri)
                    })),
                ));
            }
        }
        client.redirect_uris = request.redirect_uris.clone();
    }

    if !request.grant_types.is_empty() {
        client.grant_types = request.grant_types.clone();
    }

    if !request.response_types.is_empty() {
        client.response_types = request.response_types.clone();
    }

    if let Some(name) = request.client_name {
        client.name = name;
    }

    if let Some(scope) = request.scope {
        client.allowed_scopes = scope.split_whitespace().map(String::from).collect();
    }

    client.jwks_uri = request.jwks_uri.clone();

    // Update JWKS keys if provided
    if let Some(ref jwks) = request.jwks {
        client.jwks_keys = jwks.get("keys")
            .and_then(|k| k.as_array())
            .map(|keys| keys.clone());

        // Also update public_key_pem for backward compatibility
        client.public_key_pem = extract_public_key_from_jwks(jwks)?;
    }

    client.token_endpoint_auth_method = request.token_endpoint_auth_method.clone();
    client.backchannel_logout_uri = request.backchannel_logout_uri.clone();
    client.backchannel_logout_session_required = request.backchannel_logout_session_required;
    client.frontchannel_logout_uri = request.frontchannel_logout_uri.clone();
    client.frontchannel_logout_session_required = request.frontchannel_logout_session_required;
    client.updated_at = Utc::now();

    // Update in storage
    state
        .storage
        .update_oauth2_client(&client_id, client.clone())
        .await
        .map_err(|e| {
            warn!("Failed to update client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?;

    info!("Successfully updated client '{}'", client_id);

    // Return updated configuration
    Ok(Json(ClientRegistrationResponse {
        client_id: client.client_id,
        client_secret: None, // Don't return secret
        client_secret_expires_at: Some(0),
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: client.response_types,
        client_name: Some(client.name),
        client_uri: None,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        scope: Some(client.allowed_scopes.join(" ")),
        jwks_uri: client.jwks_uri,
        backchannel_logout_uri: client.backchannel_logout_uri,
        backchannel_logout_session_required: if client.backchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
        frontchannel_logout_uri: client.frontchannel_logout_uri,
        frontchannel_logout_session_required: if client.frontchannel_logout_session_required {
            Some(true)
        } else {
            None
        },
    }))
}

/// Delete client (RFC 7592 Section 2)
/// DELETE /api/v1/tenant/{tenant_id}/oauth/register/{client_id}
pub async fn delete_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    info!("Delete client request for client '{}' in tenant '{}'", client_id, tenant_id);

    // Verify tenant exists
    let _tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "invalid_client_metadata", "error_description": "Tenant not found" })),
        )
    })?;

    // Retrieve client to verify ownership
    let client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            warn!("Failed to retrieve client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "invalid_client_id", "error_description": "Client not found" })),
            )
        })?;

    // Verify client belongs to this tenant
    if client.tenant_id != tenant_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "invalid_client_id", "error_description": "Client does not belong to this tenant" })),
        ));
    }

    // Delete from storage
    state
        .storage
        .delete_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            warn!("Failed to delete client '{}': {}", client_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
        })?;

    info!("Successfully deleted client '{}'", client_id);
    Ok(StatusCode::NO_CONTENT)
}

/// Extract RSA/EC public key from JWKS
fn extract_public_key_from_jwks(
    jwks: &serde_json::Value,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    // Parse JWKS structure
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client_metadata",
                    "error_description": "JWKS must have a 'keys' array"
                })),
            )
        })?;

    if keys.is_empty() {
        return Ok(None);
    }

    // Get the first key (TODO: support multiple keys and key selection)
    let key = &keys[0];

    // Check key type
    let kty = key
        .get("kty")
        .and_then(|k| k.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client_metadata",
                    "error_description": "JWK must have 'kty' field"
                })),
            )
        })?;

    match kty {
        "RSA" => {
            // Extract RSA public key components
            let n = key.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "RSA key must have 'n' (modulus)"
                    })),
                )
            })?;

            let e = key.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "RSA key must have 'e' (exponent)"
                    })),
                )
            })?;

            // Convert JWK to PEM format
            // This is a simplified version - in production you'd use a proper library
            // For now, store the JWK components as JSON for later conversion
            let pem_representation = json!({
                "kty": "RSA",
                "n": n,
                "e": e,
                "kid": key.get("kid"),
                "use": key.get("use"),
                "alg": key.get("alg")
            });

            Ok(Some(pem_representation.to_string()))
        }
        "EC" => {
            // Extract EC public key components
            let crv = key.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "EC key must have 'crv' (curve)"
                    })),
                )
            })?;

            let x = key.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "EC key must have 'x' coordinate"
                    })),
                )
            })?;

            let y = key.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_client_metadata",
                        "error_description": "EC key must have 'y' coordinate"
                    })),
                )
            })?;

            // Store EC key components as JSON
            let pem_representation = json!({
                "kty": "EC",
                "crv": crv,
                "x": x,
                "y": y,
                "kid": key.get("kid"),
                "use": key.get("use"),
                "alg": key.get("alg")
            });

            Ok(Some(pem_representation.to_string()))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_metadata",
                "error_description": format!("Unsupported key type: {}. Supported types: RSA, EC", kty)
            })),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_client_secret() {
        let secret1 = generate_client_secret();
        let secret2 = generate_client_secret();

        assert_eq!(secret1.len(), 64);
        assert_eq!(secret2.len(), 64);
        assert_ne!(secret1, secret2); // Should generate different secrets
        assert!(secret1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_client_registration_request_deserialization() {
        let json = r#"{
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "My Application",
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile email"
        }"#;

        let request: ClientRegistrationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.redirect_uris.len(), 1);
        assert_eq!(request.client_name, Some("My Application".to_string()));
        assert_eq!(request.grant_types.len(), 2);
        assert_eq!(request.scope, Some("openid profile email".to_string()));
    }
}
