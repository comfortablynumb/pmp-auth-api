// OAuth2 Client management admin API

use super::{error_response, not_found, validation_error, AdminError};
use crate::storage::{OAuth2ClientData, OAuth2ClientType};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

/// List all clients for a tenant
/// GET /api/v1/admin/tenants/{tenant_id}/clients
pub async fn list_clients(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<ClientResponse>>, AdminError> {
    debug!("Admin API: List clients for tenant '{}'", tenant_id);

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let clients = state
        .storage
        .list_oauth2_clients(&tenant_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to list clients: {}", e),
            )
        })?;

    let tenant_clients: Vec<ClientResponse> = clients
        .into_iter()
        .map(|c| ClientResponse {
            client_id: c.client_id,
            tenant_id: c.tenant_id,
            name: c.name,
            description: c.description,
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.allowed_scopes,
            active: c.active,
            created_at: c.created_at,
        })
        .collect();

    info!(
        "Admin API: Listed {} clients for tenant '{}'",
        tenant_clients.len(),
        tenant_id
    );
    Ok(Json(tenant_clients))
}

/// Get a specific client
/// GET /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
pub async fn get_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientResponse>, AdminError> {
    debug!(
        "Admin API: Get client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get client: {}", e),
            )
        })?
        .ok_or_else(|| not_found("Client", &client_id))?;

    // Verify client belongs to tenant
    if client.tenant_id != tenant_id {
        return Err(not_found("Client", &client_id));
    }

    info!(
        "Admin API: Retrieved client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    Ok(Json(ClientResponse {
        client_id: client.client_id,
        tenant_id: client.tenant_id,
        name: client.name,
        description: client.description,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.allowed_scopes,
        active: client.active,
        created_at: client.created_at,
    }))
}

/// Create a new client
/// POST /api/v1/admin/tenants/{tenant_id}/clients
pub async fn create_client(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<ClientCreatedResponse>), AdminError> {
    debug!("Admin API: Create client for tenant '{}'", tenant_id);

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    // Validate request
    if request.name.is_empty() {
        return Err(validation_error("Client name cannot be empty"));
    }
    if request.redirect_uris.is_empty() {
        return Err(validation_error("At least one redirect URI is required"));
    }
    if request.grant_types.is_empty() {
        return Err(validation_error("At least one grant type is required"));
    }

    // Generate client credentials
    let client_id = format!("client_{}", Uuid::new_v4());
    let client_secret = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let client = OAuth2ClientData {
        client_id: client_id.clone(),
        client_secret: Some(client_secret.clone()),
        tenant_id: tenant_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        redirect_uris: request.redirect_uris.clone(),
        allowed_scopes: request.scopes.clone(),
        grant_types: request.grant_types.clone(),
        response_types: vec!["code".to_string()],
        client_type: OAuth2ClientType::Confidential,
        created_at: now,
        updated_at: now,
        active: true,
        public_key_pem: None,
        jwks_uri: None,
        jwks_keys: None,
        token_endpoint_auth_method: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        request_uris: None,
        jwks: None,
    };

    // Store client
    state
        .storage
        .store_oauth2_client(&client_id, client.clone())
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to store client: {}", e),
            )
        })?;

    info!(
        "Admin API: Created client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    let response = ClientCreatedResponse {
        client_id: client.client_id,
        client_secret,
        tenant_id: client.tenant_id,
        name: client.name,
        description: client.description,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.allowed_scopes,
        active: client.active,
        created_at: client.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Update an existing client
/// PUT /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
pub async fn update_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
    Json(request): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, AdminError> {
    debug!(
        "Admin API: Update client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get client: {}", e),
            )
        })?
        .ok_or_else(|| not_found("Client", &client_id))?;

    // Verify client belongs to tenant
    if client.tenant_id != tenant_id {
        return Err(not_found("Client", &client_id));
    }

    // Update fields
    if let Some(name) = request.name {
        client.name = name;
    }
    if let Some(description) = request.description {
        client.description = Some(description);
    }
    if let Some(redirect_uris) = request.redirect_uris {
        if redirect_uris.is_empty() {
            return Err(validation_error("At least one redirect URI is required"));
        }
        client.redirect_uris = redirect_uris;
    }
    if let Some(grant_types) = request.grant_types {
        if grant_types.is_empty() {
            return Err(validation_error("At least one grant type is required"));
        }
        client.grant_types = grant_types;
    }
    if let Some(scopes) = request.scopes {
        client.allowed_scopes = scopes;
    }
    if let Some(active) = request.active {
        client.active = active;
    }

    client.updated_at = chrono::Utc::now();

    state
        .storage
        .update_oauth2_client(&client_id, client.clone())
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to update client: {}", e),
            )
        })?;

    info!(
        "Admin API: Updated client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    Ok(Json(ClientResponse {
        client_id: client.client_id,
        tenant_id: client.tenant_id,
        name: client.name,
        description: client.description,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.allowed_scopes,
        active: client.active,
        created_at: client.created_at,
    }))
}

/// Delete a client
/// DELETE /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
pub async fn delete_client(
    State(state): State<AppState>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<StatusCode, AdminError> {
    debug!(
        "Admin API: Delete client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let client = state
        .storage
        .get_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get client: {}", e),
            )
        })?
        .ok_or_else(|| not_found("Client", &client_id))?;

    // Verify client belongs to tenant
    if client.tenant_id != tenant_id {
        return Err(not_found("Client", &client_id));
    }

    state
        .storage
        .delete_oauth2_client(&client_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to delete client: {}", e),
            )
        })?;

    info!(
        "Admin API: Deleted client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    Ok(StatusCode::NO_CONTENT)
}

// Request/Response types

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ClientResponse {
    pub client_id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ClientCreatedResponse {
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AppConfig, DatabaseStorageConfig, IdentityStorage, OAuth2ServerConfig,
    };
    use crate::storage::memory::MemoryStorage;
    use crate::storage::StorageBackend;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_state() -> AppState {
        let mut tenants = HashMap::new();
        tenants.insert(
            "test-tenant".to_string(),
            crate::models::Tenant {
                id: "test-tenant".to_string(),
                name: "Test Tenant".to_string(),
                description: Some("Test description".to_string()),
                allowed_origins: vec![],
                identity_providers: {
                    let mut providers = HashMap::new();
                    providers.insert(
                        "default".to_string(),
                        crate::models::IdentityProvider::OAuth2 {
                            config: OAuth2ServerConfig {
                                issuer: "http://localhost:3000".to_string(),
                                grant_types: vec!["authorization_code".to_string()],
                                token_endpoint: "/oauth/token".to_string(),
                                authorize_endpoint: "/oauth/authorize".to_string(),
                                jwks_endpoint: "/.well-known/jwks.json".to_string(),
                                access_token_expiration_secs: 3600,
                                refresh_token_expiration_secs: 2592000,
                                signing_key: crate::models::JwkSigningConfig {
                                    algorithm: "RS256".to_string(),
                                    kid: "default-key".to_string(),
                                    public_key: "dummy-public-key".to_string(),
                                    private_key: "dummy-private-key".to_string(),
                                },
                                password_grant_enabled: false,
                                request_parameter_supported: false,
                                request_uri_parameter_supported: false,
                                require_request_uri_registration: false,
                                request_object_signing_alg_values_supported: vec![],
                            },
                            identity_storage_id: "default".to_string(),
                        },
                    );
                    providers
                },
                identity_storage: {
                    let mut storage_map = HashMap::new();
                    storage_map.insert(
                        "default".to_string(),
                        IdentityStorage::Database(DatabaseStorageConfig {
                            connection_url: "postgresql://localhost/test".to_string(),
                            db_type: "postgres".to_string(),
                            users_table: "users".to_string(),
                            id_column: "id".to_string(),
                            email_column: "email".to_string(),
                            attribute_mappings: HashMap::new(),
                        }),
                    );
                    storage_map
                },
                federation_providers: HashMap::new(),
                api_keys: None,
                active: true,
            },
        );

        let config = Arc::new(AppConfig {
            tenants,
            identity_storage: HashMap::new(),
            storage: crate::models::StorageConfig::Memory,
        });

        let storage: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new());

        AppState { config, storage }
    }

    #[tokio::test]
    async fn test_create_and_get_client() {
        let state = create_test_state();

        // Create client
        let create_request = CreateClientRequest {
            name: "Test Client".to_string(),
            description: Some("Test description".to_string()),
            redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let result = create_client(
            State(state.clone()),
            Path("test-tenant".to_string()),
            Json(create_request),
        )
        .await;

        assert!(result.is_ok());
        let (status, response) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert!(!response.client_secret.is_empty());

        // Get client
        let client_id = response.client_id.clone();
        let get_result =
            get_client(State(state), Path(("test-tenant".to_string(), client_id))).await;

        assert!(get_result.is_ok());
        let client = get_result.unwrap().0;
        assert_eq!(client.name, "Test Client");
    }
}
