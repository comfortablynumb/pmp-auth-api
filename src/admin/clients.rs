// OAuth2 Client management admin API

use super::{AdminError, error_response, not_found, validation_error};
use crate::models::AppConfig;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

// In-memory client storage (TODO: Move to storage backend)
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref CLIENTS: Arc<Mutex<HashMap<String, Client>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

/// OAuth2 Client metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
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

/// List all clients for a tenant
/// GET /api/v1/admin/tenants/{tenant_id}/clients
pub async fn list_clients(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<ClientResponse>>, AdminError> {
    debug!("Admin API: List clients for tenant '{}'", tenant_id);

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let clients = CLIENTS.lock().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lock_error",
            &format!("Failed to lock clients: {}", e),
        )
    })?;

    let tenant_clients: Vec<ClientResponse> = clients
        .values()
        .filter(|c| c.tenant_id == tenant_id)
        .map(|c| ClientResponse {
            client_id: c.client_id.clone(),
            tenant_id: c.tenant_id.clone(),
            name: c.name.clone(),
            description: c.description.clone(),
            redirect_uris: c.redirect_uris.clone(),
            grant_types: c.grant_types.clone(),
            scopes: c.scopes.clone(),
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
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientResponse>, AdminError> {
    debug!(
        "Admin API: Get client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let clients = CLIENTS.lock().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lock_error",
            &format!("Failed to lock clients: {}", e),
        )
    })?;

    let client = clients
        .get(&client_id)
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
        client_id: client.client_id.clone(),
        tenant_id: client.tenant_id.clone(),
        name: client.name.clone(),
        description: client.description.clone(),
        redirect_uris: client.redirect_uris.clone(),
        grant_types: client.grant_types.clone(),
        scopes: client.scopes.clone(),
        active: client.active,
        created_at: client.created_at,
    }))
}

/// Create a new client
/// POST /api/v1/admin/tenants/{tenant_id}/clients
pub async fn create_client(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateClientRequest>,
) -> Result<(StatusCode, Json<ClientCreatedResponse>), AdminError> {
    debug!("Admin API: Create client for tenant '{}'", tenant_id);

    // Verify tenant exists
    config
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

    let client = Client {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
        tenant_id: tenant_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        redirect_uris: request.redirect_uris.clone(),
        grant_types: request.grant_types.clone(),
        scopes: request.scopes.clone(),
        active: true,
        created_at: chrono::Utc::now(),
    };

    // Store client
    let mut clients = CLIENTS.lock().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lock_error",
            &format!("Failed to lock clients: {}", e),
        )
    })?;

    clients.insert(client_id.clone(), client.clone());

    info!(
        "Admin API: Created client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    let response = ClientCreatedResponse {
        client_id: client.client_id,
        client_secret: client.client_secret,
        tenant_id: client.tenant_id,
        name: client.name,
        description: client.description,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.scopes,
        active: client.active,
        created_at: client.created_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Update an existing client
/// PUT /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
pub async fn update_client(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, client_id)): Path<(String, String)>,
    Json(request): Json<UpdateClientRequest>,
) -> Result<Json<ClientResponse>, AdminError> {
    debug!(
        "Admin API: Update client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut clients = CLIENTS.lock().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lock_error",
            &format!("Failed to lock clients: {}", e),
        )
    })?;

    let client = clients
        .get_mut(&client_id)
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
        client.scopes = scopes;
    }
    if let Some(active) = request.active {
        client.active = active;
    }

    info!(
        "Admin API: Updated client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    Ok(Json(ClientResponse {
        client_id: client.client_id.clone(),
        tenant_id: client.tenant_id.clone(),
        name: client.name.clone(),
        description: client.description.clone(),
        redirect_uris: client.redirect_uris.clone(),
        grant_types: client.grant_types.clone(),
        scopes: client.scopes.clone(),
        active: client.active,
        created_at: client.created_at,
    }))
}

/// Delete a client
/// DELETE /api/v1/admin/tenants/{tenant_id}/clients/{client_id}
pub async fn delete_client(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<StatusCode, AdminError> {
    debug!(
        "Admin API: Delete client '{}' for tenant '{}'",
        client_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut clients = CLIENTS.lock().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lock_error",
            &format!("Failed to lock clients: {}", e),
        )
    })?;

    let client = clients
        .get(&client_id)
        .ok_or_else(|| not_found("Client", &client_id))?;

    // Verify client belongs to tenant
    if client.tenant_id != tenant_id {
        return Err(not_found("Client", &client_id));
    }

    clients.remove(&client_id);

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
        IdentityBackend, IdentityProviderConfig, MockBackendConfig, OAuth2ServerConfig,
    };

    fn create_test_config() -> Arc<AppConfig> {
        let mut tenants = HashMap::new();
        tenants.insert(
            "test-tenant".to_string(),
            crate::models::Tenant {
                id: "test-tenant".to_string(),
                name: "Test Tenant".to_string(),
                description: Some("Test description".to_string()),
                identity_provider: IdentityProviderConfig {
                    oauth2: Some(OAuth2ServerConfig {
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
                    }),
                    oidc: None,
                    saml: None,
                },
                identity_backend: IdentityBackend::Mock(MockBackendConfig { users: vec![] }),
                api_keys: None,
                active: true,
            },
        );

        Arc::new(AppConfig {
            tenants,
            storage: crate::models::StorageConfig::Memory,
        })
    }

    #[tokio::test]
    async fn test_create_and_get_client() {
        let config = create_test_config();

        // Create client
        let create_request = CreateClientRequest {
            name: "Test Client".to_string(),
            description: Some("Test description".to_string()),
            redirect_uris: vec!["http://localhost:8080/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let result = create_client(
            State(config.clone()),
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
            get_client(State(config), Path(("test-tenant".to_string(), client_id))).await;

        assert!(get_result.is_ok());
        let client = get_result.unwrap().0;
        assert_eq!(client.name, "Test Client");
    }
}
