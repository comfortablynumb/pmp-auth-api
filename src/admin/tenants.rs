// Tenant management admin API

use super::{AdminError, error_response, not_found, validation_error};
use crate::models::AppConfig;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::sync::Arc;
use tracing::{debug, info};

/// List all tenants
/// GET /api/v1/admin/tenants
pub async fn list_tenants(
    State(config): State<Arc<AppConfig>>,
) -> Result<Json<Vec<TenantResponse>>, AdminError> {
    debug!("Admin API: List all tenants");

    let tenants: Vec<TenantResponse> = config
        .tenants
        .iter()
        .map(|(id, tenant)| TenantResponse {
            id: id.clone(),
            name: tenant.name.clone(),
            description: tenant.description.clone(),
            active: tenant.active,
        })
        .collect();

    info!("Admin API: Listed {} tenants", tenants.len());
    Ok(Json(tenants))
}

/// Get a specific tenant
/// GET /api/v1/admin/tenants/{tenant_id}
pub async fn get_tenant(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantDetailResponse>, AdminError> {
    debug!("Admin API: Get tenant '{}'", tenant_id);

    let tenant = config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let response = TenantDetailResponse {
        id: tenant_id.clone(),
        name: tenant.name.clone(),
        description: tenant.description.clone(),
        active: tenant.active,
        identity_provider: serde_json::to_value(&tenant.identity_provider).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                &e.to_string(),
            )
        })?,
        identity_backend: format!("{:?}", tenant.identity_backend),
        has_api_keys: tenant.api_keys.is_some(),
    };

    info!("Admin API: Retrieved tenant '{}'", tenant_id);
    Ok(Json(response))
}

/// Create a new tenant
/// POST /api/v1/admin/tenants
pub async fn create_tenant(
    State(_config): State<Arc<AppConfig>>,
    Json(request): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), AdminError> {
    debug!("Admin API: Create tenant '{}'", request.id);

    // Validate request
    if request.id.is_empty() {
        return Err(validation_error("Tenant ID cannot be empty"));
    }
    if request.name.is_empty() {
        return Err(validation_error("Tenant name cannot be empty"));
    }

    // TODO: Check if tenant already exists
    // TODO: Persist tenant to storage

    info!("Admin API: Created tenant '{}'", request.id);

    let response = TenantResponse {
        id: request.id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        active: true,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Update an existing tenant
/// PUT /api/v1/admin/tenants/{tenant_id}
pub async fn update_tenant(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, AdminError> {
    debug!("Admin API: Update tenant '{}'", tenant_id);

    // Verify tenant exists
    let tenant = config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    // TODO: Update tenant in storage

    info!("Admin API: Updated tenant '{}'", tenant_id);

    let response = TenantResponse {
        id: tenant_id.clone(),
        name: request.name.unwrap_or_else(|| tenant.name.clone()),
        description: request.description.or_else(|| tenant.description.clone()),
        active: request.active.unwrap_or(tenant.active),
    };

    Ok(Json(response))
}

/// Delete a tenant
/// DELETE /api/v1/admin/tenants/{tenant_id}
pub async fn delete_tenant(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<StatusCode, AdminError> {
    debug!("Admin API: Delete tenant '{}'", tenant_id);

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    // TODO: Delete tenant from storage
    // TODO: Delete all associated data (clients, users, sessions, etc.)

    info!("Admin API: Deleted tenant '{}'", tenant_id);
    Ok(StatusCode::NO_CONTENT)
}

// Request/Response types

#[derive(Debug, serde::Deserialize)]
pub struct CreateTenantRequest {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[allow(dead_code)]
    pub identity_provider: serde_json::Value,
    #[allow(dead_code)]
    pub identity_backend: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub active: Option<bool>,
}

#[derive(Debug, serde::Serialize)]
pub struct TenantResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct TenantDetailResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
    pub identity_provider: serde_json::Value,
    pub identity_backend: String,
    pub has_api_keys: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        IdentityBackend, IdentityProviderConfig, MockBackendConfig, OAuth2ServerConfig, Tenant,
    };
    use std::collections::HashMap;

    fn create_test_config() -> Arc<AppConfig> {
        let mut tenants = HashMap::new();
        tenants.insert(
            "test-tenant".to_string(),
            Tenant {
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
    async fn test_list_tenants() {
        let config = create_test_config();
        let result = list_tenants(State(config)).await;
        assert!(result.is_ok());

        let tenants = result.unwrap().0;
        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].id, "test-tenant");
    }

    #[tokio::test]
    async fn test_get_tenant() {
        let config = create_test_config();
        let result = get_tenant(State(config), Path("test-tenant".to_string())).await;
        assert!(result.is_ok());

        let tenant = result.unwrap().0;
        assert_eq!(tenant.id, "test-tenant");
        assert_eq!(tenant.name, "Test Tenant");
    }

    #[tokio::test]
    async fn test_get_tenant_not_found() {
        let config = create_test_config();
        let result = get_tenant(State(config), Path("nonexistent".to_string())).await;
        assert!(result.is_err());

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
