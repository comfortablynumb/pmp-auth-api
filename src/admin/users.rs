// User management admin API

use super::{error_response, not_found, validation_error, AdminError};
use crate::auth::password::hash_password;
use crate::models::UserRole;
use crate::storage::UserData;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// List all users for a tenant
/// GET /api/v1/admin/tenants/{tenant_id}/users
pub async fn list_users(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<UserResponse>>, AdminError> {
    debug!("Admin API: List users for tenant '{}'", tenant_id);

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let users = state.storage.list_users(&tenant_id).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Failed to list users: {}", e),
        )
    })?;

    let tenant_users: Vec<UserResponse> = users
        .into_iter()
        .map(|u| {
            let role = UserRole::from_str(&u.role).unwrap_or(UserRole::User);

            UserResponse {
                id: u.id,
                tenant_id: u.tenant_id,
                email: u.email,
                name: u.name,
                picture: u.picture,
                role,
                active: u.active,
                email_verified: u.email_verified,
                created_at: u.created_at,
                updated_at: u.updated_at,
                attributes: u.attributes,
            }
        })
        .collect();

    info!(
        "Admin API: Listed {} users for tenant '{}'",
        tenant_users.len(),
        tenant_id
    );
    Ok(Json(tenant_users))
}

/// Get a specific user
/// GET /api/v1/admin/tenants/{tenant_id}/users/{user_id}
pub async fn get_user(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserResponse>, AdminError> {
    debug!(
        "Admin API: Get user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let user = state
        .storage
        .get_user(&user_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get user: {}", e),
            )
        })?
        .ok_or_else(|| not_found("User", &user_id))?;

    // Verify user belongs to tenant
    if user.tenant_id != tenant_id {
        return Err(not_found("User", &user_id));
    }

    info!(
        "Admin API: Retrieved user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    let role = UserRole::from_str(&user.role).unwrap_or(UserRole::User);

    Ok(Json(UserResponse {
        id: user.id,
        tenant_id: user.tenant_id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        role,
        active: user.active,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        attributes: user.attributes,
    }))
}

/// Create a new user
/// POST /api/v1/admin/tenants/{tenant_id}/users
pub async fn create_user(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AdminError> {
    debug!("Admin API: Create user for tenant '{}'", tenant_id);

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    // Validate request
    if request.email.is_empty() {
        return Err(validation_error("Email cannot be empty"));
    }
    if request.password.len() < 8 {
        return Err(validation_error(
            "Password must be at least 8 characters long",
        ));
    }

    // Check if user with email already exists
    if let Some(_existing) = state
        .storage
        .get_user_by_email(&tenant_id, &request.email)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to check existing user: {}", e),
            )
        })?
    {
        return Err(validation_error("User with this email already exists"));
    }

    // Hash password
    let password_hash = hash_password(&request.password).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hash_error",
            &format!("Failed to hash password: {}", e),
        )
    })?;

    let user_id = format!("user_{}", Uuid::new_v4());
    let now = chrono::Utc::now();
    let role = request.role.unwrap_or(UserRole::User);

    let user = UserData {
        id: user_id.clone(),
        tenant_id: tenant_id.clone(),
        email: request.email.clone(),
        password_hash,
        name: request.name.clone(),
        picture: request.picture.clone(),
        role: role.to_string(),
        active: true,
        email_verified: request.email_verified.unwrap_or(false),
        created_at: now,
        updated_at: now,
        attributes: request.attributes.unwrap_or_default(),
    };

    // Store user
    state
        .storage
        .store_user(&user_id, user.clone())
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to store user: {}", e),
            )
        })?;

    info!(
        "Admin API: Created user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    let response = UserResponse {
        id: user.id,
        tenant_id: user.tenant_id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        role,
        active: user.active,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        attributes: user.attributes,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Update an existing user
/// PUT /api/v1/admin/tenants/{tenant_id}/users/{user_id}
pub async fn update_user(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(String, String)>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AdminError> {
    debug!(
        "Admin API: Update user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut user = state
        .storage
        .get_user(&user_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get user: {}", e),
            )
        })?
        .ok_or_else(|| not_found("User", &user_id))?;

    // Verify user belongs to tenant
    if user.tenant_id != tenant_id {
        return Err(not_found("User", &user_id));
    }

    // Update fields
    if let Some(email) = request.email {
        user.email = email;
    }
    if let Some(password) = request.password {
        if password.len() < 8 {
            return Err(validation_error(
                "Password must be at least 8 characters long",
            ));
        }
        user.password_hash = hash_password(&password).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "hash_error",
                &format!("Failed to hash password: {}", e),
            )
        })?;
    }
    if let Some(name) = request.name {
        user.name = Some(name);
    }
    if let Some(picture) = request.picture {
        user.picture = Some(picture);
    }
    if let Some(role) = request.role {
        user.role = role.to_string();
    }
    if let Some(active) = request.active {
        user.active = active;
    }
    if let Some(email_verified) = request.email_verified {
        user.email_verified = email_verified;
    }
    if let Some(attributes) = request.attributes {
        user.attributes = attributes;
    }

    user.updated_at = chrono::Utc::now();

    state
        .storage
        .update_user(&user_id, user.clone())
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to update user: {}", e),
            )
        })?;

    info!(
        "Admin API: Updated user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    let role = UserRole::from_str(&user.role).unwrap_or(UserRole::User);

    Ok(Json(UserResponse {
        id: user.id,
        tenant_id: user.tenant_id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        role,
        active: user.active,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        attributes: user.attributes,
    }))
}

/// Delete a user
/// DELETE /api/v1/admin/tenants/{tenant_id}/users/{user_id}
pub async fn delete_user(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, AdminError> {
    debug!(
        "Admin API: Delete user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    state
        .config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let user = state
        .storage
        .get_user(&user_id)
        .await
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Failed to get user: {}", e),
            )
        })?
        .ok_or_else(|| not_found("User", &user_id))?;

    // Verify user belongs to tenant
    if user.tenant_id != tenant_id {
        return Err(not_found("User", &user_id));
    }

    state.storage.delete_user(&user_id).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Failed to delete user: {}", e),
        )
    })?;

    info!(
        "Admin API: Deleted user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    Ok(StatusCode::NO_CONTENT)
}

// Request/Response types

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: Option<UserRole>,
    pub email_verified: Option<bool>,
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: Option<UserRole>,
    pub active: Option<bool>,
    pub email_verified: Option<bool>,
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: UserRole,
    pub active: bool,
    pub email_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub attributes: HashMap<String, String>,
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
    async fn test_create_and_get_user() {
        let state = create_test_state();

        // Create user
        let create_request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: Some("Test User".to_string()),
            picture: None,
            role: Some(UserRole::User),
            email_verified: Some(true),
            attributes: Some(HashMap::new()),
        };

        let result = create_user(
            State(state.clone()),
            Path("test-tenant".to_string()),
            Json(create_request),
        )
        .await;

        assert!(result.is_ok());
        let (status, response) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.email, "test@example.com");

        // Get user
        let user_id = response.id.clone();
        let get_result = get_user(State(state), Path(("test-tenant".to_string(), user_id))).await;

        assert!(get_result.is_ok());
        let user = get_result.unwrap().0;
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email() {
        let state = create_test_state();

        // Create first user
        let create_request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: Some("Test User".to_string()),
            picture: None,
            role: Some(UserRole::User),
            email_verified: Some(true),
            attributes: Some(HashMap::new()),
        };

        let result = create_user(
            State(state.clone()),
            Path("test-tenant".to_string()),
            Json(create_request.clone()),
        )
        .await;

        assert!(result.is_ok());

        // Try to create duplicate
        let result = create_user(
            State(state),
            Path("test-tenant".to_string()),
            Json(create_request),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
