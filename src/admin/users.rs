// User management admin API

use super::{error_response, not_found, validation_error, AdminError};
use crate::auth::password::{hash_password, verify_password};
use crate::models::{AppConfig, UserRole};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

// In-memory user storage (TODO: Move to storage backend)
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref USERS: Arc<Mutex<HashMap<String, User>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

/// User metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub password_hash: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub role: UserRole,
    pub active: bool,
    pub email_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub attributes: HashMap<String, String>,
}

/// List all users for a tenant
/// GET /api/v1/admin/tenants/{tenant_id}/users
pub async fn list_users(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<UserResponse>>, AdminError> {
    debug!("Admin API: List users for tenant '{}'", tenant_id);

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let users = USERS
        .lock()
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_error",
                &format!("Failed to lock users: {}", e),
            )
        })?;

    let tenant_users: Vec<UserResponse> = users
        .values()
        .filter(|u| u.tenant_id == tenant_id)
        .map(|u| UserResponse {
            id: u.id.clone(),
            tenant_id: u.tenant_id.clone(),
            email: u.email.clone(),
            name: u.name.clone(),
            picture: u.picture.clone(),
            role: u.role.clone(),
            active: u.active,
            email_verified: u.email_verified,
            created_at: u.created_at,
            updated_at: u.updated_at,
            attributes: u.attributes.clone(),
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
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserResponse>, AdminError> {
    debug!(
        "Admin API: Get user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let users = USERS
        .lock()
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_error",
                &format!("Failed to lock users: {}", e),
            )
        })?;

    let user = users
        .get(&user_id)
        .ok_or_else(|| not_found("User", &user_id))?;

    // Verify user belongs to tenant
    if user.tenant_id != tenant_id {
        return Err(not_found("User", &user_id));
    }

    info!(
        "Admin API: Retrieved user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    Ok(Json(UserResponse {
        id: user.id.clone(),
        tenant_id: user.tenant_id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        picture: user.picture.clone(),
        role: user.role.clone(),
        active: user.active,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        attributes: user.attributes.clone(),
    }))
}

/// Create a new user
/// POST /api/v1/admin/tenants/{tenant_id}/users
pub async fn create_user(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AdminError> {
    debug!("Admin API: Create user for tenant '{}'", tenant_id);

    // Verify tenant exists
    config
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
    {
        let users = USERS
            .lock()
            .map_err(|e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "lock_error",
                    &format!("Failed to lock users: {}", e),
                )
            })?;

        if users
            .values()
            .any(|u| u.tenant_id == tenant_id && u.email == request.email)
        {
            return Err(validation_error("User with this email already exists"));
        }
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

    let user = User {
        id: user_id.clone(),
        tenant_id: tenant_id.clone(),
        email: request.email.clone(),
        password_hash,
        name: request.name.clone(),
        picture: request.picture.clone(),
        role: request.role.unwrap_or(UserRole::User),
        active: true,
        email_verified: request.email_verified.unwrap_or(false),
        created_at: now,
        updated_at: now,
        attributes: request.attributes.unwrap_or_default(),
    };

    // Store user
    let mut users = USERS
        .lock()
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_error",
                &format!("Failed to lock users: {}", e),
            )
        })?;

    users.insert(user_id.clone(), user.clone());

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
        role: user.role,
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
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, user_id)): Path<(String, String)>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AdminError> {
    debug!(
        "Admin API: Update user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut users = USERS
        .lock()
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_error",
                &format!("Failed to lock users: {}", e),
            )
        })?;

    let user = users
        .get_mut(&user_id)
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
        user.role = role;
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

    info!(
        "Admin API: Updated user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    Ok(Json(UserResponse {
        id: user.id.clone(),
        tenant_id: user.tenant_id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        picture: user.picture.clone(),
        role: user.role.clone(),
        active: user.active,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
        attributes: user.attributes.clone(),
    }))
}

/// Delete a user
/// DELETE /api/v1/admin/tenants/{tenant_id}/users/{user_id}
pub async fn delete_user(
    State(config): State<Arc<AppConfig>>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, AdminError> {
    debug!(
        "Admin API: Delete user '{}' for tenant '{}'",
        user_id, tenant_id
    );

    // Verify tenant exists
    config
        .get_tenant(&tenant_id)
        .ok_or_else(|| not_found("Tenant", &tenant_id))?;

    let mut users = USERS
        .lock()
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "lock_error",
                &format!("Failed to lock users: {}", e),
            )
        })?;

    let user = users
        .get(&user_id)
        .ok_or_else(|| not_found("User", &user_id))?;

    // Verify user belongs to tenant
    if user.tenant_id != tenant_id {
        return Err(not_found("User", &user_id));
    }

    users.remove(&user_id);

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
    use crate::models::{IdentityBackend, IdentityProviderConfig, MockBackendConfig, OAuth2ServerConfig};

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
                identity_backend: IdentityBackend::Mock(MockBackendConfig {
                    users: vec![],
                }),
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
    async fn test_create_and_get_user() {
        let config = create_test_config();

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
            State(config.clone()),
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
        let get_result = get_user(
            State(config),
            Path(("test-tenant".to_string(), user_id)),
        )
        .await;

        assert!(get_result.is_ok());
        let user = get_result.unwrap().0;
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email() {
        let config = create_test_config();

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
            State(config.clone()),
            Path("test-tenant".to_string()),
            Json(create_request.clone()),
        )
        .await;

        assert!(result.is_ok());

        // Try to create duplicate
        let result = create_user(
            State(config),
            Path("test-tenant".to_string()),
            Json(create_request),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
