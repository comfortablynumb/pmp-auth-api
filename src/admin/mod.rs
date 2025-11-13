// Admin API for tenant, client, and user management
// Provides CRUD operations for administrative tasks

pub mod clients;
pub mod tenants;
pub mod users;

pub use clients::{create_client, delete_client, get_client, list_clients, update_client};
pub use tenants::{create_tenant, delete_tenant, get_tenant, list_tenants, update_tenant};
pub use users::{create_user, delete_user, get_user, list_users, update_user};

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

/// Standard error response for admin API
pub type AdminError = (StatusCode, Json<Value>);

/// Create a standard error response
pub fn error_response(status: StatusCode, error: &str, description: &str) -> AdminError {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
}

/// Create a not found error response
pub fn not_found(resource: &str, id: &str) -> AdminError {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        &format!("{} '{}' not found", resource, id),
    )
}

/// Create a validation error response
pub fn validation_error(message: &str) -> AdminError {
    error_response(StatusCode::BAD_REQUEST, "validation_error", message)
}

/// Create a conflict error response
pub fn conflict_error(message: &str) -> AdminError {
    error_response(StatusCode::CONFLICT, "conflict", message)
}
