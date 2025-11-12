use crate::auth::validate_strategy_token;
use crate::models::{AppConfig, Claims, UserRole};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// Context about the authenticated user and tenant
#[derive(Debug, Clone)]
pub struct TenantAuthUser {
    pub claims: Claims,
    pub tenant_id: String,
    pub strategy_name: String,
}

/// Middleware to authenticate requests for tenant-specific routes
pub async fn tenant_auth_middleware(
    State(config): State<Arc<AppConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Extract tenant_id and strategy_name from the path
    // The path should be like: /api/v1/tenant/{tenant_id}/auth/{strategy_name}/...
    let path = request.uri().path();
    let parts: Vec<&str> = path.split('/').collect();

    // Find tenant_id and strategy_name in the path
    let (tenant_id, strategy_name) = if let Some(tenant_pos) =
        parts.iter().position(|&p| p == "tenant")
    {
        if parts.len() > tenant_pos + 3 && parts[tenant_pos + 2] == "auth" {
            (
                parts[tenant_pos + 1].to_string(),
                parts[tenant_pos + 3].to_string(),
            )
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid path format. Expected /api/v1/tenant/{tenant_id}/auth/{strategy_name}/..."
                })),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Tenant ID not found in path"
            })),
        ));
    };

    debug!(
        "Authenticating request for tenant '{}' strategy '{}'",
        tenant_id, strategy_name
    );

    // Get the auth strategy
    let strategy = config
        .get_auth_strategy(&tenant_id, &strategy_name)
        .ok_or_else(|| {
            warn!(
                "Tenant or strategy not found: {}/{}",
                tenant_id, strategy_name
            );
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Tenant or auth strategy not found"
                })),
            )
        })?;

    // Extract token from Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Missing Authorization header"
                })),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid Authorization header format. Expected: Bearer <token>"
            })),
        )
    })?;

    // Validate token using the appropriate strategy
    let claims = validate_strategy_token(token, strategy)
        .await
        .map_err(|(status, error)| (status, Json(json!({ "error": error }))))?;

    // Store auth context in request extensions
    request.extensions_mut().insert(TenantAuthUser {
        claims,
        tenant_id,
        strategy_name,
    });

    Ok(next.run(request).await)
}

/// Middleware to require admin role for tenant-specific routes
pub async fn require_tenant_admin(
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Get the auth user from the request extensions
    let auth_user = request
        .extensions()
        .get::<TenantAuthUser>()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized"
                })),
            )
        })?;

    // Check if the user is an admin
    if auth_user.claims.role != UserRole::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Admin access required"
            })),
        ));
    }

    Ok(next.run(request).await)
}
