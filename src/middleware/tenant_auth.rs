// Temporary stub file - old tenant auth middleware removed
// Will be replaced with OAuth2/OIDC/SAML token validation

use crate::models::{AppConfig, Claims};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

/// Context about the authenticated user and tenant
#[derive(Debug, Clone)]
#[allow(dead_code)] // Exported for library use
pub struct TenantAuthUser {
    pub claims: Claims,
    pub tenant_id: String,
    pub strategy_name: String,
}

/// Stub: Tenant auth middleware (removed - will use OAuth2 token introspection)
#[allow(dead_code)] // Exported for library use
pub async fn tenant_auth_middleware(
    _state: State<Arc<AppConfig>>,
    _request: Request,
    _next: Next,
) -> Result<Response, impl IntoResponse> {
    warn!(
        "Legacy tenant auth middleware called - not implemented in OAuth2/OIDC/SAML architecture"
    );
    Err::<Response, _>((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "Legacy tenant auth middleware removed. Use OAuth2 token introspection."
        })),
    ))
}

/// Stub: Require tenant admin middleware (removed - will use OAuth2 scopes)
#[allow(dead_code)] // Exported for library use
pub async fn require_tenant_admin(
    _request: Request,
    _next: Next,
) -> Result<Response, impl IntoResponse> {
    warn!("Legacy require_tenant_admin middleware called - not implemented");
    Err::<Response, _>((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "Legacy admin middleware removed. Use OAuth2 scopes."
        })),
    ))
}
