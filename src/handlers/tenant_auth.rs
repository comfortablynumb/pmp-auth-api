// Temporary stub file - old local auth handlers removed
// Will be replaced with OAuth2/OIDC/SAML provider endpoints

use crate::models::AppConfig;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

/// Stub: Register endpoint (will be removed - no local auth)
pub async fn register(
    _state: State<Arc<AppConfig>>,
    _path: Path<(String, String)>,
    _json: Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    warn!("Legacy register endpoint called - not implemented in OAuth2/OIDC/SAML architecture");
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(
            json!({ "error": "Local authentication removed. Use OAuth2/OIDC/SAML identity providers." }),
        ),
    ))
}

/// Stub: Login endpoint (will be removed - no local auth)
pub async fn login(
    _state: State<Arc<AppConfig>>,
    _path: Path<(String, String)>,
    _json: Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    warn!("Legacy login endpoint called - not implemented in OAuth2/OIDC/SAML architecture");
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(
            json!({ "error": "Local authentication removed. Use OAuth2/OIDC/SAML identity providers." }),
        ),
    ))
}

/// Stub: OAuth2 login (old client flow - will be replaced with server flow)
pub async fn oauth2_login(
    _state: State<Arc<AppConfig>>,
    _path: Path<(String, String)>,
) -> Result<Redirect, (StatusCode, Json<serde_json::Value>)> {
    warn!(
        "Legacy OAuth2 login endpoint called - will be replaced with OAuth2 authorization server"
    );
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(
            json!({ "error": "OAuth2 client flow removed. Use /oauth/authorize for OAuth2 authorization server." }),
        ),
    ))
}

#[derive(Debug, Deserialize)]
pub struct OAuth2CallbackQuery {
    #[allow(dead_code)]
    code: String,
    #[allow(dead_code)]
    state: String,
}

/// Stub: OAuth2 callback (old client flow - will be replaced)
pub async fn oauth2_callback(
    _state: State<Arc<AppConfig>>,
    _path: Path<(String, String)>,
    _query: Query<OAuth2CallbackQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    warn!(
        "Legacy OAuth2 callback endpoint called - will be replaced with identity backend integration"
    );
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(
            json!({ "error": "OAuth2 client callback removed. This service is now an OAuth2 authorization server." }),
        ),
    ))
}

/// List available identity providers for a tenant
pub async fn list_strategies(
    State(config): State<Arc<AppConfig>>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let tenant = config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Tenant not found" })),
        )
    })?;

    let mut providers = Vec::new();

    if tenant.identity_provider.oauth2.is_some() {
        providers.push(json!({
            "type": "oauth2",
            "authorize_endpoint": tenant.identity_provider.oauth2.as_ref().unwrap().authorize_endpoint,
            "token_endpoint": tenant.identity_provider.oauth2.as_ref().unwrap().token_endpoint,
        }));
    }

    if tenant.identity_provider.oidc.is_some() {
        providers.push(json!({
            "type": "oidc",
            "issuer": tenant.identity_provider.oidc.as_ref().unwrap().issuer,
            "userinfo_endpoint": tenant.identity_provider.oidc.as_ref().unwrap().userinfo_endpoint,
        }));
    }

    if tenant.identity_provider.saml.is_some() {
        providers.push(json!({
            "type": "saml",
            "entity_id": tenant.identity_provider.saml.as_ref().unwrap().entity_id,
            "sso_url": tenant.identity_provider.saml.as_ref().unwrap().sso_url,
        }));
    }

    let backend_type = match &tenant.identity_backend {
        crate::models::IdentityBackend::OAuth2(_) => "oauth2",
        crate::models::IdentityBackend::Ldap(_) => "ldap",
        crate::models::IdentityBackend::Database(_) => "database",
        crate::models::IdentityBackend::Federated(_) => "federated",
        crate::models::IdentityBackend::Mock(_) => "mock",
    };

    Ok(Json(json!({
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "identity_providers": providers,
        "identity_backend": backend_type,
    })))
}
