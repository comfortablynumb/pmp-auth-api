// Tenant authentication handlers

use crate::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

/// List available identity providers for a tenant
pub async fn list_strategies(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
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
