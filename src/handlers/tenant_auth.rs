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

    // Build providers map from the new structure
    let mut providers = serde_json::Map::new();

    for (provider_id, provider) in &tenant.identity_providers {
        use crate::models::IdentityProvider;

        let provider_info = match provider {
            IdentityProvider::OAuth2 {
                config,
                identity_storage_id,
            } => json!({
                "type": "oauth2",
                "authorize_endpoint": config.authorize_endpoint,
                "token_endpoint": config.token_endpoint,
                "identity_storage_id": identity_storage_id,
            }),
            IdentityProvider::Oidc {
                config,
                identity_storage_id,
            } => json!({
                "type": "oidc",
                "issuer": config.issuer,
                "userinfo_endpoint": config.userinfo_endpoint,
                "identity_storage_id": identity_storage_id,
            }),
            IdentityProvider::Saml {
                config,
                identity_storage_id,
            } => json!({
                "type": "saml",
                "entity_id": config.entity_id,
                "sso_url": config.sso_url,
                "identity_storage_id": identity_storage_id,
            }),
        };

        providers.insert(provider_id.clone(), provider_info);
    }

    // Build storage map
    let mut storages = serde_json::Map::new();
    for (storage_id, storage) in &tenant.identity_storage {
        let storage_type = match storage {
            crate::models::IdentityStorage::Ldap(_) => "ldap",
            crate::models::IdentityStorage::Database(_) => "database",
        };
        storages.insert(storage_id.clone(), json!({ "type": storage_type }));
    }

    // Also include global storages
    for (storage_id, storage) in &state.config.identity_storage {
        if !storages.contains_key(storage_id) {
            let storage_type = match storage {
                crate::models::IdentityStorage::Ldap(_) => "ldap",
                crate::models::IdentityStorage::Database(_) => "database",
            };
            storages.insert(storage_id.clone(), json!({ "type": storage_type, "global": true }));
        }
    }

    Ok(Json(json!({
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "identity_providers": providers,
        "identity_storage": storages,
    })))
}
