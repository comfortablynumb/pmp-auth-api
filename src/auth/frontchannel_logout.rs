// Front-Channel Logout Implementation (OpenID Connect Front-Channel Logout 1.0)
// This module implements browser-based logout notifications to clients via iframes

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, warn};

/// Front-channel logout query parameters
#[derive(Debug, Deserialize)]
pub struct FrontChannelLogoutParams {
    /// Issuer identifier
    pub iss: String,
    /// Session ID
    pub sid: Option<String>,
}

/// Generate front-channel logout iframe HTML
/// This creates an HTML page with invisible iframes that trigger logout at each RP
pub fn generate_logout_iframe_page(
    logout_uris: Vec<(String, String)>, // Vec of (client_id, logout_uri)
    issuer: &str,
    session_id: Option<&str>,
) -> String {
    let mut iframes = Vec::new();

    for (client_id, logout_uri) in logout_uris {
        // Construct logout URL with query parameters
        let mut url = format!("{}?iss={}", logout_uri, urlencoding::encode(issuer));

        if let Some(sid) = session_id {
            url.push_str(&format!("&sid={}", urlencoding::encode(sid)));
        }

        // Create invisible iframe
        let iframe = format!(
            r#"<iframe src="{}" width="0" height="0" style="display:none;"></iframe>"#,
            html_escape::encode_text(&url)
        );
        iframes.push(iframe);

        debug!(
            "Added front-channel logout iframe for client '{}': {}",
            client_id, logout_uri
        );
    }

    // Generate HTML page with iframes
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Logout</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>Signing out...</h1>
    <p>Please wait while we sign you out of all connected applications.</p>
    {}
    <script>
        // After a timeout, consider logout complete and redirect if needed
        setTimeout(function() {{
            // Could redirect to a post-logout page here
            console.log('Front-channel logout complete');
        }}, 3000);
    </script>
</body>
</html>"#,
        iframes.join("\n    ")
    )
}

/// Front-Channel Logout Endpoint (at the OP)
/// GET /api/v1/tenant/{tenant_id}/oauth/frontchannel_logout
///
/// This endpoint is called when a user initiates logout.
/// It returns an HTML page with iframes that trigger logout at all RPs.
pub async fn frontchannel_logout(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(params): Query<FrontChannelLogoutParams>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Front-channel logout request for tenant '{}', session: {:?}",
        tenant_id, params.sid
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if OIDC is enabled
    let (oidc_config, _oidc_storage_id) = tenant.get_oidc_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "oidc_not_enabled" })),
        )
    })?;

    // Verify issuer matches
    if params.iss != oidc_config.issuer {
        warn!(
            "Issuer mismatch in logout request: got '{}', expected '{}'",
            params.iss, oidc_config.issuer
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Issuer does not match"
            })),
        ));
    }

    // Get all registered clients with front-channel logout URIs
    let logout_uris = Vec::new();

    // In a real implementation, you would query the storage for all clients
    // that have front_channel_logout_uri registered and are part of this session
    // For now, we'll use a simplified approach

    // Example: Get clients from storage (this would need to be implemented)
    // let clients = state.storage.get_clients_with_frontchannel_logout(&tenant_id).await?;
    // for client in clients {
    //     if let Some(logout_uri) = client.frontchannel_logout_uri {
    //         logout_uris.push((client.client_id, logout_uri));
    //     }
    // }

    // For demonstration, we'll show how it would work
    info!(
        "Front-channel logout will notify {} RPs",
        logout_uris.len()
    );

    // Generate HTML page with logout iframes
    let html = generate_logout_iframe_page(
        logout_uris,
        &oidc_config.issuer,
        params.sid.as_deref(),
    );

    // Return HTML response
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )],
        html,
    )
        .into_response())
}

/// Front-Channel Logout Callback Endpoint (at the RP)
/// GET /oauth/frontchannel_logout_callback
///
/// This is an example of what an RP's front-channel logout endpoint might look like.
/// Each RP must implement this endpoint to handle logout notifications.
pub async fn frontchannel_logout_callback(
    Query(params): Query<FrontChannelLogoutParams>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Front-channel logout callback received from issuer '{}', session: {:?}",
        params.iss, params.sid
    );

    // Validate issuer
    // In a real implementation, verify that the issuer is trusted

    // Clear the session identified by sid (if provided)
    if let Some(ref sid) = params.sid {
        debug!("Clearing session: {}", sid);
        // Clear local session, cookies, etc.
        // This is application-specific logic
    } else {
        // If no sid provided, clear all sessions for this issuer
        debug!("Clearing all sessions for issuer: {}", params.iss);
    }

    // Return a minimal response (200 OK)
    // The response content doesn't matter as it's loaded in an invisible iframe
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        "OK",
    )
        .into_response())
}

/// Helper function to trigger front-channel logout for a session
/// This should be called when a user initiates logout
pub async fn trigger_frontchannel_logout(
    tenant_id: &str,
    session_id: &str,
    state: &AppState,
) -> Result<String, String> {
    info!(
        "Triggering front-channel logout for session '{}' in tenant '{}'",
        session_id, tenant_id
    );

    // Get tenant configuration
    let tenant = state
        .config
        .get_tenant(tenant_id)
        .ok_or_else(|| "Tenant not found".to_string())?;

    let (oidc_config, _oidc_storage_id) = tenant
        .get_oidc_provider()
        .ok_or_else(|| "OIDC not enabled".to_string())?;

    // Get all clients that need to be notified
    // This would query the storage for all clients in this session
    let logout_uris = Vec::new(); // Placeholder

    // Generate the logout HTML page
    let html = generate_logout_iframe_page(
        logout_uris,
        &oidc_config.issuer,
        Some(session_id),
    );

    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_logout_iframe_page_empty() {
        let html = generate_logout_iframe_page(Vec::new(), "https://example.com", None);
        assert!(html.contains("Signing out"));
        assert!(html.contains("<html>"));
    }

    #[test]
    fn test_generate_logout_iframe_page_with_clients() {
        let logout_uris = vec![
            (
                "client1".to_string(),
                "https://client1.example.com/logout".to_string(),
            ),
            (
                "client2".to_string(),
                "https://client2.example.com/logout".to_string(),
            ),
        ];

        let html = generate_logout_iframe_page(
            logout_uris,
            "https://op.example.com",
            Some("session123"),
        );

        assert!(html.contains("client1.example.com"));
        assert!(html.contains("client2.example.com"));
        assert!(html.contains("iss=https%3A%2F%2Fop.example.com"));
        assert!(html.contains("sid=session123"));
        assert!(html.contains("<iframe"));
    }

    #[test]
    fn test_generate_logout_iframe_page_without_sid() {
        let logout_uris = vec![(
            "client1".to_string(),
            "https://client1.example.com/logout".to_string(),
        )];

        let html =
            generate_logout_iframe_page(logout_uris, "https://op.example.com", None);

        assert!(html.contains("iss=https%3A%2F%2Fop.example.com"));
        assert!(!html.contains("sid="));
    }

    #[test]
    fn test_frontchannel_logout_params() {
        let params = FrontChannelLogoutParams {
            iss: "https://example.com".to_string(),
            sid: Some("session123".to_string()),
        };

        assert_eq!(params.iss, "https://example.com");
        assert_eq!(params.sid, Some("session123".to_string()));
    }
}
