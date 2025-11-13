mod auth;
mod config;
mod handlers;
mod middleware;
mod models;

use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pmp_auth_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Load tenant configuration
    let tenant_config = match config::load_config_with_fallback() {
        Ok(config) => {
            tracing::info!("✓ Multi-tenant configuration loaded successfully");
            Some(config)
        }
        Err(e) => {
            tracing::warn!(
                "⚠ Failed to load tenant configuration: {}. Running in legacy mode with old routes only.",
                e
            );
            None
        }
    };

    // Build our application with routes
    let mut app = Router::new()
        // Health check routes (always available)
        .route("/", get(handlers::health::health_check))
        .route("/health", get(handlers::health::health_check));

    // Add tenant-specific routes if configuration is available
    if let Some(config) = tenant_config.clone() {
        tracing::info!("Setting up multi-tenant routes");

        // Create tenant router with state
        let tenant_router = Router::new()
            // List available identity providers for a tenant
            .route(
                "/api/v1/tenant/:tenant_id/strategies",
                get(handlers::tenant_auth::list_strategies),
            )
            // OAuth2 Authorization Server endpoints
            .route(
                "/api/v1/tenant/:tenant_id/oauth/authorize",
                get(auth::oauth2_authorize),
            )
            .route(
                "/api/v1/tenant/:tenant_id/oauth/token",
                post(auth::oauth2_token),
            )
            // JWKS endpoint for public key distribution
            .route(
                "/api/v1/tenant/:tenant_id/.well-known/jwks.json",
                get(auth::jwks),
            )
            // Legacy endpoints (will return NOT_IMPLEMENTED)
            .route(
                "/api/v1/tenant/:tenant_id/auth/:strategy_name/register",
                post(handlers::tenant_auth::register),
            )
            .route(
                "/api/v1/tenant/:tenant_id/auth/:strategy_name/login",
                post(handlers::tenant_auth::login),
            )
            .route(
                "/api/v1/tenant/:tenant_id/auth/:strategy_name/oauth/login",
                get(handlers::tenant_auth::oauth2_login),
            )
            .route(
                "/api/v1/tenant/:tenant_id/auth/:strategy_name/oauth/callback",
                get(handlers::tenant_auth::oauth2_callback),
            )
            .with_state(config);

        app = app.merge(tenant_router);

        tracing::info!("✓ Multi-tenant routes configured");
    }

    // Legacy routes (for backward compatibility)
    app = app
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        // Protected routes (legacy)
        .route(
            "/api/v1/user/profile",
            get(handlers::user::get_profile)
                .layer(axum::middleware::from_fn(middleware::auth::auth_middleware)),
        )
        .route(
            "/api/v1/admin/users",
            get(handlers::admin::list_users)
                .layer(axum::middleware::from_fn(middleware::auth::auth_middleware))
                .layer(axum::middleware::from_fn(middleware::auth::require_admin)),
        );

    // Add global middleware
    app = app
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // Run the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("🚀 Starting PMP Auth API server on {}", addr);

    if tenant_config.is_some() {
        tracing::info!("📋 Mode: Multi-tenant (with legacy routes for backward compatibility)");
        tracing::info!("📖 Tenant routes: /api/v1/tenant/{{tenant-id}}/auth/{{strategy-name}}/*");
    } else {
        tracing::info!("📋 Mode: Legacy (single-tenant)");
    }

    tracing::info!("📖 Legacy routes: /api/v1/auth/*");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
