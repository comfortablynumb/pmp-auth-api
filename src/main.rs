mod auth;
mod handlers;
mod middleware;
mod models;

use axum::{
    routing::{get, post},
    Router,
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

    // Build our application with routes
    let app = Router::new()
        // Public routes
        .route("/", get(handlers::health::health_check))
        .route("/health", get(handlers::health::health_check))
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        // Protected routes
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
        )
        // Add middleware
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // Run the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
