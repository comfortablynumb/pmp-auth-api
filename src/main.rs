mod openapi;

use axum::{
    http::Request,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// Use library modules instead of duplicating them in the binary
use pmp_auth_api::{admin, auth, config, handlers, metrics, middleware, models, storage, AppState};

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

    tracing::info!("🚀 PMP Auth API starting...");
    tracing::info!("📋 Version: {}", env!("CARGO_PKG_VERSION"));

    // Load environment variables
    tracing::debug!("Loading environment variables from .env file (if present)");
    dotenvy::dotenv().ok();

    // Log important environment variables (without exposing secrets)
    if let Ok(config_path) = std::env::var("CONFIG_PATH") {
        tracing::info!("📁 CONFIG_PATH: {}", config_path);
    }
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        tracing::info!("📝 RUST_LOG: {}", rust_log);
    }

    // Load tenant configuration (required)
    tracing::info!("📄 Loading tenant configuration...");
    let tenant_config = match config::load_config_with_fallback() {
        Ok(config) => {
            tracing::info!("✅ Multi-tenant configuration loaded successfully");
            config
        }
        Err(e) => {
            tracing::error!("❌ Failed to load tenant configuration: {}", e);
            tracing::error!("💡 Configuration is required to start the server");
            tracing::error!("🔍 Please ensure:");
            tracing::error!("   1. A valid config file exists (config/config.yaml or config/config.docker.yaml)");
            tracing::error!(
                "   2. Or set CONFIG_PATH environment variable to point to your config file"
            );
            tracing::error!("   3. See config/config.example.yaml for reference");
            std::process::exit(1);
        }
    };

    tracing::info!(
        "🔧 Building application routes for {} tenant(s)...",
        tenant_config.tenants.len()
    );

    // Initialize storage backend
    tracing::info!("💾 Initializing storage backend...");
    let storage_backend = storage::create_storage_backend(&tenant_config.storage);
    tracing::info!(
        "✅ Storage backend initialized: {:?}",
        tenant_config.storage
    );

    // Create application state
    let app_state = AppState {
        config: tenant_config.clone(),
        storage: Arc::from(storage_backend),
    };

    // Build our application with routes
    let app = Router::new()
        // Health check routes (always available)
        .route("/", get(handlers::health::health_check))
        .route("/health", get(handlers::health::health_check))
        // Kubernetes-style health probes
        .route("/healthz", get(handlers::health::health_check))
        .route("/livez", get(handlers::health::health_check))
        .route("/readyz", get(handlers::health::health_check))
        // Metrics endpoint
        .route(
            "/metrics",
            get(metrics::prometheus_metrics::metrics_handler),
        )
        // Device authorization page
        .route("/device", get(handlers::device::device_page))
        // Multi-tenant routes
        .nest("/api/v1/tenant", create_tenant_routes(app_state.clone()))
        // Admin routes
        .nest("/api/v1/admin", create_admin_routes(app_state.clone()))
        // Swagger UI (includes OpenAPI spec endpoint at /api/openapi.json)
        .merge(SwaggerUi::new("/api/swagger").url("/api/openapi.json", openapi::ApiDoc::openapi()));

    tracing::info!("✅ Multi-tenant and admin routes configured");

    // Log all available routes
    log_available_routes(&tenant_config);

    // Add global middleware
    tracing::debug!("Adding global middleware (CORS, Tracing)");

    // Collect all allowed origins from all tenants
    let mut allowed_origins: Vec<String> = tenant_config
        .tenants
        .values()
        .flat_map(|tenant| tenant.allowed_origins.clone())
        .collect();

    // Remove duplicates
    allowed_origins.sort();
    allowed_origins.dedup();

    // Configure CORS based on tenant origins
    let cors_layer = if allowed_origins.is_empty() {
        tracing::warn!("No CORS origins configured for any tenant - using permissive CORS");
        CorsLayer::permissive()
    } else {
        tracing::info!("Configuring CORS with {} allowed origins", allowed_origins.len());

        use tower_http::cors::{Any, AllowOrigin};
        use axum::http::{Method, HeaderValue};

        // Parse origins into HeaderValue
        let origin_values: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect();

        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origin_values))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
                Method::PATCH,
            ])
            .allow_headers(Any)
            .allow_credentials(true)
    };

    // Add security headers middleware
    let app = app
        .layer(axum::middleware::from_fn(middleware::security_headers::add_security_headers))
        .layer(cors_layer)
        .layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let uri = request.uri().path();
                // Skip span creation entirely for health/metrics
                if uri.starts_with("/health")
                    || uri.starts_with("/metrics")
                    || uri == "/"
                    || uri == "/livez"
                    || uri == "/readyz"
                    || uri == "/healthz"
                {
                    tracing::Span::none()
                } else {
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        uri = %uri,
                        version = ?request.version(),
                    )
                }
            })
            .on_request(|request: &Request<_>, _span: &tracing::Span| {
                let uri = request.uri().path();
                // Don't log health check and metrics requests
                if !uri.starts_with("/health")
                    && !uri.starts_with("/metrics")
                    && uri != "/"
                    && uri != "/livez"
                    && uri != "/readyz"
                    && uri != "/healthz"
                {
                    tracing::info!("→ {} {}", request.method(), uri);
                }
            })
            .on_response(
                |response: &axum::http::Response<_>,
                 latency: std::time::Duration,
                 _span: &tracing::Span| {
                    // Don't log health check and metrics responses
                    // The span is None for these endpoints, so we can check if span is disabled
                    if !_span.is_disabled() {
                        tracing::debug!(
                            "finished processing request latency={} ms status={}",
                            latency.as_millis(),
                            response.status()
                        );
                    }
                },
            ),
    );

    tracing::info!("✅ Application routes and middleware configured");

    // Run the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("🌐 Binding to address: {}", addr);
    tracing::info!("📋 Mode: Multi-tenant");
    tracing::info!("📖 Tenant routes: /api/v1/tenant/{{tenant-id}}/*");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            tracing::info!("✅ Successfully bound to {}", addr);
            listener
        }
        Err(e) => {
            tracing::error!("❌ Failed to bind to address {}: {}", addr, e);
            tracing::error!(
                "💡 Make sure the port is not already in use and you have permission to bind to it"
            );
            tracing::error!("🔍 Possible causes:");
            tracing::error!("   - Port 3000 is already in use by another process");
            tracing::error!("   - Insufficient permissions to bind to port 3000");
            tracing::error!("   - Network configuration issues");
            std::process::exit(1);
        }
    };

    tracing::info!("🎉 PMP Auth API is ready to accept connections!");
    tracing::info!(
        "📍 Health check: http://{}:{}/health",
        addr.ip(),
        addr.port()
    );
    tracing::info!("📊 Metrics: http://{}:{}/metrics", addr.ip(), addr.port());

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("❌ Server error: {}", e);
        tracing::error!("💡 The server encountered a fatal error and must exit");
        tracing::error!("🔍 Error details: {:?}", e);
        std::process::exit(1);
    }

    tracing::info!("👋 Server shut down gracefully");
}

fn create_tenant_routes(state: AppState) -> Router {
    Router::new()
        // List available identity providers for a tenant
        .route(
            "/:tenant_id/strategies",
            get(handlers::tenant_auth::list_strategies),
        )
        // OAuth2 Authorization Server endpoints
        .route("/:tenant_id/oauth/authorize", get(auth::oauth2_authorize))
        .route("/:tenant_id/oauth/token", post(auth::oauth2_token))
        .route(
            "/:tenant_id/oauth/logout",
            get(auth::oauth2_logout).post(auth::oauth2_logout),
        )
        // Dynamic Client Registration (RFC 7591, RFC 7592)
        .route("/:tenant_id/oauth/register", post(auth::register_client))
        .route(
            "/:tenant_id/oauth/register/:client_id",
            get(auth::get_client)
                .put(auth::update_client)
                .delete(auth::delete_client),
        )
        // Token Exchange (RFC 8693)
        .route("/:tenant_id/oauth/token/exchange", post(auth::token_exchange))
        // Token Introspection and Revocation endpoints (RFC 7662, RFC 7009)
        .route("/:tenant_id/oauth/introspect", post(auth::token_introspect))
        .route("/:tenant_id/oauth/revoke", post(auth::token_revoke))
        // JWKS endpoint for public key distribution
        .route("/:tenant_id/.well-known/jwks.json", get(auth::jwks))
        // OpenID Connect endpoints
        .route(
            "/:tenant_id/.well-known/openid-configuration",
            get(auth::oidc_discovery),
        )
        .route("/:tenant_id/oauth/userinfo", get(auth::oidc_userinfo))
        .route(
            "/:tenant_id/oauth/check_session_iframe",
            get(auth::check_session_iframe),
        )
        // API Key Management endpoints
        .route("/:tenant_id/api-keys/create", post(auth::create_api_key))
        .route("/:tenant_id/api-keys/list", get(auth::list_api_keys))
        .route(
            "/:tenant_id/api-keys/:key_id/revoke",
            post(auth::revoke_api_key),
        )
        // SAML 2.0 Identity Provider endpoints
        .route("/:tenant_id/saml/metadata", get(auth::saml_metadata))
        .route(
            "/:tenant_id/saml/sso",
            get(auth::saml_sso_redirect).post(auth::saml_sso_post),
        )
        .route("/:tenant_id/saml/slo", post(auth::saml_slo))
        // Device Authorization Grant endpoints (RFC 8628)
        .route(
            "/:tenant_id/oauth/device/authorize",
            post(auth::device_authorize),
        )
        .route("/:tenant_id/oauth/device/token", post(auth::device_token))
        .route("/:tenant_id/oauth/device/verify", post(auth::device_verify))
        .route(
            "/:tenant_id/oauth/device/confirm",
            post(auth::device_confirm),
        )
        // OAuth2 Federation endpoints (external provider authentication)
        .route(
            "/:tenant_id/federate/:provider_id/login",
            get(auth::federation_login),
        )
        .route(
            "/:tenant_id/federate/:provider_id/callback",
            get(auth::federation_callback),
        )
        .with_state(state)
}

fn create_admin_routes(state: AppState) -> Router {
    Router::new()
        // Tenant management
        .route("/tenants", get(admin::list_tenants))
        .route("/tenants", post(admin::create_tenant))
        .route("/tenants/:tenant_id", get(admin::get_tenant))
        .route(
            "/tenants/:tenant_id",
            axum::routing::put(admin::update_tenant),
        )
        .route(
            "/tenants/:tenant_id",
            axum::routing::delete(admin::delete_tenant),
        )
        // Client management
        .route("/tenants/:tenant_id/clients", get(admin::list_clients))
        .route("/tenants/:tenant_id/clients", post(admin::create_client))
        .route(
            "/tenants/:tenant_id/clients/:client_id",
            get(admin::get_client),
        )
        .route(
            "/tenants/:tenant_id/clients/:client_id",
            axum::routing::put(admin::update_client),
        )
        .route(
            "/tenants/:tenant_id/clients/:client_id",
            axum::routing::delete(admin::delete_client),
        )
        // User management
        .route("/tenants/:tenant_id/users", get(admin::list_users))
        .route("/tenants/:tenant_id/users", post(admin::create_user))
        .route("/tenants/:tenant_id/users/:user_id", get(admin::get_user))
        .route(
            "/tenants/:tenant_id/users/:user_id",
            axum::routing::put(admin::update_user),
        )
        .route(
            "/tenants/:tenant_id/users/:user_id",
            axum::routing::delete(admin::delete_user),
        )
        .with_state(state)
}

fn log_available_routes(config: &crate::models::AppConfig) {
    tracing::info!("📋 Available Routes:");
    tracing::info!("");

    // Global routes
    tracing::info!("🌍 Global Routes:");
    tracing::info!("  GET    /");
    tracing::info!("  GET    /health");
    tracing::info!("  GET    /healthz");
    tracing::info!("  GET    /livez");
    tracing::info!("  GET    /readyz");
    tracing::info!("  GET    /metrics");
    tracing::info!("  GET    /api/openapi.json");
    tracing::info!("  GET    /api/swagger");
    tracing::info!("  GET    /device");
    tracing::info!("");

    // Per-tenant routes
    for (tenant_id, tenant) in &config.tenants {
        tracing::info!("🏢 Tenant: {} ({})", tenant_id, tenant.name);

        // OAuth2 routes
        if tenant.get_oauth2_provider().is_some() {
            tracing::info!("  📝 OAuth2 Authorization Server:");
            tracing::info!("    GET    /api/v1/tenant/{}/strategies", tenant_id);
            tracing::info!("    GET    /api/v1/tenant/{}/oauth/authorize", tenant_id);
            tracing::info!("    POST   /api/v1/tenant/{}/oauth/token", tenant_id);
            tracing::info!("    POST   /api/v1/tenant/{}/oauth/introspect", tenant_id);
            tracing::info!("    POST   /api/v1/tenant/{}/oauth/revoke", tenant_id);
            tracing::info!(
                "    GET    /api/v1/tenant/{}/.well-known/jwks.json",
                tenant_id
            );
        }

        // OIDC routes
        if tenant.get_oidc_provider().is_some() {
            tracing::info!("  🔐 OpenID Connect:");
            tracing::info!(
                "    GET    /api/v1/tenant/{}/.well-known/openid-configuration",
                tenant_id
            );
            tracing::info!("    GET    /api/v1/tenant/{}/oauth/userinfo", tenant_id);
        }

        // API Keys routes
        if tenant.api_keys.is_some() {
            tracing::info!("  🔑 API Key Management:");
            tracing::info!("    POST   /api/v1/tenant/{}/api-keys/create", tenant_id);
            tracing::info!("    GET    /api/v1/tenant/{}/api-keys/list", tenant_id);
            tracing::info!(
                "    POST   /api/v1/tenant/{}/api-keys/:key_id/revoke",
                tenant_id
            );
        }

        // SAML routes
        if tenant.get_saml_provider().is_some() {
            tracing::info!("  🎫 SAML 2.0 Identity Provider:");
            tracing::info!("    GET    /api/v1/tenant/{}/saml/metadata", tenant_id);
            tracing::info!("    GET    /api/v1/tenant/{}/saml/sso", tenant_id);
            tracing::info!("    POST   /api/v1/tenant/{}/saml/sso", tenant_id);
            tracing::info!("    POST   /api/v1/tenant/{}/saml/slo", tenant_id);
        }

        // Device flow routes (always available for OAuth2 tenants)
        if tenant.get_oauth2_provider().is_some() {
            tracing::info!("  📱 Device Authorization Grant (RFC 8628):");
            tracing::info!(
                "    POST   /api/v1/tenant/{}/oauth/device/authorize",
                tenant_id
            );
            tracing::info!("    POST   /api/v1/tenant/{}/oauth/device/token", tenant_id);
            tracing::info!(
                "    POST   /api/v1/tenant/{}/oauth/device/verify",
                tenant_id
            );
            tracing::info!(
                "    POST   /api/v1/tenant/{}/oauth/device/confirm",
                tenant_id
            );
        }

        // Federation routes
        if !tenant.federation_providers.is_empty() {
            tracing::info!("  🌐 OAuth2 Federation (External Providers):");
            for provider_id in tenant.federation_providers.keys() {
                tracing::info!(
                    "    GET    /api/v1/tenant/{}/federate/{}/login",
                    tenant_id, provider_id
                );
                tracing::info!(
                    "    GET    /api/v1/tenant/{}/federate/{}/callback",
                    tenant_id, provider_id
                );
            }
        }

        tracing::info!("");
    }

    // Admin routes
    tracing::info!("🔧 Admin API:");
    tracing::info!("  📂 Tenant Management:");
    tracing::info!("    GET    /api/v1/admin/tenants");
    tracing::info!("    POST   /api/v1/admin/tenants");
    tracing::info!("    GET    /api/v1/admin/tenants/:tenant_id");
    tracing::info!("    PUT    /api/v1/admin/tenants/:tenant_id");
    tracing::info!("    DELETE /api/v1/admin/tenants/:tenant_id");
    tracing::info!("  👥 Client Management:");
    tracing::info!("    GET    /api/v1/admin/tenants/:tenant_id/clients");
    tracing::info!("    POST   /api/v1/admin/tenants/:tenant_id/clients");
    tracing::info!("    GET    /api/v1/admin/tenants/:tenant_id/clients/:client_id");
    tracing::info!("    PUT    /api/v1/admin/tenants/:tenant_id/clients/:client_id");
    tracing::info!("    DELETE /api/v1/admin/tenants/:tenant_id/clients/:client_id");
    tracing::info!("  👤 User Management:");
    tracing::info!("    GET    /api/v1/admin/tenants/:tenant_id/users");
    tracing::info!("    POST   /api/v1/admin/tenants/:tenant_id/users");
    tracing::info!("    GET    /api/v1/admin/tenants/:tenant_id/users/:user_id");
    tracing::info!("    PUT    /api/v1/admin/tenants/:tenant_id/users/:user_id");
    tracing::info!("    DELETE /api/v1/admin/tenants/:tenant_id/users/:user_id");
    tracing::info!("");
}
