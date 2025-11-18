use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "PMP Auth API",
        version = "0.1.0",
        description = "Multi-tenant OAuth2, OIDC, SAML, and API Key authentication service",
        contact(
            name = "API Support",
            email = "support@example.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "https://api.example.com", description = "Production server")
    ),
    paths(
        // OAuth2 Authorization Server endpoints
        crate::auth::oauth2_server::oauth2_authorize,
        crate::auth::oauth2_server::oauth2_token,
        crate::auth::oauth2_server::jwks,
    ),
    components(
        schemas(
            // OAuth2 types
            crate::auth::oauth2_server::AuthorizeRequest,
            crate::auth::oauth2_server::TokenRequest,
            crate::auth::oauth2_server::TokenResponse,
        )
    ),
    tags(
        (name = "OAuth2", description = "OAuth2 Authorization Server endpoints"),
        (name = "OIDC", description = "OpenID Connect endpoints"),
        (name = "API Keys", description = "API Key management endpoints"),
        (name = "SAML", description = "SAML 2.0 Identity Provider endpoints"),
        (name = "Device Flow", description = "Device Authorization Grant endpoints (RFC 8628)"),
        (name = "Admin - Tenants", description = "Tenant management endpoints"),
        (name = "Admin - Clients", description = "OAuth2 client management endpoints"),
        (name = "Admin - Users", description = "User management endpoints"),
        (name = "Identity", description = "Identity provider management"),
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::Scopes;

        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT Bearer token authentication"))
                        .build(),
                ),
            );

            let scopes = Scopes::from_iter([
                ("openid".to_string(), "OpenID Connect scope".to_string()),
                (
                    "profile".to_string(),
                    "Access to user profile information".to_string(),
                ),
                ("email".to_string(), "Access to user email".to_string()),
                (
                    "offline_access".to_string(),
                    "Ability to get refresh tokens".to_string(),
                ),
            ]);

            components.add_security_scheme(
                "oauth2_client_credentials",
                SecurityScheme::OAuth2(utoipa::openapi::security::OAuth2::new([
                    utoipa::openapi::security::Flow::ClientCredentials(
                        utoipa::openapi::security::ClientCredentials::new(
                            "/api/v1/tenant/{tenant_id}/oauth/token",
                            scopes.clone(),
                        ),
                    ),
                ])),
            );
            components.add_security_scheme(
                "oauth2_authorization_code",
                SecurityScheme::OAuth2(utoipa::openapi::security::OAuth2::new([
                    utoipa::openapi::security::Flow::AuthorizationCode(
                        utoipa::openapi::security::AuthorizationCode::new(
                            "/api/v1/tenant/{tenant_id}/oauth/authorize",
                            "/api/v1/tenant/{tenant_id}/oauth/token",
                            scopes,
                        ),
                    ),
                ])),
            );
        }
    }
}
