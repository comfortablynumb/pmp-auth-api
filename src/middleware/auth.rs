use axum::{
    Json,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::auth::jwt::validate_token;
use crate::models::{Claims, UserRole};

// Extension to store claims in request
#[derive(Clone)]
pub struct AuthUser {
    pub claims: Claims,
}

pub async fn auth_middleware(
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if it starts with "Bearer "
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract the token
    let token = &auth_header[7..];

    // Validate the token
    let claims = validate_token(token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Add the claims to the request extensions
    request.extensions_mut().insert(AuthUser { claims });

    Ok(next.run(request).await)
}

pub async fn require_admin(request: Request, next: Next) -> Result<Response, impl IntoResponse> {
    // Get the claims from the request extensions
    let auth_user = request.extensions().get::<AuthUser>().ok_or_else(|| {
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
