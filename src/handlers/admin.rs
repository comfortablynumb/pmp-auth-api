use axum::{http::StatusCode, Extension, Json};
use serde_json::{json, Value};

use crate::middleware::auth::AuthUser;

pub async fn list_users(
    Extension(auth_user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // This endpoint is only accessible to admins
    // The middleware has already checked that the user is an admin

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "Admin endpoint - list all users",
            "requested_by": auth_user.claims.email,
            "note": "In production, this would return a list of users from the database"
        })),
    ))
}
