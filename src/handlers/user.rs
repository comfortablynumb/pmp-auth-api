use axum::{Extension, Json, http::StatusCode};
use serde_json::{Value, json};

use crate::middleware::auth::AuthUser;

pub async fn get_profile(
    Extension(auth_user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "id": auth_user.claims.sub,
            "email": auth_user.claims.email,
            "role": auth_user.claims.role,
        })),
    ))
}
