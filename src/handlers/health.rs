use axum::{Json, http::StatusCode};
use serde_json::{Value, json};

pub async fn health_check() -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "service": "pmp-auth-api",
            "version": env!("CARGO_PKG_VERSION")
        })),
    )
}
