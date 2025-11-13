// Device verification page handler

use axum::response::{Html, IntoResponse};

/// Serve the device verification HTML page
/// GET /device
pub async fn device_page() -> impl IntoResponse {
    let html = include_str!("../../static/device.html");
    Html(html)
}
