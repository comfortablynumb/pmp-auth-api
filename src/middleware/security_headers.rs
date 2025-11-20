// Security Headers Middleware
// Adds security-related HTTP headers to all responses

use axum::{
    body::Body,
    http::{Request, header, HeaderName},
    middleware::Next,
    response::IntoResponse,
};

/// Middleware to add security headers to all responses
///
/// Adds the following headers:
/// - Content-Security-Policy: Restricts resource loading to prevent XSS
/// - X-Frame-Options: Prevents clickjacking by denying framing
/// - X-Content-Type-Options: Prevents MIME type sniffing
/// - Strict-Transport-Security: Enforces HTTPS connections
/// - X-XSS-Protection: Legacy XSS protection (for older browsers)
/// - Referrer-Policy: Controls referrer information sent
pub async fn add_security_headers(
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Content Security Policy - Restrictive by default
    // Adjust based on your application's needs
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );

    // Prevent the page from being loaded in an iframe (clickjacking protection)
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    );

    // Prevent MIME type sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );

    // Enforce HTTPS for 1 year (31536000 seconds)
    // includeSubDomains applies to all subdomains
    // preload allows inclusion in browser preload lists
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );

    // XSS Protection (legacy, for older browsers)
    // Modern browsers use CSP instead
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        "1; mode=block".parse().unwrap(),
    );

    // Referrer Policy - Don't send referrer to cross-origin requests
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Permissions Policy - Restrict browser features
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
            .parse()
            .unwrap(),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        Router,
        routing::get,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "test response"
    }

    #[tokio::test]
    async fn test_security_headers_added() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(add_security_headers));

        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();

        // Check that all security headers are present
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(headers.contains_key(header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(header::REFERRER_POLICY));

        // Verify specific header values
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert!(headers
            .get(header::STRICT_TRANSPORT_SECURITY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("max-age=31536000"));
    }
}
