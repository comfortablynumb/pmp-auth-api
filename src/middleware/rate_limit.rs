// Rate limiting middleware and infrastructure
// Provides protection against brute force attacks and DDoS

#![allow(dead_code)]

use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// Rate limiter trait for different backend implementations
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Check if a request is allowed for the given key
    /// Returns Ok(()) if allowed, Err with retry-after seconds if rate limited
    async fn check_rate_limit(
        &self,
        key: &str,
        max_requests: u32,
        window_secs: u64,
    ) -> Result<(), u64>;

    /// Record a failed authentication attempt
    async fn record_failed_attempt(&self, key: &str) -> Result<(), String>;

    /// Check if an IP/user is currently blocked due to brute force attempts
    async fn is_blocked(&self, key: &str) -> Result<bool, String>;

    /// Reset the rate limit counter for a key
    async fn reset(&self, key: &str) -> Result<(), String>;
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window in seconds
    pub window_secs: u64,
    /// Maximum failed login attempts before blocking
    pub max_failed_attempts: u32,
    /// Block duration in seconds after max failed attempts
    pub block_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
            max_failed_attempts: 5,
            block_duration_secs: 300, // 5 minutes
        }
    }
}

/// Rate limit state shared across the application
#[derive(Clone)]
pub struct RateLimitState {
    pub limiter: Arc<dyn RateLimiter>,
    pub config: RateLimitConfig,
}

/// Extract rate limit key from request
/// Uses IP address and optionally client_id for per-client limiting
pub fn extract_rate_limit_key(req: &Request) -> String {
    // Try to get IP from X-Forwarded-For header first (proxy/load balancer)
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .or_else(|| req.headers().get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("unknown");

    // For now, use IP as the key
    // TODO: Add client_id extraction from request for per-client rate limiting
    format!("ip:{}", ip)
}

/// Rate limiting middleware for token endpoints
pub async fn rate_limit_middleware(
    State(rate_limit_state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let key = extract_rate_limit_key(&req);

    debug!("Rate limit check for key: {}", key);

    // Check if blocked due to brute force attempts
    match rate_limit_state.limiter.is_blocked(&key).await {
        Ok(true) => {
            warn!("Blocked request from: {}", key);
            return rate_limit_error(rate_limit_state.config.block_duration_secs);
        }
        Ok(false) => {
            // Not blocked, continue with rate limit check
        }
        Err(e) => {
            warn!("Error checking block status: {}", e);
            // Continue on error to avoid blocking legitimate requests
        }
    }

    // Check rate limit
    match rate_limit_state
        .limiter
        .check_rate_limit(
            &key,
            rate_limit_state.config.max_requests,
            rate_limit_state.config.window_secs,
        )
        .await
    {
        Ok(()) => {
            // Rate limit check passed, proceed with request
            next.run(req).await
        }
        Err(retry_after) => {
            warn!("Rate limit exceeded for: {}", key);
            rate_limit_error(retry_after)
        }
    }
}

/// Create a rate limit error response
fn rate_limit_error(retry_after: u64) -> Response {
    let body = Json(json!({
        "error": "rate_limit_exceeded",
        "error_description": "Too many requests. Please try again later.",
        "retry_after": retry_after
    }));

    (StatusCode::TOO_MANY_REQUESTS, body).into_response()
}

/// Middleware for recording failed authentication attempts
/// This should be called after authentication fails
pub async fn record_failed_auth_attempt(
    State(rate_limit_state): State<RateLimitState>,
    key: String,
) -> Result<(), String> {
    rate_limit_state.limiter.record_failed_attempt(&key).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rate_limit_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.max_failed_attempts, 5);
        assert_eq!(config.block_duration_secs, 300);
    }
}
