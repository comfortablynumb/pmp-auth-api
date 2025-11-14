// In-memory rate limiter implementation using token bucket algorithm

#![allow(dead_code)]

use super::rate_limit::RateLimiter;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::debug;

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Number of tokens currently available
    tokens: f64,
    /// Last time the bucket was refilled
    last_refill: u64,
    /// Maximum tokens (capacity)
    capacity: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        let now = current_timestamp();
        Self {
            tokens: capacity,
            last_refill: now,
            capacity,
            refill_rate,
        }
    }

    /// Try to consume a token
    /// Returns Ok(()) if successful, Err with retry-after seconds if not
    fn try_consume(&mut self) -> Result<(), u64> {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate retry-after time (when next token will be available)
            let tokens_needed = 1.0 - self.tokens;
            let retry_after = (tokens_needed / self.refill_rate).ceil() as u64;
            Err(retry_after.max(1))
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = current_timestamp();
        let elapsed = now.saturating_sub(self.last_refill);

        if elapsed > 0 {
            let new_tokens = (elapsed as f64) * self.refill_rate;
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// Failed attempt tracking
#[derive(Debug, Clone)]
struct FailedAttempts {
    /// Number of failed attempts
    count: u32,
    /// When the tracking started
    first_attempt: u64,
    /// When the user was blocked
    blocked_until: Option<u64>,
}

/// In-memory rate limiter
pub struct MemoryRateLimiter {
    /// Token buckets for rate limiting
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Failed authentication attempts tracking
    failed_attempts: Arc<RwLock<HashMap<String, FailedAttempts>>>,
    /// Maximum failed attempts before blocking
    max_failed_attempts: u32,
    /// Block duration in seconds
    block_duration_secs: u64,
}

impl MemoryRateLimiter {
    pub fn new(max_failed_attempts: u32, block_duration_secs: u64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            max_failed_attempts,
            block_duration_secs,
        }
    }
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn check_rate_limit(
        &self,
        key: &str,
        max_requests: u32,
        window_secs: u64,
    ) -> Result<(), u64> {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            let capacity = max_requests as f64;
            let refill_rate = capacity / (window_secs as f64);
            TokenBucket::new(capacity, refill_rate)
        });

        bucket.try_consume()
    }

    async fn record_failed_attempt(&self, key: &str) -> Result<(), String> {
        let mut attempts = self.failed_attempts.write().await;
        let now = current_timestamp();

        let entry = attempts.entry(key.to_string()).or_insert(FailedAttempts {
            count: 0,
            first_attempt: now,
            blocked_until: None,
        });

        // Reset counter if it's been more than the block duration since first attempt
        if now.saturating_sub(entry.first_attempt) > self.block_duration_secs {
            entry.count = 0;
            entry.first_attempt = now;
            entry.blocked_until = None;
        }

        entry.count += 1;

        // Block if exceeded max attempts
        if entry.count >= self.max_failed_attempts {
            entry.blocked_until = Some(now + self.block_duration_secs);
            debug!("Blocking {} after {} failed attempts", key, entry.count);
        }

        Ok(())
    }

    async fn is_blocked(&self, key: &str) -> Result<bool, String> {
        let mut attempts = self.failed_attempts.write().await;
        let now = current_timestamp();

        if let Some(entry) = attempts.get_mut(key)
            && let Some(blocked_until) = entry.blocked_until
        {
            if now < blocked_until {
                return Ok(true);
            } else {
                // Unblock and reset
                entry.blocked_until = None;
                entry.count = 0;
                entry.first_attempt = now;
                return Ok(false);
            }
        }

        Ok(false)
    }

    async fn reset(&self, key: &str) -> Result<(), String> {
        let mut buckets = self.buckets.write().await;
        buckets.remove(key);

        let mut attempts = self.failed_attempts.write().await;
        attempts.remove(key);

        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_allows_requests_under_limit() {
        let limiter = MemoryRateLimiter::new(5, 300);

        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("test-key", 10, 60).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_over_limit() {
        let limiter = MemoryRateLimiter::new(5, 300);

        // Consume all tokens
        for _ in 0..10 {
            let _ = limiter.check_rate_limit("test-key", 10, 60).await;
        }

        // Next request should be rate limited
        assert!(limiter.check_rate_limit("test-key", 10, 60).await.is_err());
    }

    #[tokio::test]
    async fn test_failed_attempts_blocks_after_threshold() {
        let limiter = MemoryRateLimiter::new(3, 300);

        // Record 3 failed attempts
        for _ in 0..3 {
            limiter.record_failed_attempt("test-key").await.unwrap();
        }

        // Should be blocked
        assert!(limiter.is_blocked("test-key").await.unwrap());
    }

    #[tokio::test]
    async fn test_reset_clears_rate_limit() {
        let limiter = MemoryRateLimiter::new(5, 300);

        // Consume all tokens
        for _ in 0..10 {
            let _ = limiter.check_rate_limit("test-key", 10, 60).await;
        }

        // Reset
        limiter.reset("test-key").await.unwrap();

        // Should allow requests again
        assert!(limiter.check_rate_limit("test-key", 10, 60).await.is_ok());
    }
}
