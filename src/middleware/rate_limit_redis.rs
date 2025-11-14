// Redis-backed rate limiter implementation
// Provides distributed rate limiting across multiple instances

#![allow(dead_code)]

use super::rate_limit::RateLimiter;
use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, AsyncCommands, RedisError};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error};

/// Redis rate limiter using Lua scripts for atomic operations
pub struct RedisRateLimiter {
    /// Redis connection pool
    conn: Arc<Mutex<MultiplexedConnection>>,
    /// Maximum failed attempts before blocking
    max_failed_attempts: u32,
    /// Block duration in seconds
    block_duration_secs: u64,
}

impl RedisRateLimiter {
    /// Create a new Redis rate limiter
    pub async fn new(
        redis_url: &str,
        max_failed_attempts: u32,
        block_duration_secs: u64,
    ) -> Result<Self, RedisError> {
        let client = redis::Client::open(redis_url)?;
        let conn = client.get_multiplexed_tokio_connection().await?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            max_failed_attempts,
            block_duration_secs,
        })
    }

    /// Get Redis key for rate limiting
    fn rate_limit_key(&self, key: &str) -> String {
        format!("rate_limit:{}", key)
    }

    /// Get Redis key for failed attempts
    fn failed_attempts_key(&self, key: &str) -> String {
        format!("failed_attempts:{}", key)
    }

    /// Get Redis key for blocking
    fn block_key(&self, key: &str) -> String {
        format!("blocked:{}", key)
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check_rate_limit(
        &self,
        key: &str,
        max_requests: u32,
        window_secs: u64,
    ) -> Result<(), u64> {
        let redis_key = self.rate_limit_key(key);
        let mut conn = self.conn.lock().await;

        // Use Lua script for atomic rate limiting using sliding window counter
        // This ensures accurate rate limiting even under high concurrency
        let script = r#"
            local key = KEYS[1]
            local max_requests = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])

            -- Remove old entries outside the window
            redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

            -- Count current requests in window
            local current = redis.call('ZCARD', key)

            if current < max_requests then
                -- Add new request with current timestamp as score
                redis.call('ZADD', key, now, now)
                redis.call('EXPIRE', key, window)
                return 0
            else
                -- Calculate retry-after time
                local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                if #oldest > 0 then
                    local retry_after = oldest[2] + window - now
                    return math.max(1, math.ceil(retry_after))
                else
                    return 1
                end
            end
        "#;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match redis::Script::new(script)
            .key(&redis_key)
            .arg(max_requests)
            .arg(window_secs)
            .arg(now)
            .invoke_async::<_, i64>(&mut *conn)
            .await
        {
            Ok(0) => Ok(()),
            Ok(retry_after) => Err(retry_after as u64),
            Err(e) => {
                error!("Redis rate limit error: {}", e);
                // Fail open on Redis errors to avoid blocking legitimate requests
                Ok(())
            }
        }
    }

    async fn record_failed_attempt(&self, key: &str) -> Result<(), String> {
        let attempts_key = self.failed_attempts_key(key);
        let block_key = self.block_key(key);
        let mut conn = self.conn.lock().await;

        // Increment failed attempts counter
        let attempts: u32 = conn
            .incr(&attempts_key, 1)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;

        // Set expiry on first attempt
        if attempts == 1 {
            let _: () = conn
                .expire(&attempts_key, self.block_duration_secs as i64)
                .await
                .map_err(|e| format!("Redis error: {}", e))?;
        }

        // Block if exceeded threshold
        if attempts >= self.max_failed_attempts {
            debug!("Blocking {} after {} failed attempts", key, attempts);
            let _: () = conn
                .set_ex(&block_key, 1, self.block_duration_secs)
                .await
                .map_err(|e| format!("Redis error: {}", e))?;
        }

        Ok(())
    }

    async fn is_blocked(&self, key: &str) -> Result<bool, String> {
        let block_key = self.block_key(key);
        let mut conn = self.conn.lock().await;

        let blocked: Option<i32> = conn
            .get(&block_key)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;

        Ok(blocked.is_some())
    }

    async fn reset(&self, key: &str) -> Result<(), String> {
        let rate_limit_key = self.rate_limit_key(key);
        let attempts_key = self.failed_attempts_key(key);
        let block_key = self.block_key(key);
        let mut conn = self.conn.lock().await;

        // Delete all keys for this rate limit entry
        let _: () = redis::pipe()
            .del(&rate_limit_key)
            .del(&attempts_key)
            .del(&block_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| format!("Redis error: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a Redis instance running
    // Skip them in CI unless Redis is available

    #[tokio::test]
    #[ignore] // Remove this to run with a local Redis instance
    async fn test_redis_rate_limit() {
        let limiter = RedisRateLimiter::new("redis://127.0.0.1/", 5, 300)
            .await
            .expect("Failed to connect to Redis");

        // Should allow first 10 requests
        for i in 0..10 {
            let result = limiter.check_rate_limit("test-key", 10, 60).await;
            assert!(result.is_ok(), "Request {} failed: {:?}", i, result);
        }

        // Next request should be rate limited
        let result = limiter.check_rate_limit("test-key", 10, 60).await;
        assert!(result.is_err());

        // Clean up
        limiter.reset("test-key").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Remove this to run with a local Redis instance
    async fn test_redis_failed_attempts() {
        let limiter = RedisRateLimiter::new("redis://127.0.0.1/", 3, 300)
            .await
            .expect("Failed to connect to Redis");

        limiter.reset("test-key-2").await.unwrap();

        // Record 3 failed attempts
        for _ in 0..3 {
            limiter.record_failed_attempt("test-key-2").await.unwrap();
        }

        // Should be blocked
        assert!(limiter.is_blocked("test-key-2").await.unwrap());

        // Clean up
        limiter.reset("test-key-2").await.unwrap();
    }
}
