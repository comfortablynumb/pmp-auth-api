use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub details: Option<serde_json::Value>,
}

impl HealthCheckResult {
    pub fn healthy(name: String, duration_ms: u64) -> Self {
        Self {
            name,
            status: HealthStatus::Healthy,
            message: None,
            checked_at: Utc::now(),
            duration_ms,
            details: None,
        }
    }

    pub fn degraded(name: String, message: String, duration_ms: u64) -> Self {
        Self {
            name,
            status: HealthStatus::Degraded,
            message: Some(message),
            checked_at: Utc::now(),
            duration_ms,
            details: None,
        }
    }

    pub fn unhealthy(name: String, message: String, duration_ms: u64) -> Self {
        Self {
            name,
            status: HealthStatus::Unhealthy,
            message: Some(message),
            checked_at: Utc::now(),
            duration_ms,
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Health check trait
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Name of the health check
    fn name(&self) -> &str;

    /// Perform the health check
    async fn check(&self) -> HealthCheckResult;

    /// Whether this check is critical (affects overall health)
    fn is_critical(&self) -> bool {
        true
    }

    /// Timeout for this health check
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

/// Dependency health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    pub name: String,
    pub dependency_type: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Database health check
pub struct DatabaseHealthCheck {
    storage: Arc<dyn crate::storage::StorageBackend>,
}

impl DatabaseHealthCheck {
    pub fn new(storage: Arc<dyn crate::storage::StorageBackend>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // Try to perform a simple operation
        let result = self.storage.list_api_keys("health_check", 1).await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => HealthCheckResult::healthy("database".to_string(), duration_ms),
            Err(e) => {
                error!("Database health check failed: {}", e);
                HealthCheckResult::unhealthy(
                    "database".to_string(),
                    format!("Database error: {}", e),
                    duration_ms,
                )
            }
        }
    }

    fn is_critical(&self) -> bool {
        true
    }
}

/// Redis health check
pub struct RedisHealthCheck {
    redis_client: Option<redis::Client>,
}

impl RedisHealthCheck {
    pub fn new(redis_url: Option<String>) -> Self {
        let redis_client = redis_url.and_then(|url| redis::Client::open(url).ok());
        Self { redis_client }
    }
}

#[async_trait]
impl HealthCheck for RedisHealthCheck {
    fn name(&self) -> &str {
        "redis"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        if self.redis_client.is_none() {
            return HealthCheckResult::healthy("redis".to_string(), 0)
                .with_details(serde_json::json!({"configured": false}));
        }

        let client = self.redis_client.as_ref().unwrap();

        match client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                use redis::AsyncCommands;
                match conn.ping::<String>().await {
                    Ok(_) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        HealthCheckResult::healthy("redis".to_string(), duration_ms)
                    }
                    Err(e) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        error!("Redis ping failed: {}", e);
                        HealthCheckResult::unhealthy(
                            "redis".to_string(),
                            format!("Ping failed: {}", e),
                            duration_ms,
                        )
                    }
                }
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                error!("Redis connection failed: {}", e);
                HealthCheckResult::unhealthy(
                    "redis".to_string(),
                    format!("Connection failed: {}", e),
                    duration_ms,
                )
            }
        }
    }

    fn is_critical(&self) -> bool {
        false // Redis is optional for rate limiting
    }
}

/// LDAP health check
pub struct LdapHealthCheck {
    ldap_backend: Option<Arc<crate::ldap::backend::LdapBackendImpl>>,
}

impl LdapHealthCheck {
    pub fn new(ldap_backend: Option<Arc<crate::ldap::backend::LdapBackendImpl>>) -> Self {
        Self { ldap_backend }
    }
}

#[async_trait]
impl HealthCheck for LdapHealthCheck {
    fn name(&self) -> &str {
        "ldap"
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        if self.ldap_backend.is_none() {
            return HealthCheckResult::healthy("ldap".to_string(), 0)
                .with_details(serde_json::json!({"configured": false}));
        }

        let backend = self.ldap_backend.as_ref().unwrap();

        match backend.health_check().await {
            Ok(_) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                HealthCheckResult::healthy("ldap".to_string(), duration_ms)
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                error!("LDAP health check failed: {}", e);
                HealthCheckResult::degraded(
                    "ldap".to_string(),
                    format!("LDAP error: {}", e),
                    duration_ms,
                )
            }
        }
    }

    fn is_critical(&self) -> bool {
        false // LDAP may be one of multiple auth backends
    }
}

/// External OAuth2 provider health check
pub struct OAuth2ProviderHealthCheck {
    provider_name: String,
    userinfo_url: Option<String>,
}

impl OAuth2ProviderHealthCheck {
    pub fn new(provider_name: String, userinfo_url: Option<String>) -> Self {
        Self {
            provider_name,
            userinfo_url,
        }
    }
}

#[async_trait]
impl HealthCheck for OAuth2ProviderHealthCheck {
    fn name(&self) -> &str {
        &self.provider_name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        if self.userinfo_url.is_none() {
            return HealthCheckResult::healthy(self.provider_name.clone(), 0)
                .with_details(serde_json::json!({"configured": false}));
        }

        let url = self.userinfo_url.as_ref().unwrap();

        // Just check if we can reach the endpoint (without auth)
        let client = reqwest::Client::new();
        match timeout(Duration::from_secs(5), client.head(url).send()).await {
            Ok(Ok(response)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let status = response.status();

                if status.is_client_error() || status.is_server_error() {
                    // Some providers return 401 when no auth is provided, which is actually good
                    if status == 401 || status == 403 {
                        HealthCheckResult::healthy(self.provider_name.clone(), duration_ms)
                    } else {
                        warn!("OAuth2 provider returned status: {}", status);
                        HealthCheckResult::degraded(
                            self.provider_name.clone(),
                            format!("Provider returned status: {}", status),
                            duration_ms,
                        )
                    }
                } else {
                    HealthCheckResult::healthy(self.provider_name.clone(), duration_ms)
                }
            }
            Ok(Err(e)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                error!("OAuth2 provider health check failed: {}", e);
                HealthCheckResult::unhealthy(
                    self.provider_name.clone(),
                    format!("Connection failed: {}", e),
                    duration_ms,
                )
            }
            Err(_) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                error!("OAuth2 provider health check timed out");
                HealthCheckResult::unhealthy(
                    self.provider_name.clone(),
                    "Connection timeout".to_string(),
                    duration_ms,
                )
            }
        }
    }

    fn is_critical(&self) -> bool {
        false // External providers may be optional
    }
}

/// System health check (basic application health)
pub struct SystemHealthCheck;

#[async_trait]
impl HealthCheck for SystemHealthCheck {
    fn name(&self) -> &str {
        "system"
    }

    async fn check(&self) -> HealthCheckResult {
        // Always healthy - if we can respond, we're alive
        HealthCheckResult::healthy("system".to_string(), 0).with_details(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }))
    }

    fn is_critical(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_health_check() {
        let check = SystemHealthCheck;
        let result = check.check().await;

        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.name, "system");
    }

    #[test]
    fn test_health_check_result() {
        let result = HealthCheckResult::healthy("test".to_string(), 100);
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.duration_ms, 100);

        let result = HealthCheckResult::degraded("test".to_string(), "warning".to_string(), 200);
        assert_eq!(result.status, HealthStatus::Degraded);
        assert!(result.message.is_some());

        let result = HealthCheckResult::unhealthy("test".to_string(), "error".to_string(), 300);
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }
}
