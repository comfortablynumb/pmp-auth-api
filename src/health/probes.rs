use super::checks::{HealthCheck, HealthCheckResult, HealthStatus};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub status: HealthStatus,
    pub timestamp: DateTime<Utc>,
    pub checks: Vec<HealthCheckResult>,
    pub summary: ProbeSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub total_checks: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unhealthy: usize,
}

impl ProbeResponse {
    pub fn new(checks: Vec<HealthCheckResult>) -> Self {
        let total_checks = checks.len();
        let healthy = checks
            .iter()
            .filter(|c| c.status == HealthStatus::Healthy)
            .count();
        let degraded = checks
            .iter()
            .filter(|c| c.status == HealthStatus::Degraded)
            .count();
        let unhealthy = checks
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count();

        let status = if unhealthy > 0 {
            HealthStatus::Unhealthy
        } else if degraded > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        Self {
            status,
            timestamp: Utc::now(),
            checks,
            summary: ProbeSummary {
                total_checks,
                healthy,
                degraded,
                unhealthy,
            },
        }
    }

    pub fn http_status_code(&self) -> StatusCode {
        match self.status {
            HealthStatus::Healthy => StatusCode::OK,
            HealthStatus::Degraded => StatusCode::OK, // Still considered OK
            HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for ProbeResponse {
    fn into_response(self) -> Response {
        let status = self.http_status_code();
        (status, Json(self)).into_response()
    }
}

/// Liveness probe - checks if the application is running
pub struct LivenessProbe {
    checks: Vec<Arc<dyn HealthCheck>>,
}

impl LivenessProbe {
    pub fn new() -> Self {
        Self { checks: vec![] }
    }

    pub fn add_check(mut self, check: Arc<dyn HealthCheck>) -> Self {
        self.checks.push(check);
        self
    }

    pub async fn probe(&self) -> ProbeResponse {
        let mut results = Vec::new();

        for check in &self.checks {
            if check.is_critical() {
                let result = check.check().await;
                results.push(result);
            }
        }

        // If no critical checks, always return healthy
        if results.is_empty() {
            results.push(HealthCheckResult::healthy("liveness".to_string(), 0));
        }

        ProbeResponse::new(results)
    }
}

impl Default for LivenessProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Readiness probe - checks if the application is ready to serve traffic
pub struct ReadinessProbe {
    checks: Vec<Arc<dyn HealthCheck>>,
}

impl ReadinessProbe {
    pub fn new() -> Self {
        Self { checks: vec![] }
    }

    pub fn add_check(mut self, check: Arc<dyn HealthCheck>) -> Self {
        self.checks.push(check);
        self
    }

    pub async fn probe(&self) -> ProbeResponse {
        let mut results = Vec::new();

        for check in &self.checks {
            let result = check.check().await;
            results.push(result);
        }

        ProbeResponse::new(results)
    }
}

impl Default for ReadinessProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Startup probe - checks if the application has started successfully
pub struct StartupProbe {
    checks: Vec<Arc<dyn HealthCheck>>,
    started: Arc<RwLock<bool>>,
}

impl StartupProbe {
    pub fn new() -> Self {
        Self {
            checks: vec![],
            started: Arc::new(RwLock::new(false)),
        }
    }

    pub fn add_check(mut self, check: Arc<dyn HealthCheck>) -> Self {
        self.checks.push(check);
        self
    }

    pub async fn probe(&self) -> ProbeResponse {
        let started = *self.started.read().await;

        if started {
            return ProbeResponse::new(vec![HealthCheckResult::healthy("startup".to_string(), 0)]);
        }

        let mut results = Vec::new();

        for check in &self.checks {
            let result = check.check().await;
            results.push(result);
        }

        let response = ProbeResponse::new(results);

        // Mark as started if all checks pass
        if response.status == HealthStatus::Healthy {
            let mut started_lock = self.started.write().await;
            *started_lock = true;
            info!("Application startup complete - all checks passed");
        }

        response
    }

    pub async fn is_started(&self) -> bool {
        *self.started.read().await
    }
}

impl Default for StartupProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Health probe manager
pub struct HealthProbeManager {
    liveness: Arc<LivenessProbe>,
    readiness: Arc<ReadinessProbe>,
    startup: Arc<StartupProbe>,
    last_results: Arc<RwLock<Option<ProbeResponse>>>,
}

impl HealthProbeManager {
    pub fn new(liveness: LivenessProbe, readiness: ReadinessProbe, startup: StartupProbe) -> Self {
        Self {
            liveness: Arc::new(liveness),
            readiness: Arc::new(readiness),
            startup: Arc::new(startup),
            last_results: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn liveness(&self) -> ProbeResponse {
        self.liveness.probe().await
    }

    pub async fn readiness(&self) -> ProbeResponse {
        self.readiness.probe().await
    }

    pub async fn startup(&self) -> ProbeResponse {
        self.startup.probe().await
    }

    pub async fn health(&self) -> ProbeResponse {
        self.readiness().await
    }

    pub async fn last_health_check(&self) -> Option<ProbeResponse> {
        self.last_results.read().await.clone()
    }

    /// Start periodic health check background task
    pub async fn start_background_checks(self: Arc<Self>, interval_secs: u64) {
        info!(
            "Starting background health checks (interval: {}s)",
            interval_secs
        );

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));

            loop {
                ticker.tick().await;

                debug!("Running background health check");

                let result = self.readiness().await;

                // Store results
                {
                    let mut last_results = self.last_results.write().await;
                    *last_results = Some(result.clone());
                }

                // Log unhealthy statuses
                if result.status == HealthStatus::Unhealthy {
                    error!("Health check failed: {:?}", result);
                } else if result.status == HealthStatus::Degraded {
                    debug!("Health check degraded: {:?}", result);
                }
            }
        });
    }
}

/// HTTP handlers for health probes

pub async fn liveness_handler(
    axum::extract::State(manager): axum::extract::State<Arc<HealthProbeManager>>,
) -> impl IntoResponse {
    manager.liveness().await
}

pub async fn readiness_handler(
    axum::extract::State(manager): axum::extract::State<Arc<HealthProbeManager>>,
) -> impl IntoResponse {
    manager.readiness().await
}

pub async fn startup_handler(
    axum::extract::State(manager): axum::extract::State<Arc<HealthProbeManager>>,
) -> impl IntoResponse {
    manager.startup().await
}

pub async fn health_handler(
    axum::extract::State(manager): axum::extract::State<Arc<HealthProbeManager>>,
) -> impl IntoResponse {
    manager.health().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::checks::SystemHealthCheck;

    #[tokio::test]
    async fn test_liveness_probe() {
        let probe = LivenessProbe::new().add_check(Arc::new(SystemHealthCheck));

        let response = probe.probe().await;
        assert_eq!(response.status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_readiness_probe() {
        let probe = ReadinessProbe::new().add_check(Arc::new(SystemHealthCheck));

        let response = probe.probe().await;
        assert_eq!(response.status, HealthStatus::Healthy);
        assert!(!response.checks.is_empty());
    }

    #[tokio::test]
    async fn test_startup_probe() {
        let probe = StartupProbe::new().add_check(Arc::new(SystemHealthCheck));

        assert!(!probe.is_started().await);

        let response = probe.probe().await;
        assert_eq!(response.status, HealthStatus::Healthy);

        // Should be marked as started now
        assert!(probe.is_started().await);
    }

    #[tokio::test]
    async fn test_probe_response() {
        let checks = vec![
            HealthCheckResult::healthy("test1".to_string(), 10),
            HealthCheckResult::degraded("test2".to_string(), "warning".to_string(), 20),
        ];

        let response = ProbeResponse::new(checks);
        assert_eq!(response.status, HealthStatus::Degraded);
        assert_eq!(response.summary.total_checks, 2);
        assert_eq!(response.summary.healthy, 1);
        assert_eq!(response.summary.degraded, 1);
    }
}
