use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use lazy_static::lazy_static;
use prometheus::{
    Counter, CounterVec, Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

lazy_static! {
    /// Global metrics registry
    pub static ref METRICS_REGISTRY: Arc<MetricsRegistry> = Arc::new(MetricsRegistry::new());
}

pub struct MetricsRegistry {
    pub registry: Registry,

    // Token issuance metrics
    pub tokens_issued_total: IntCounterVec,
    pub tokens_revoked_total: IntCounterVec,
    pub refresh_tokens_issued_total: IntCounterVec,
    pub api_keys_created_total: IntCounterVec,

    // Authentication metrics
    pub auth_attempts_total: IntCounterVec,
    pub auth_success_total: IntCounterVec,
    pub auth_failures_total: IntCounterVec,
    pub mfa_attempts_total: IntCounterVec,

    // Error metrics
    pub errors_total: IntCounterVec,
    pub rate_limit_hits_total: IntCounterVec,

    // Latency metrics
    pub request_duration_seconds: HistogramVec,
    pub token_generation_duration_seconds: Histogram,
    pub ldap_query_duration_seconds: Histogram,
    pub db_query_duration_seconds: Histogram,

    // Active sessions
    pub active_sessions: IntGaugeVec,
    pub active_connections: IntGauge,

    // OAuth2 specific metrics
    pub oauth_authorize_requests: IntCounterVec,
    pub oauth_token_requests: IntCounterVec,
    pub device_flow_requests: IntCounterVec,

    // SAML specific metrics
    pub saml_sso_requests: IntCounterVec,
    pub saml_assertions_issued: IntCounterVec,

    // Resource usage
    pub ldap_connections_pool: IntGauge,
    pub db_connections_pool: IntGauge,
    pub redis_connections_pool: IntGauge,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let registry = Registry::new();

        // Token issuance metrics
        let tokens_issued_total = IntCounterVec::new(
            Opts::new("tokens_issued_total", "Total number of tokens issued"),
            &["tenant_id", "token_type"],
        )
        .unwrap();

        let tokens_revoked_total = IntCounterVec::new(
            Opts::new("tokens_revoked_total", "Total number of tokens revoked"),
            &["tenant_id", "token_type"],
        )
        .unwrap();

        let refresh_tokens_issued_total = IntCounterVec::new(
            Opts::new(
                "refresh_tokens_issued_total",
                "Total number of refresh tokens issued",
            ),
            &["tenant_id"],
        )
        .unwrap();

        let api_keys_created_total = IntCounterVec::new(
            Opts::new("api_keys_created_total", "Total number of API keys created"),
            &["tenant_id"],
        )
        .unwrap();

        // Authentication metrics
        let auth_attempts_total = IntCounterVec::new(
            Opts::new(
                "auth_attempts_total",
                "Total number of authentication attempts",
            ),
            &["tenant_id", "backend_type"],
        )
        .unwrap();

        let auth_success_total = IntCounterVec::new(
            Opts::new(
                "auth_success_total",
                "Total number of successful authentications",
            ),
            &["tenant_id", "backend_type"],
        )
        .unwrap();

        let auth_failures_total = IntCounterVec::new(
            Opts::new(
                "auth_failures_total",
                "Total number of failed authentications",
            ),
            &["tenant_id", "backend_type", "reason"],
        )
        .unwrap();

        let mfa_attempts_total = IntCounterVec::new(
            Opts::new("mfa_attempts_total", "Total number of MFA attempts"),
            &["tenant_id", "mfa_type", "result"],
        )
        .unwrap();

        // Error metrics
        let errors_total = IntCounterVec::new(
            Opts::new("errors_total", "Total number of errors"),
            &["tenant_id", "error_type", "endpoint"],
        )
        .unwrap();

        let rate_limit_hits_total = IntCounterVec::new(
            Opts::new("rate_limit_hits_total", "Total number of rate limit hits"),
            &["tenant_id", "endpoint"],
        )
        .unwrap();

        // Latency metrics
        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new("request_duration_seconds", "Request duration in seconds").buckets(
                vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ],
            ),
            &["tenant_id", "method", "endpoint", "status"],
        )
        .unwrap();

        let token_generation_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "token_generation_duration_seconds",
                "Token generation duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1]),
        )
        .unwrap();

        let ldap_query_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "ldap_query_duration_seconds",
                "LDAP query duration in seconds",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        )
        .unwrap();

        let db_query_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "db_query_duration_seconds",
                "Database query duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )
        .unwrap();

        // Active sessions
        let active_sessions = IntGaugeVec::new(
            Opts::new("active_sessions", "Number of active sessions"),
            &["tenant_id"],
        )
        .unwrap();

        let active_connections =
            IntGauge::new("active_connections", "Number of active connections").unwrap();

        // OAuth2 specific metrics
        let oauth_authorize_requests = IntCounterVec::new(
            Opts::new(
                "oauth_authorize_requests_total",
                "Total OAuth2 authorize requests",
            ),
            &["tenant_id", "response_type"],
        )
        .unwrap();

        let oauth_token_requests = IntCounterVec::new(
            Opts::new("oauth_token_requests_total", "Total OAuth2 token requests"),
            &["tenant_id", "grant_type"],
        )
        .unwrap();

        let device_flow_requests = IntCounterVec::new(
            Opts::new("device_flow_requests_total", "Total device flow requests"),
            &["tenant_id", "flow_type"],
        )
        .unwrap();

        // SAML specific metrics
        let saml_sso_requests = IntCounterVec::new(
            Opts::new("saml_sso_requests_total", "Total SAML SSO requests"),
            &["tenant_id", "binding"],
        )
        .unwrap();

        let saml_assertions_issued = IntCounterVec::new(
            Opts::new(
                "saml_assertions_issued_total",
                "Total SAML assertions issued",
            ),
            &["tenant_id"],
        )
        .unwrap();

        // Resource usage
        let ldap_connections_pool =
            IntGauge::new("ldap_connections_pool", "LDAP connection pool size").unwrap();

        let db_connections_pool =
            IntGauge::new("db_connections_pool", "Database connection pool size").unwrap();

        let redis_connections_pool =
            IntGauge::new("redis_connections_pool", "Redis connection pool size").unwrap();

        // Register all metrics
        registry
            .register(Box::new(tokens_issued_total.clone()))
            .unwrap();
        registry
            .register(Box::new(tokens_revoked_total.clone()))
            .unwrap();
        registry
            .register(Box::new(refresh_tokens_issued_total.clone()))
            .unwrap();
        registry
            .register(Box::new(api_keys_created_total.clone()))
            .unwrap();
        registry
            .register(Box::new(auth_attempts_total.clone()))
            .unwrap();
        registry
            .register(Box::new(auth_success_total.clone()))
            .unwrap();
        registry
            .register(Box::new(auth_failures_total.clone()))
            .unwrap();
        registry
            .register(Box::new(mfa_attempts_total.clone()))
            .unwrap();
        registry.register(Box::new(errors_total.clone())).unwrap();
        registry
            .register(Box::new(rate_limit_hits_total.clone()))
            .unwrap();
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(token_generation_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(ldap_query_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(db_query_duration_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(active_sessions.clone()))
            .unwrap();
        registry
            .register(Box::new(active_connections.clone()))
            .unwrap();
        registry
            .register(Box::new(oauth_authorize_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(oauth_token_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(device_flow_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(saml_sso_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(saml_assertions_issued.clone()))
            .unwrap();
        registry
            .register(Box::new(ldap_connections_pool.clone()))
            .unwrap();
        registry
            .register(Box::new(db_connections_pool.clone()))
            .unwrap();
        registry
            .register(Box::new(redis_connections_pool.clone()))
            .unwrap();

        Self {
            registry,
            tokens_issued_total,
            tokens_revoked_total,
            refresh_tokens_issued_total,
            api_keys_created_total,
            auth_attempts_total,
            auth_success_total,
            auth_failures_total,
            mfa_attempts_total,
            errors_total,
            rate_limit_hits_total,
            request_duration_seconds,
            token_generation_duration_seconds,
            ldap_query_duration_seconds,
            db_query_duration_seconds,
            active_sessions,
            active_connections,
            oauth_authorize_requests,
            oauth_token_requests,
            device_flow_requests,
            saml_sso_requests,
            saml_assertions_issued,
            ldap_connections_pool,
            db_connections_pool,
            redis_connections_pool,
        }
    }

    /// Render metrics in Prometheus text format
    pub fn render(&self) -> Result<String, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience functions for common metrics operations

pub fn record_token_issued(tenant_id: &str, token_type: &str) {
    METRICS_REGISTRY
        .tokens_issued_total
        .with_label_values(&[tenant_id, token_type])
        .inc();
}

pub fn record_token_revoked(tenant_id: &str, token_type: &str) {
    METRICS_REGISTRY
        .tokens_revoked_total
        .with_label_values(&[tenant_id, token_type])
        .inc();
}

pub fn record_auth_attempt(tenant_id: &str, backend_type: &str, success: bool) {
    METRICS_REGISTRY
        .auth_attempts_total
        .with_label_values(&[tenant_id, backend_type])
        .inc();

    if success {
        METRICS_REGISTRY
            .auth_success_total
            .with_label_values(&[tenant_id, backend_type])
            .inc();
    }
}

pub fn record_auth_failure(tenant_id: &str, backend_type: &str, reason: &str) {
    METRICS_REGISTRY
        .auth_failures_total
        .with_label_values(&[tenant_id, backend_type, reason])
        .inc();
}

pub fn record_error(tenant_id: &str, error_type: &str, endpoint: &str) {
    METRICS_REGISTRY
        .errors_total
        .with_label_values(&[tenant_id, error_type, endpoint])
        .inc();
}

pub fn record_request_duration(
    tenant_id: &str,
    method: &str,
    endpoint: &str,
    status: u16,
    duration_secs: f64,
) {
    METRICS_REGISTRY
        .request_duration_seconds
        .with_label_values(&[tenant_id, method, endpoint, &status.to_string()])
        .observe(duration_secs);
}

pub fn record_oauth_request(tenant_id: &str, grant_type: &str) {
    METRICS_REGISTRY
        .oauth_token_requests
        .with_label_values(&[tenant_id, grant_type])
        .inc();
}

pub fn record_active_sessions(tenant_id: &str, count: i64) {
    METRICS_REGISTRY
        .active_sessions
        .with_label_values(&[tenant_id])
        .set(count);
}

/// Metrics handler for Prometheus
pub async fn metrics_handler() -> impl IntoResponse {
    match METRICS_REGISTRY.render() {
        Ok(metrics) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Body::from(metrics))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("Failed to render metrics: {}", e)))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_creation() {
        let registry = MetricsRegistry::new();
        assert!(registry.render().is_ok());
    }

    #[test]
    fn test_record_token_issued() {
        record_token_issued("tenant1", "access_token");
        record_token_issued("tenant1", "access_token");

        let metrics = METRICS_REGISTRY.render().unwrap();
        assert!(metrics.contains("tokens_issued_total"));
    }

    #[test]
    fn test_record_auth_attempt() {
        record_auth_attempt("tenant1", "ldap", true);
        record_auth_attempt("tenant1", "ldap", false);

        let metrics = METRICS_REGISTRY.render().unwrap();
        assert!(metrics.contains("auth_attempts_total"));
    }
}
