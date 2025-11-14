#![allow(dead_code)]

use opentelemetry::{
    metrics::{Counter, Histogram, Meter, UpDownCounter},
    KeyValue,
};
use std::time::{Duration, Instant};

/// Token-related metrics collector
#[allow(dead_code)]
pub struct TokenMetrics {
    _meter: Meter,
    tokens_issued: Counter<u64>,
    tokens_revoked: Counter<u64>,
    token_generation_duration: Histogram<f64>,
    active_tokens: UpDownCounter<i64>,
}

impl TokenMetrics {
    pub fn new(meter: Meter) -> Self {
        let tokens_issued = meter
            .u64_counter("tokens.issued")
            .with_description("Total number of tokens issued")
            .init();

        let tokens_revoked = meter
            .u64_counter("tokens.revoked")
            .with_description("Total number of tokens revoked")
            .init();

        let token_generation_duration = meter
            .f64_histogram("tokens.generation.duration")
            .with_description("Token generation duration in seconds")
            .with_unit("s")
            .init();

        let active_tokens = meter
            .i64_up_down_counter("tokens.active")
            .with_description("Number of currently active tokens")
            .init();

        Self {
            _meter: meter,
            tokens_issued,
            tokens_revoked,
            token_generation_duration,
            active_tokens,
        }
    }

    pub fn record_token_issued(&self, tenant_id: &str, token_type: &str) {
        self.tokens_issued.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("token_type", token_type.to_string()),
            ],
        );
        self.active_tokens.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("token_type", token_type.to_string()),
            ],
        );
    }

    pub fn record_token_revoked(&self, tenant_id: &str, token_type: &str) {
        self.tokens_revoked.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("token_type", token_type.to_string()),
            ],
        );
        self.active_tokens.add(
            -1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("token_type", token_type.to_string()),
            ],
        );
    }

    #[allow(dead_code)]
    pub fn record_generation_duration(&self, tenant_id: &str, duration: Duration) {
        self.token_generation_duration.record(
            duration.as_secs_f64(),
            &[KeyValue::new("tenant_id", tenant_id.to_string())],
        );
    }

    #[allow(dead_code)]
    pub fn start_timer(&self) -> MetricsTimer {
        MetricsTimer::new()
    }
}

/// Authentication metrics collector
pub struct AuthMetrics {
    _meter: Meter,
    auth_attempts: Counter<u64>,
    auth_successes: Counter<u64>,
    auth_failures: Counter<u64>,
    auth_duration: Histogram<f64>,
}

impl AuthMetrics {
    pub fn new(meter: Meter) -> Self {
        let auth_attempts = meter
            .u64_counter("auth.attempts")
            .with_description("Total authentication attempts")
            .init();

        let auth_successes = meter
            .u64_counter("auth.successes")
            .with_description("Successful authentications")
            .init();

        let auth_failures = meter
            .u64_counter("auth.failures")
            .with_description("Failed authentications")
            .init();

        let auth_duration = meter
            .f64_histogram("auth.duration")
            .with_description("Authentication duration in seconds")
            .with_unit("s")
            .init();

        Self {
            _meter: meter,
            auth_attempts,
            auth_successes,
            auth_failures,
            auth_duration,
        }
    }

    pub fn record_attempt(&self, tenant_id: &str, backend_type: &str) {
        self.auth_attempts.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("backend_type", backend_type.to_string()),
            ],
        );
    }

    pub fn record_success(&self, tenant_id: &str, backend_type: &str, duration: Duration) {
        self.auth_successes.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("backend_type", backend_type.to_string()),
            ],
        );
        self.auth_duration.record(
            duration.as_secs_f64(),
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("backend_type", backend_type.to_string()),
                KeyValue::new("result", "success"),
            ],
        );
    }

    pub fn record_failure(&self, tenant_id: &str, backend_type: &str, reason: &str) {
        self.auth_failures.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("backend_type", backend_type.to_string()),
                KeyValue::new("reason", reason.to_string()),
            ],
        );
    }
}

/// Error metrics collector
pub struct ErrorMetrics {
    _meter: Meter,
    errors_total: Counter<u64>,
    rate_limit_hits: Counter<u64>,
}

impl ErrorMetrics {
    pub fn new(meter: Meter) -> Self {
        let errors_total = meter
            .u64_counter("errors.total")
            .with_description("Total errors encountered")
            .init();

        let rate_limit_hits = meter
            .u64_counter("rate_limit.hits")
            .with_description("Total rate limit hits")
            .init();

        Self {
            _meter: meter,
            errors_total,
            rate_limit_hits,
        }
    }

    pub fn record_error(&self, tenant_id: &str, error_type: &str, endpoint: &str) {
        self.errors_total.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("error_type", error_type.to_string()),
                KeyValue::new("endpoint", endpoint.to_string()),
            ],
        );
    }

    pub fn record_rate_limit_hit(&self, tenant_id: &str, endpoint: &str) {
        self.rate_limit_hits.add(
            1,
            &[
                KeyValue::new("tenant_id", tenant_id.to_string()),
                KeyValue::new("endpoint", endpoint.to_string()),
            ],
        );
    }
}

/// Latency metrics collector
pub struct LatencyMetrics {
    _meter: Meter,
    http_request_duration: Histogram<f64>,
    db_query_duration: Histogram<f64>,
    ldap_query_duration: Histogram<f64>,
    external_call_duration: Histogram<f64>,
}

impl LatencyMetrics {
    pub fn new(meter: Meter) -> Self {
        let http_request_duration = meter
            .f64_histogram("http.request.duration")
            .with_description("HTTP request duration in seconds")
            .with_unit("s")
            .init();

        let db_query_duration = meter
            .f64_histogram("db.query.duration")
            .with_description("Database query duration in seconds")
            .with_unit("s")
            .init();

        let ldap_query_duration = meter
            .f64_histogram("ldap.query.duration")
            .with_description("LDAP query duration in seconds")
            .with_unit("s")
            .init();

        let external_call_duration = meter
            .f64_histogram("external.call.duration")
            .with_description("External API call duration in seconds")
            .with_unit("s")
            .init();

        Self {
            _meter: meter,
            http_request_duration,
            db_query_duration,
            ldap_query_duration,
            external_call_duration,
        }
    }

    pub fn record_http_request(
        &self,
        method: &str,
        endpoint: &str,
        status: u16,
        duration: Duration,
    ) {
        self.http_request_duration.record(
            duration.as_secs_f64(),
            &[
                KeyValue::new("method", method.to_string()),
                KeyValue::new("endpoint", endpoint.to_string()),
                KeyValue::new("status", status.to_string()),
            ],
        );
    }

    pub fn record_db_query(&self, operation: &str, duration: Duration) {
        self.db_query_duration.record(
            duration.as_secs_f64(),
            &[KeyValue::new("operation", operation.to_string())],
        );
    }

    pub fn record_ldap_query(&self, operation: &str, duration: Duration) {
        self.ldap_query_duration.record(
            duration.as_secs_f64(),
            &[KeyValue::new("operation", operation.to_string())],
        );
    }

    pub fn record_external_call(&self, service: &str, duration: Duration) {
        self.external_call_duration.record(
            duration.as_secs_f64(),
            &[KeyValue::new("service", service.to_string())],
        );
    }
}

/// Timer for measuring operation duration
pub struct MetricsTimer {
    start: Instant,
}

impl MetricsTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    #[allow(dead_code)]
    pub fn stop(self) -> Duration {
        self.elapsed()
    }
}

impl Default for MetricsTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Centralized metrics collector
pub struct MetricsCollector {
    pub tokens: TokenMetrics,
    pub auth: AuthMetrics,
    pub errors: ErrorMetrics,
    pub latency: LatencyMetrics,
}

impl MetricsCollector {
    pub fn new(meter: Meter) -> Self {
        Self {
            tokens: TokenMetrics::new(meter.clone()),
            auth: AuthMetrics::new(meter.clone()),
            errors: ErrorMetrics::new(meter.clone()),
            latency: LatencyMetrics::new(meter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::opentelemetry::get_meter;

    #[test]
    fn test_metrics_timer() {
        let timer = MetricsTimer::new();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn test_token_metrics() {
        let meter = get_meter("test");
        let metrics = TokenMetrics::new(meter);
        metrics.record_token_issued("tenant1", "access_token");
        metrics.record_token_revoked("tenant1", "access_token");
    }
}
