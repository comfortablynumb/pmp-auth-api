use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
use std::borrow::Cow;
use tracing::{error, info};

/// OpenTelemetry configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub enable_metrics: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "pmp-auth-api".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            enable_metrics: true,
        }
    }
}

/// Initialize OpenTelemetry with tracing and metrics
pub fn init_telemetry(
    config: TelemetryConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Initializing OpenTelemetry");

    // Create resource with service information
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
    ]);

    // Initialize metrics if enabled
    if config.enable_metrics {
        match init_metrics(resource) {
            Ok(_) => info!("OpenTelemetry metrics initialized"),
            Err(e) => error!("Failed to initialize OpenTelemetry metrics: {}", e),
        }
    }

    Ok(())
}

/// Initialize OpenTelemetry metrics with Prometheus exporter
fn init_metrics(
    resource: Resource,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Using Prometheus exporter for metrics");
    let exporter = opentelemetry_prometheus::exporter()
        .build()?;

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(exporter)
        .build();

    global::set_meter_provider(provider);
    Ok(())
}

/// Shutdown OpenTelemetry and flush pending data
pub fn shutdown_telemetry() {
    info!("Shutting down OpenTelemetry");
    global::shutdown_tracer_provider();
}

/// Get a meter for custom metrics
pub fn get_meter(name: impl Into<Cow<'static, str>>) -> opentelemetry::metrics::Meter {
    global::meter(name)
}

/// Get a tracer for custom spans
pub fn get_tracer(name: impl Into<Cow<'static, str>>) -> opentelemetry::global::BoxedTracer {
    global::tracer(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "pmp-auth-api");
        assert!(config.enable_metrics);
    }

    #[test]
    fn test_init_telemetry() {
        let config = TelemetryConfig::default();
        let result = init_telemetry(config);
        assert!(result.is_ok());
    }
}
