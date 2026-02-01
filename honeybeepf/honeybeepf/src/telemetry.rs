//! OpenTelemetry metrics export module
//!
//! Exports eBPF metrics collected by honeybeepf to OpenTelemetry Collector.
//! 
//! ## OTLP Endpoint Priority
//! 1. Helm values (injected via environment variables)
//! 2. Direct environment variable configuration
//! 3. Code default value (FQDN)

use anyhow::{Context, Result};
use log::info;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

/// Default OTLP endpoint (FQDN format)
/// Can be overridden via Helm values
const DEFAULT_OTLP_ENDPOINT: &str = "http://honeybeepf-otel-collector-opentelemetry-collector.monitoring.svc.cluster.local:4317";

/// Metric export interval in seconds
const METRIC_EXPORT_INTERVAL_SECS: u64 = 30;

/// Global metrics handle
static METRICS: OnceLock<HoneyBeeMetrics> = OnceLock::new();

/// Global active probes count (for ObservableGauge callback)
static ACTIVE_PROBES: OnceLock<RwLock<HashMap<String, u64>>> = OnceLock::new();

/// Get or initialize the active probes map
fn active_probes_map() -> &'static RwLock<HashMap<String, u64>> {
    ACTIVE_PROBES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// honeybeepf metrics collection
/// 
/// Note: Do NOT add _total suffix to Counter names (Prometheus adds it automatically)
pub struct HoneyBeeMetrics {
    /// Block I/O event counter
    pub block_io_events: Counter<u64>,
    /// Block I/O bytes counter
    pub block_io_bytes: Counter<u64>,
    /// Block I/O latency histogram (nanoseconds)
    pub block_io_latency_ns: Histogram<u64>,
    /// Network latency histogram (nanoseconds)
    pub network_latency_ns: Histogram<u64>,
    /// GPU open event counter
    pub gpu_open_events: Counter<u64>,
    // Note: active_probes is registered as ObservableGauge in init_metrics()
}

impl HoneyBeeMetrics {
    /// Create new metrics instance from Meter
    fn new(meter: &Meter) -> Self {
        // Note: Do NOT add _total suffix to Counter names!
        // Prometheus automatically adds _total suffix
        Self {
            block_io_events: meter
                .u64_counter("hbpf_block_io_events")
                .with_description("Number of block I/O events")
                .with_unit("events")
                .build(),
            block_io_bytes: meter
                .u64_counter("hbpf_block_io_bytes")
                .with_description("Total bytes of block I/O operations")
                .with_unit("bytes")
                .build(),
            block_io_latency_ns: meter
                .u64_histogram("hbpf_block_io_latency_ns")
                .with_description("Block I/O operation latency in nanoseconds")
                .with_unit("ns")
                .build(),
            network_latency_ns: meter
                .u64_histogram("hbpf_network_latency_ns")
                .with_description("Network operation latency in nanoseconds")
                .with_unit("ns")
                .build(),
            gpu_open_events: meter
                .u64_counter("hbpf_gpu_open_events")
                .with_description("Number of GPU device open events")
                .with_unit("events")
                .build(),
        }
    }
}

/// Determine OTLP endpoint
/// 
/// Priority:
/// 1. OTEL_EXPORTER_OTLP_ENDPOINT environment variable (injected from Helm values)
/// 2. Code default value (FQDN)
fn get_otlp_endpoint() -> String {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_OTLP_ENDPOINT.to_string());
    
    // Add http:// or https:// prefix if missing
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        format!("http://{}", endpoint)
    } else {
        endpoint
    }
}

/// Initialize OpenTelemetry metrics provider
/// 
/// Configures metrics export to OTLP Collector via gRPC
pub fn init_metrics() -> Result<()> {
    let endpoint = get_otlp_endpoint();
    
    // Log endpoint at runtime for troubleshooting
    info!("Initializing OpenTelemetry metrics exporter");
    info!("OTLP endpoint: {}", endpoint);
    
    // Configure OTLP gRPC exporter
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .with_timeout(Duration::from_secs(10))
        .build()
        .context("Failed to create OTLP metric exporter")?;

    // Configure periodic export with PeriodicReader
    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_interval(Duration::from_secs(METRIC_EXPORT_INTERVAL_SECS))
        .build();

    // Configure resource (service name and other metadata)
    let resource = Resource::new(vec![
        KeyValue::new("service.name", "honeybeepf"),
        KeyValue::new("service.namespace", "monitoring"),
        KeyValue::new("telemetry.sdk.language", "rust"),
    ]);

    // Create and register MeterProvider
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    global::set_meter_provider(provider);

    // Meter name is used as prefix only
    let meter = global::meter("honeybeepf");
    
    // Register ObservableGauge for active probes (async gauge with callback)
    // This is the correct way to export gauge metrics via OTLP
    let _active_probes_gauge = meter
        .u64_observable_gauge("hbpf_active_probes")
        .with_description("Number of currently active eBPF probes")
        .with_unit("probes")
        .with_callback(|observer| {
            // Read current active probes from global map
            if let Ok(probes) = active_probes_map().read() {
                for (probe_name, count) in probes.iter() {
                    observer.observe(
                        *count,
                        &[KeyValue::new("probe", probe_name.clone())],
                    );
                }
            }
        })
        .build();

    // Initialize global metrics handle
    let _ = METRICS.set(HoneyBeeMetrics::new(&meter));

    info!("OpenTelemetry metrics initialized successfully");
    Ok(())
}

/// Get global metrics handle
pub fn metrics() -> Option<&'static HoneyBeeMetrics> {
    METRICS.get()
}

/// Record Block I/O event
pub fn record_block_io_event(
    event_type: &str,
    bytes: u64,
    latency_ns: Option<u64>,
    device: &str,
) {
    if let Some(m) = metrics() {
        let attrs = [
            KeyValue::new("event_type", event_type.to_string()),
            KeyValue::new("device", device.to_string()),
        ];
        
        m.block_io_events.add(1, &attrs);
        m.block_io_bytes.add(bytes, &attrs);
        
        if let Some(lat) = latency_ns {
            m.block_io_latency_ns.record(lat, &attrs);
        }
    }
}

/// Record network latency
pub fn record_network_latency(latency_ns: u64, protocol: &str) {
    if let Some(m) = metrics() {
        let attrs = [KeyValue::new("protocol", protocol.to_string())];
        m.network_latency_ns.record(latency_ns, &attrs);
    }
}

/// Record GPU open event
pub fn record_gpu_open_event(device_path: &str) {
    if let Some(m) = metrics() {
        let attrs = [KeyValue::new("device", device_path.to_string())];
        m.gpu_open_events.add(1, &attrs);
    }
}

/// Record active probe count
/// Updates the global active probes map for ObservableGauge callback
pub fn record_active_probe(probe_name: &str, count: u64) {
    // Update the global map (ObservableGauge callback reads from this)
    if let Ok(mut probes) = active_probes_map().write() {
        probes.insert(probe_name.to_string(), count);
        info!("Active probe registered: {} = {}", probe_name, count);
    }
}

/// Shutdown OpenTelemetry (graceful shutdown)
/// Note: OpenTelemetry SDK 0.27 does not expose shutdown_meter_provider
/// The MeterProvider will be dropped when the process exits
pub fn shutdown_metrics() {
    info!("Shutting down OpenTelemetry metrics...");
    // Graceful shutdown happens automatically when MeterProvider is dropped
    // For explicit flush, we could store the provider globally and call shutdown()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_get_otlp_endpoint_default() {
        // Use default value if environment variable is not set
        unsafe { std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"); }
        let endpoint = get_otlp_endpoint();
        assert!(endpoint.starts_with("http://"));
        assert!(endpoint.contains("honeybeepf-otel-collector"));
    }

    #[test]
    #[serial]
    fn test_get_otlp_endpoint_from_env() {
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://custom:4317");
        }
        let endpoint = get_otlp_endpoint();
        assert_eq!(endpoint, "http://custom:4317");
        unsafe { std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"); }
    }

    #[test]
    #[serial]
    fn test_get_otlp_endpoint_adds_http_prefix() {
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317");
        }
        let endpoint = get_otlp_endpoint();
        assert_eq!(endpoint, "http://collector:4317");
        unsafe { std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT"); }
    }
}
