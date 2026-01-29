use anyhow::{Context, Result};
use tracing::info;

/// Initializes the OpenTelemetry tracing pipeline with a gRPC exporter.
/// 
/// This function sets up OTLP (OpenTelemetry Protocol) exporter to send
/// traces to a remote collector (e.g., Jaeger, Tempo, or OTEL Collector).
/// 
/// # Arguments
/// * `endpoint` - The OTLP collector endpoint (e.g., "http://collector:4317")
/// 
/// # Returns
/// * `Result<()>` - Ok if initialization succeeds, Err otherwise
/// 
/// # Example
/// ```no_run
/// use honeybeepf::observability::otlp::init_otlp;
/// 
/// tokio::spawn(async {
///     if let Err(e) = init_otlp("http://localhost:4317").await {
///         eprintln!("Failed to init OTLP: {}", e);
///     }
/// });
/// ```
pub async fn init_otlp(endpoint: &str) -> Result<()> {
    use opentelemetry_otlp::WithExportConfig;
    use std::time::Duration;

    info!("Initializing OTLP exporter to endpoint: {}", endpoint);

    // Configure the OTLP exporter with a connection timeout
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(3));

    // Install the tracing pipeline into the global tracing registry
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .context("Failed to install OTLP pipeline")?;

    info!("OTLP exporter initialized successfully");
    Ok(())
}