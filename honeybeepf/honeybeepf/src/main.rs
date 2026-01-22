use anyhow::{Context, Result};
use aya::include_bytes_aligned;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::{self, EnvFilter};
use honeybeepf::observability::otlp::init_otlp;

#[derive(Debug, Parser)]
struct Opt {
    /// Enable verbose output (sets log level to INFO)
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Initialize the logging system. 
    // It prioritizes the RUST_LOG environment variable.
    // If RUST_LOG is not set, it defaults to 'info' when --verbose is used, 
    // otherwise it defaults to 'warn' to reduce noise.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(if opt.verbose { "info" } else { "warn" })),
        )
        .init();

    // Load agent settings from environment variables or a .env file.
    let settings = honeybeepf::settings::Settings::new().context("Failed to load settings")?;

    // Check if an OTLP endpoint is provided in the configuration.
    if let Some(endpoint) = &settings.otel_exporter_otlp_endpoint {
        let endpoint_c = endpoint.clone();
        
        // IMPORTANT: Spawn OTLP initialization in a background task.
        // This prevents the main thread from blocking (hanging in futex_wait)
        // if the remote collector is unreachable or slow to respond.
        tokio::spawn(async move {
            info!("Attempting to connect to OTLP collector: {}", endpoint_c);
            
            // init_otlp includes a connection timeout to ensure this task
            // eventually fails rather than waiting forever.
            if let Err(e) = init_otlp(&endpoint_c).await {
                // If the collector is unavailable, log a warning and fallback to local logging.
                warn!("Failed to connect to OTLP collector: {}. Continuing in local mode.", e);
            } else {
                info!("Successfully connected to OTLP collector.");
            }
        });
    }

    // Load the eBPF bytecode and initialize the HoneyBee engine.
    // include_bytes_aligned ensures the bytecode is correctly aligned in memory for Aya.
    let engine = honeybeepf::HoneyBeeEngine::new(
        settings,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/honeybeepf")),
    )?;

    // Start the main event loop and attach probes to the kernel.
    engine.run().await?;

    Ok(())
}
