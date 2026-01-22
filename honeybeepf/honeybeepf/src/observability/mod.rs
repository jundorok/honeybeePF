pub mod otlp;
// pub mod metrics;

use crate::settings::Settings;
use tracing::{info, warn};

/// Initialize all observability components based on settings
pub async fn init(settings: &Settings) {
    // Initialize OTLP if configured
    if let Some(endpoint) = &settings.otel_exporter_otlp_endpoint {
        let endpoint_c = endpoint.clone();
        
        tokio::spawn(async move {
            info!("Attempting to connect to OTLP collector: {}", endpoint_c);
            
            if let Err(e) = otlp::init_otlp(&endpoint_c).await {
                warn!("Failed to connect to OTLP collector: {}. Continuing in local mode.", e);
            } else {
                info!("Successfully connected to OTLP collector.");
            }
        });
    }
    
    // TODO: Initialize Prometheus metrics server
    // if settings.metrics.enabled {
    //     metrics::start_server(settings.metrics.port).await;
    // }
}