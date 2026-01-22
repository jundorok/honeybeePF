pub mod otlp;
pub mod metrics;

use crate::settings::Settings;
use tracing::{info, warn};

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
    
    // Initialize Prometheus metrics server
    if let Some(metrics_config) = &settings.metrics {
        if metrics_config.enabled.unwrap_or(false) {
            let port = metrics_config.port.unwrap_or(9464);
            
            tokio::spawn(async move {
                if let Err(e) = metrics::start_metrics_server(port).await {
                    warn!("Failed to start metrics server: {}", e);
                }
            });
        }
    }
}