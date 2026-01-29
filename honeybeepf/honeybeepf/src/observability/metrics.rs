use anyhow::Result;
use axum::{routing::get, Router, response::IntoResponse};
use prometheus::{TextEncoder, Encoder};
use tracing::info;

pub async fn start_metrics_server(port: u16) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler));
    
    let addr = format!("0.0.0.0:{}", port);
    info!("Starting Prometheus metrics server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        buffer
    )
}