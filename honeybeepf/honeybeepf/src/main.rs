use anyhow::{Context, Result};
use aya::include_bytes_aligned;
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if opt.verbose { "info" } else { "warn" }),
    )
    .init();

    // Initialize Settings and Engine
    let settings = honeybeepf::settings::Settings::new().context("Failed to load settings")?;

    let engine = honeybeepf::HoneyBeeEngine::new(
        settings,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/honeybeepf")),
    )?;

    engine.run().await?;

    std::process::exit(0);
}
