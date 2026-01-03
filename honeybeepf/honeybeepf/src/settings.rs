use config::{Config, ConfigError, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct BuiltinProbes {
    pub block_io: Option<bool>,
    pub network_latency: Option<bool>,
    pub interval: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct Settings {
    pub otel_exporter_otlp_endpoint: Option<String>,
    pub otel_exporter_otlp_protocol: Option<String>,
    pub builtin_probes: BuiltinProbes,
    pub custom_probe_config: Option<String>,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let s = Config::builder()
            // Map flat environment variables to nested structure keys
            // Use __ as separator for nested keys (e.g. BUILTIN_PROBES__BLOCK_IO -> builtin_probes.block_io)
            .add_source(Environment::default().separator("__"))
            .build()?;

        s.try_deserialize()
    }

    pub fn to_common_config(&self) -> honeybeepf_common::CommonConfig {
        // Convert Option<bool> / Option<u32> to primitive POD types
        let probe_block_io = self.builtin_probes.block_io.unwrap_or(false);
        let probe_network_latency = self.builtin_probes.network_latency.unwrap_or(false);
        let probe_interval = self.builtin_probes.interval.unwrap_or(0);

        honeybeepf_common::CommonConfig {
            probe_block_io: if probe_block_io { 1 } else { 0 },
            probe_network_latency: if probe_network_latency { 1 } else { 0 },
            probe_interval: probe_interval as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_settings() {
        // Ensure .env is loaded
        dotenvy::dotenv().ok();
        
        // Manual override for testing deterministic values
        unsafe {
            std::env::set_var("BUILTIN_PROBES__BLOCK_IO", "true");
            std::env::set_var("BUILTIN_PROBES__INTERVAL", "42");
        }
        
        let settings = Settings::new().expect("Failed to load settings");

        println!("Settings: {:#?}", settings);

        assert_eq!(settings.builtin_probes.block_io, Some(true));
        assert_eq!(settings.builtin_probes.interval, Some(42));
    }
}
