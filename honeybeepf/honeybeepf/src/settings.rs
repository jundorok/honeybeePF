use config::{Config, ConfigError, Environment};
use serde::Deserialize;

const DEFAULT_PROBE_INTERVAL_SECONDS: u32 = 60;

/// Network probe configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[allow(unused)]
pub struct NetworkProbes {
    pub tcp_connect: Option<bool>,
    pub tcp_retrans: Option<bool>,
    pub dns: Option<bool>,
}

/// Filesystem probe configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[allow(unused)]
pub struct FilesystemProbes {
    pub vfs_latency: Option<bool>,
    pub vfs_latency_threshold_ms: Option<u32>,
    pub file_access: Option<bool>,
    pub watched_paths: Option<Vec<String>>,
}

/// Scheduler probe configuration
#[derive(Debug, Deserialize, Clone, Default)]
#[allow(unused)]
pub struct SchedulerProbes {
    pub runqueue: Option<bool>,
    pub runqueue_threshold_ms: Option<u32>,
    pub offcpu: Option<bool>,
    pub offcpu_threshold_ms: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct BuiltinProbes {
    #[serde(default)]
    pub network: NetworkProbes,
    #[serde(default)]
    pub filesystem: FilesystemProbes,
    #[serde(default)]
    pub scheduler: SchedulerProbes,
    pub llm: Option<bool>,
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
        dotenvy::dotenv().ok();

        let s = Config::builder()
            .add_source(Environment::default().separator("__"))
            .build()?;

        s.try_deserialize()
    }

    pub fn to_common_config(&self) -> honeybeepf_common::CommonConfig {
        // Network probes
        let probe_tcp_connect = self.builtin_probes.network.tcp_connect.unwrap_or(false);
        let probe_tcp_retrans = self.builtin_probes.network.tcp_retrans.unwrap_or(false);
        let probe_dns = self.builtin_probes.network.dns.unwrap_or(false);
        
        // Filesystem probes
        let probe_vfs_latency = self.builtin_probes.filesystem.vfs_latency.unwrap_or(false);
        let probe_file_access = self.builtin_probes.filesystem.file_access.unwrap_or(false);
        
        // Scheduler probes
        let probe_runqueue = self.builtin_probes.scheduler.runqueue.unwrap_or(false);
        let probe_offcpu = self.builtin_probes.scheduler.offcpu.unwrap_or(false);
        
        // LLM probe
        let probe_llm = self.builtin_probes.llm.unwrap_or(false);
        
        let probe_interval = self
            .builtin_probes
            .interval
            .unwrap_or(DEFAULT_PROBE_INTERVAL_SECONDS);

        honeybeepf_common::CommonConfig {
            // Network
            probe_tcp_connect: probe_tcp_connect as u8,
            probe_tcp_retrans: probe_tcp_retrans as u8,
            probe_dns: probe_dns as u8,
            // Filesystem
            probe_vfs_latency: probe_vfs_latency as u8,
            probe_file_access: probe_file_access as u8,
            // Scheduler
            probe_runqueue: probe_runqueue as u8,
            probe_offcpu: probe_offcpu as u8,
            // LLM
            probe_llm: probe_llm as u8,
            // Interval
            probe_interval,
            _pad: [0; 0],
        }
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use super::*;

    #[test]
    #[serial]
    fn test_load_settings() {
        dotenvy::dotenv().ok();

        unsafe {
            std::env::set_var("BUILTIN_PROBES__NETWORK__TCP_CONNECT", "true");
            std::env::set_var("BUILTIN_PROBES__FILESYSTEM__VFS_LATENCY", "true");
            std::env::set_var("BUILTIN_PROBES__INTERVAL", "42");
        }

        let settings = Settings::new().expect("Failed to load settings");

        assert_eq!(settings.builtin_probes.network.tcp_connect, Some(true));
        assert_eq!(settings.builtin_probes.filesystem.vfs_latency, Some(true));
        assert_eq!(settings.builtin_probes.interval, Some(42));
    }

    #[test]
    fn test_to_common_config() {
        let settings = Settings {
            otel_exporter_otlp_endpoint: None,
            otel_exporter_otlp_protocol: None,
            builtin_probes: BuiltinProbes {
                network: NetworkProbes {
                    tcp_connect: Some(true),
                    tcp_retrans: None,
                    dns: Some(true),
                },
                filesystem: FilesystemProbes {
                    vfs_latency: Some(true),
                    vfs_latency_threshold_ms: Some(10),
                    file_access: None,
                    watched_paths: None,
                },
                scheduler: SchedulerProbes {
                    runqueue: None,
                    runqueue_threshold_ms: None,
                    offcpu: Some(true),
                    offcpu_threshold_ms: Some(5),
                },
                llm: None,
                interval: None,
            },
            custom_probe_config: None,
        };

        let common = settings.to_common_config();

        assert_eq!(common.probe_tcp_connect, 1);
        assert_eq!(common.probe_tcp_retrans, 0);
        assert_eq!(common.probe_dns, 1);
        assert_eq!(common.probe_vfs_latency, 1);
        assert_eq!(common.probe_file_access, 0);
        assert_eq!(common.probe_runqueue, 0);
        assert_eq!(common.probe_offcpu, 1);
        assert_eq!(common.probe_interval, DEFAULT_PROBE_INTERVAL_SECONDS);
    }
}
