pub mod settings;
pub mod telemetry;

use anyhow::Result;
use aya::Ebpf;  // Bpf → Ebpf
use aya_log::EbpfLogger;  // BpfLogger → EbpfLogger
use log::{info, warn};
use tokio::signal;

use crate::settings::Settings;

pub mod probes;
use crate::probes::builtin::network::NetworkLatencyProbe;
use crate::probes::builtin::block_io::BlockIoProbe;
use crate::probes::builtin::gpu_open::GpuOpenProbe;
use crate::probes::Probe;

pub struct HoneyBeeEngine {
    pub settings: Settings,
    bpf: Ebpf,
}

impl HoneyBeeEngine {
    pub fn new(settings: Settings, bytecode: &[u8]) -> Result<Self> {
        bump_memlock_rlimit()?;
        let mut bpf = Ebpf::load(bytecode)?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("Failed to initialize eBPF logger: {}", e);
        }
        Ok(Self { settings, bpf })
    }

    pub async fn run(mut self) -> Result<()> {
        // Init OpenTelemetry Metric
        if let Err(e) = telemetry::init_metrics() {
            warn!("Failed to initialize OpenTelemetry metrics: {}. Metrics will not be exported.", e);
        }

        self.attach_probes()?;

        info!("Monitoring active. Press Ctrl-C to exit.");
        signal::ctrl_c().await?;
        info!("Exiting...");

        // Graceful shutdown
        telemetry::shutdown_metrics();

        Ok(())
    }

    fn attach_probes(&mut self) -> Result<()> {
        if self.settings.builtin_probes.network_latency.unwrap_or(false) {
            NetworkLatencyProbe.attach(&mut self.bpf)?;
            telemetry::record_active_probe("network_latency", 1); // gauge
        }

        if self.settings.builtin_probes.block_io.unwrap_or(false) {
            BlockIoProbe.attach(&mut self.bpf)?;
            telemetry::record_active_probe("block_io", 1); // gauge
        }

        if self.settings.builtin_probes.gpu_open.unwrap_or(false) {
            GpuOpenProbe.attach(&mut self.bpf)?;
            telemetry::record_active_probe("gpu_open", 1); // gauge
        }

        Ok(())
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit");
    }
    Ok(())
}
