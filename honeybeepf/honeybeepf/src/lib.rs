pub mod settings;
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
        self.attach_probes()?;

        info!("Monitoring active. Press Ctrl-C to exit.");
        signal::ctrl_c().await?;
        info!("Exiting...");

        Ok(())
    }

    fn attach_probes(&mut self) -> Result<()> {
        if self.settings.builtin_probes.network_latency.unwrap_or(false) {
            NetworkLatencyProbe.attach(&mut self.bpf)?;
        }

        if self.settings.builtin_probes.block_io.unwrap_or(false) {
            BlockIoProbe.attach(&mut self.bpf)?;
        }

        if self.settings.builtin_probes.gpu_open.unwrap_or(false) {
            GpuOpenProbe.attach(&mut self.bpf)?;
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
