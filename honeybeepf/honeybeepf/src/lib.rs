pub mod settings;

use anyhow::Result;
use crate::settings::Settings;


pub struct HoneyBeeEngine {
    pub settings: Settings,
}

impl HoneyBeeEngine {
    pub fn new(settings: Settings) -> Result<Self> {
        // TODO: Implement actual probe attachment logic based on settings.
        // Future enhancement: Iterate over `settings.builtin_probes` and attach the corresponding
        // eBPF programs (network_latency, block_io, etc.) here.
        // For now, checks are performed but no action is taken.

        // if let Some(enabled) = settings.builtin_probes.network_latency {
        //     if enabled {
        //         ...
        //     }
        // }

        // if let Some(enabled) = settings.builtin_probes.block_io {
        //     if enabled {
        //         ...
        //     }
        // }

        Ok(Self { settings })
    }
}
