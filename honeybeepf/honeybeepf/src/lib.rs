pub mod settings;

use anyhow::Result;
use crate::settings::Settings;


pub struct HoneyBeeEngine {
    pub settings: Settings,
}

impl HoneyBeeEngine {
    pub fn new(settings: Settings) -> Result<Self> {
        // Attach probes based on settings
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
