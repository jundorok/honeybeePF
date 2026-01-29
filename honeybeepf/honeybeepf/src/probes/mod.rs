use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{info, warn};
use std::path::Path;
use std::time::Duration;

pub mod builtin;
pub mod custom;

pub trait Probe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()>;
}

pub struct TracepointConfig<'a> {
    pub program_name: &'a str,
    pub category: &'a str,
    pub name: &'a str,
}

pub const POLL_INTERVAL_MS: u64 = 10;

fn tracepoint_exists(category: &str, name: &str) -> bool {
    const TRACEFS_MOUNT_POINTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

    TRACEFS_MOUNT_POINTS.iter().any(|base| {
        Path::new(base)
            .join("events")
            .join(category)
            .join(name)
            .exists()
    })
}

pub fn attach_tracepoint(bpf: &mut Ebpf, config: TracepointConfig) -> Result<bool> {
    if !tracepoint_exists(config.category, config.name) {
        warn!(
            "Tracepoint {}:{} not available; skipping {}",
            config.category, config.name, config.program_name
        );
        return Ok(false);
    }

    info!("Loading program {}", config.program_name);
    let program: &mut TracePoint = bpf
        .program_mut(config.program_name)
        .with_context(|| format!("Failed to find {} program", config.program_name))?
        .try_into()?;
    program.load()?;
    program
        .attach(config.category, config.name)
        .with_context(|| format!("Failed to attach {}", config.name))?;
    Ok(true)
}

pub fn spawn_ringbuf_handler<T, F>(bpf: &mut Ebpf, map_name: &str, handler: F) -> Result<()>
where
    T: Copy + Send + 'static,
    F: Fn(T) + Send + 'static,
{
    let mut ring_buf =
        RingBuf::try_from(bpf.take_map(map_name).context("Failed to get map")?)?;
    tokio::task::spawn_blocking(move || {
        loop {
            let mut has_work = false;
            while let Some(item) = ring_buf.next() {
                has_work = true;
                let event = unsafe { (item.as_ptr() as *const T).read_unaligned() };
                handler(event);
            }
            if !has_work {
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
        }
    });
    Ok(())
}
