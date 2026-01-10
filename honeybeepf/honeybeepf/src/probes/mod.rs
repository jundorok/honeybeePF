use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Bpf;
use log::debug;
use std::time::Duration;

pub mod builtin;
pub mod custom;

pub trait Probe {
    fn attach(&self, bpf: &mut Bpf) -> Result<()>;
}

pub struct TracepointConfig<'a> {
    pub program_name: &'a str,
    pub category: &'a str,
    pub name: &'a str,
}

pub const POLL_INTERVAL_MS: u64 = 10;

pub fn attach_tracepoint(bpf: &mut Bpf, config: TracepointConfig) -> Result<()> {
    debug!("Loading program {}", config.program_name);
    let program: &mut TracePoint = bpf
        .program_mut(config.program_name)
        .with_context(|| format!("Failed to find {} program", config.program_name))?
        .try_into()?;
    program.load()?;
    program
        .attach(config.category, config.name)
        .with_context(|| format!("Failed to attach {}", config.name))?;
    Ok(())
}

pub fn spawn_ringbuf_handler<T, F>(bpf: &mut Bpf, map_name: &str, handler: F) -> Result<()>
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
