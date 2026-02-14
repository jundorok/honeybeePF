//! Run queue latency probe.
//!
//! ## Why eBPF?
//! - **Kernel internals visibility**: See scheduler queue state
//! - **Per-task granularity**: Know exactly which tasks are starving
//! - **Low overhead**: Only report when latency exceeds threshold
//!
//! ## Use Cases
//! - CPU contention analysis
//! - Detecting CPU-bound workload interference
//! - SLO monitoring for latency-sensitive services
//! - Noisy neighbor detection in shared environments

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// Run queue latency event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RunqueueEvent {
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub latency_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

pub struct RunqueueLatencyProbe {
    pub threshold_ns: u64,
    running: Arc<AtomicBool>,
}

impl Default for RunqueueLatencyProbe {
    fn default() -> Self {
        Self {
            threshold_ns: 10_000_000, // 10ms
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for RunqueueLatencyProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        // Attach to sched_wakeup
        let wakeup: &mut TracePoint = bpf
            .program_mut("sched_wakeup")
            .context("Failed to find sched_wakeup program")?
            .try_into()?;
        wakeup.load()?;
        wakeup.attach("sched", "sched_wakeup")?;
        info!("Attached tracepoint: sched/sched_wakeup");

        // Attach to sched_switch
        let switch: &mut TracePoint = bpf
            .program_mut("sched_switch")
            .context("Failed to find sched_switch program")?
            .try_into()?;
        switch.load()?;
        switch.attach("sched", "sched_switch")?;
        info!("Attached tracepoint: sched/sched_switch");

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("runqueue", 1);
        info!(
            "RunqueueLatencyProbe attached (threshold={}ms)",
            self.threshold_ns / 1_000_000
        );

        Ok(())
    }
}

impl RunqueueLatencyProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.map_mut("RUNQUEUE_EVENTS")
                .context("Failed to find RUNQUEUE_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<RunqueueEvent>() {
                        let event: RunqueueEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const RunqueueEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        info!(
                            "RUNQUEUE_LATENCY pid={} comm={} cpu={} latency={}ms cgroup={}",
                            event.pid,
                            comm,
                            event.cpu,
                            event.latency_ns / 1_000_000,
                            event.cgroup_id,
                        );

                        telemetry::record_runqueue_latency(
                            event.latency_ns,
                            event.cpu,
                            comm,
                            event.cgroup_id,
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        Ok(())
    }
}
