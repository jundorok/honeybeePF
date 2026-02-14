use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// Reason for being off-CPU
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum OffCpuReason {
    Unknown = 0,
    Sleeping = 1,
    DiskIO = 2,
    NetworkIO = 3,
    Lock = 4,
    PageFault = 5,
    Preempted = 6,
}

impl From<u8> for OffCpuReason {
    fn from(v: u8) -> Self {
        match v {
            1 => OffCpuReason::Sleeping,
            2 => OffCpuReason::DiskIO,
            3 => OffCpuReason::NetworkIO,
            4 => OffCpuReason::Lock,
            5 => OffCpuReason::PageFault,
            6 => OffCpuReason::Preempted,
            _ => OffCpuReason::Unknown,
        }
    }
}

/// Off-CPU event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OffCpuEvent {
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub reason: u8,
    pub duration_ns: u64,
    pub waker_pid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub waker_comm: [u8; 16],
}

pub struct OffCpuProbe {
    pub threshold_ns: u64,
    pub capture_stack: bool,
    running: Arc<AtomicBool>,
}

impl Default for OffCpuProbe {
    fn default() -> Self {
        Self {
            threshold_ns: 1_000_000, // 1ms
            capture_stack: false,
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for OffCpuProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        let program: &mut TracePoint = bpf
            .program_mut("sched_switch_offcpu")
            .context("Failed to find sched_switch_offcpu program")?
            .try_into()?;

        program.load()?;
        program.attach("sched", "sched_switch")?;
        info!("Attached tracepoint: sched/sched_switch (off-CPU tracking)");

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("offcpu", 1);
        info!(
            "OffCpuProbe attached (threshold={}ms)",
            self.threshold_ns / 1_000_000
        );

        Ok(())
    }
}

impl OffCpuProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.take_map("OFFCPU_EVENTS")
                .context("Failed to find OFFCPU_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<OffCpuEvent>() {
                        let event: OffCpuEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const OffCpuEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let waker_comm = std::str::from_utf8(&event.waker_comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let reason = reason_name(event.reason.into());

                        info!(
                            "OFFCPU pid={} comm={} reason={} duration={}ms waker={}/{} cgroup={}",
                            event.pid,
                            comm,
                            reason,
                            event.duration_ns / 1_000_000,
                            event.waker_pid,
                            waker_comm,
                            event.cgroup_id,
                        );

                        telemetry::record_offcpu_event(
                            event.duration_ns,
                            reason,
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

fn reason_name(reason: OffCpuReason) -> &'static str {
    match reason {
        OffCpuReason::Unknown => "unknown",
        OffCpuReason::Sleeping => "sleeping",
        OffCpuReason::DiskIO => "disk_io",
        OffCpuReason::NetworkIO => "network_io",
        OffCpuReason::Lock => "lock",
        OffCpuReason::PageFault => "page_fault",
        OffCpuReason::Preempted => "preempted",
    }
}
