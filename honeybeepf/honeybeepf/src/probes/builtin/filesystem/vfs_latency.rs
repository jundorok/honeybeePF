use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// VFS operation types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VfsOpType {
    Read = 0,
    Write = 1,
    Open = 2,
    Fsync = 3,
}

impl From<u8> for VfsOpType {
    fn from(v: u8) -> Self {
        match v {
            0 => VfsOpType::Read,
            1 => VfsOpType::Write,
            2 => VfsOpType::Open,
            3 => VfsOpType::Fsync,
            _ => VfsOpType::Read,
        }
    }
}

/// VFS latency event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VfsLatencyEvent {
    pub pid: u32,
    pub tid: u32,
    pub op_type: u8,
    pub latency_ns: u64,
    pub bytes: u64,
    pub ino: u64,
    pub dev: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

pub struct VfsLatencyProbe {
    pub threshold_ns: u64,
    running: Arc<AtomicBool>,
}

impl Default for VfsLatencyProbe {
    fn default() -> Self {
        Self {
            threshold_ns: 1_000_000, // 1ms default
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for VfsLatencyProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        // Attach to vfs_read
        attach_kprobe_pair(bpf, "vfs_read_entry", "vfs_read_exit", "vfs_read")?;
        info!("Attached kprobe pair: vfs_read");

        // Attach to vfs_write
        attach_kprobe_pair(bpf, "vfs_write_entry", "vfs_write_exit", "vfs_write")?;
        info!("Attached kprobe pair: vfs_write");

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("vfs_latency", 1);
        info!(
            "VfsLatencyProbe attached (threshold={}ms)",
            self.threshold_ns / 1_000_000
        );

        Ok(())
    }
}

impl VfsLatencyProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.take_map("VFS_EVENTS")
                .context("Failed to find VFS_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<VfsLatencyEvent>() {
                        let event: VfsLatencyEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const VfsLatencyEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let filename = std::str::from_utf8(&event.filename)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let op = match VfsOpType::from(event.op_type) {
                            VfsOpType::Read => "READ",
                            VfsOpType::Write => "WRITE",
                            VfsOpType::Open => "OPEN",
                            VfsOpType::Fsync => "FSYNC",
                        };

                        info!(
                            "VFS_{} pid={} comm={} file={} bytes={} latency={} cgroup={}",
                            op,
                            event.pid,
                            comm,
                            filename,
                            event.bytes,
                            format_duration(event.latency_ns),
                            event.cgroup_id,
                        );

                        telemetry::record_vfs_event(
                            op.to_lowercase().as_str(),
                            filename,
                            event.bytes,
                            event.latency_ns,
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

fn attach_kprobe_pair(
    bpf: &mut Ebpf,
    entry_name: &str,
    exit_name: &str,
    target_fn: &str,
) -> Result<()> {
    let entry: &mut KProbe = bpf
        .program_mut(entry_name)
        .context(format!("Failed to find {} program", entry_name))?
        .try_into()?;
    entry.load()?;
    entry.attach(target_fn, 0)?;

    let exit: &mut KProbe = bpf
        .program_mut(exit_name)
        .context(format!("Failed to find {} program", exit_name))?
        .try_into()?;
    exit.load()?;
    exit.attach(target_fn, 0)?;

    Ok(())
}

pub fn format_duration(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2}µs", ns as f64 / 1_000.0)
    } else {
        format!("{}ns", ns)
    }
}
