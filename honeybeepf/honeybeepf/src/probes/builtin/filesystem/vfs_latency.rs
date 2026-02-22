use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::{HashMap, RingBuf};
use aya::programs::KProbe;
use honeybeepf_common::{VfsLatencyEvent, VfsOpType};
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

pub struct VfsLatencyProbe {
    pub threshold_ns: u64,
    running: Arc<AtomicBool>,
}

impl VfsLatencyProbe {
    pub fn new(threshold_ms: u32) -> Self {
        Self {
            threshold_ns: (threshold_ms as u64) * 1_000_000,
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Default for VfsLatencyProbe {
    fn default() -> Self {
        Self {
            threshold_ns: 10_000_000, // 10ms default
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for VfsLatencyProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        // Set threshold in eBPF map
        self.set_threshold(bpf)?;

        // Attach to vfs_write (always)
        attach_kprobe_pair(bpf, "vfs_write_entry", "vfs_write_exit", "vfs_write")?;
        info!("Attached kprobe pair: vfs_write");

        // Attach to vfs_read (with smart filtering in eBPF)
        // eBPF filters: regular files only + (large read OR slow read)
        attach_kprobe_pair(bpf, "vfs_read_entry", "vfs_read_exit", "vfs_read")?;
        info!("Attached kprobe pair: vfs_read (filtered: regular files, large/slow only)");

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("vfs_latency", 1);
        info!(
            "VfsLatencyProbe attached (threshold={}ms, read+write)",
            self.threshold_ns / 1_000_000
        );

        Ok(())
    }
}

impl VfsLatencyProbe {
    fn set_threshold(&self, bpf: &mut Ebpf) -> Result<()> {
        let mut threshold_map: HashMap<_, u32, u64> = bpf
            .map_mut("VFS_THRESHOLD_NS")
            .context("Failed to find VFS_THRESHOLD_NS map")?
            .try_into()
            .context("VFS_THRESHOLD_NS is not a HashMap")?;

        threshold_map.insert(0, self.threshold_ns, 0)?;
        info!("Set VFS latency threshold to {}ns", self.threshold_ns);

        Ok(())
    }

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
                        };

                        // Categorize file type
                        let category = categorize_file(filename);

                        info!(
                            "VFS_{} pid={} comm={} file={} bytes={} latency={} category={} cgroup={}",
                            op,
                            event.metadata.pid,
                            comm,
                            filename,
                            format_bytes(event.bytes),
                            format_duration(event.latency_ns),
                            category,
                            event.metadata.cgroup_id,
                        );

                        telemetry::record_vfs_event(
                            op.to_lowercase().as_str(),
                            filename,
                            event.bytes,
                            event.latency_ns,
                            event.metadata.cgroup_id,
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        Ok(())
    }
}

/// Categorize file by extension for model/dataset identification
fn categorize_file(filename: &str) -> &'static str {
    let lower = filename.to_lowercase();
    
    // Model files
    if lower.ends_with(".safetensors")
        || lower.ends_with(".gguf")
        || lower.ends_with(".ggml")
        || lower.ends_with(".pt")
        || lower.ends_with(".pth")
        || lower.ends_with(".bin") && (lower.contains("model") || lower.contains("pytorch"))
    {
        return "model";
    }
    
    // Dataset files
    if lower.ends_with(".parquet")
        || lower.ends_with(".arrow")
        || lower.ends_with(".csv")
        || lower.ends_with(".jsonl")
    {
        return "dataset";
    }
    
    // Checkpoint files
    if lower.contains("checkpoint") || lower.contains("ckpt") {
        return "checkpoint";
    }
    
    "other"
}

/// Format bytes to human readable
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
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
