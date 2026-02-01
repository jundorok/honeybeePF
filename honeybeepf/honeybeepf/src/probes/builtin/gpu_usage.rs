use anyhow::Result;
use aya::Ebpf;
use honeybeepf_common::{GpuCloseEvent, GpuOpenEvent};
use log::info;
use std::fs;

use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};

fn get_process_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

fn get_gpu_type(filename: &str) -> &'static str {
    if filename.starts_with("/dev/nvidia") {
        "NVIDIA"
    } else if filename.starts_with("/dev/dri/") {
        "DRI"
    } else {
        "Unknown"
    }
}

pub struct GpuUsageProbe;

impl Probe for GpuUsageProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        info!("Attaching GPU usage probes...");

        // Attach sys_enter_openat (check if GPU, store pending)
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_gpu_open_enter",
                category: "syscalls",
                name: "sys_enter_openat",
            },
        )?;

        // Attach sys_exit_openat (get fd, emit open event)
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_gpu_open_exit",
                category: "syscalls",
                name: "sys_exit_openat",
            },
        )?;

        // Attach sys_enter_close (check if GPU fd, emit close event)
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_gpu_close",
                category: "syscalls",
                name: "sys_enter_close",
            },
        )?;

        // Handle GPU open events
        spawn_ringbuf_handler(bpf, "GPU_OPEN_EVENTS", |event: GpuOpenEvent| {
            let comm = get_process_name(event.metadata.pid);
            let filename = std::str::from_utf8(&event.filename)
                .unwrap_or("<invalid>")
                .trim_matches(char::from(0));
            let gpu_type = get_gpu_type(filename);

            info!(
                "GPU_OPEN pid={} comm={} gpu_index={} fd={} type={} file={} cgroup_id={}",
                event.metadata.pid,
                comm,
                event.gpu_index,
                event.fd,
                gpu_type,
                filename,
                event.metadata.cgroup_id,
            );
        })?;

        // Handle GPU close events
        spawn_ringbuf_handler(bpf, "GPU_CLOSE_EVENTS", |event: GpuCloseEvent| {
            let comm = get_process_name(event.metadata.pid);

            info!(
                "GPU_CLOSE pid={} comm={} gpu_index={} fd={} cgroup_id={}",
                event.metadata.pid,
                comm,
                event.gpu_index,
                event.fd,
                event.metadata.cgroup_id,
            );
        })?;

        Ok(())
    }
}
