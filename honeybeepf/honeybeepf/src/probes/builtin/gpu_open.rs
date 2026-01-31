use anyhow::Result;
use aya::Ebpf;
use honeybeepf_common::GpuOpenEvent;
use log::info;
use std::fs;

use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};
use crate::telemetry;

fn get_process_name(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

pub struct GpuOpenProbe;

impl Probe for GpuOpenProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        info!("Attaching GPU open probes...");

        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_gpu_open_enter",
                category: "syscalls",
                name: "sys_enter_openat",
            },
        )?;

        spawn_ringbuf_handler(bpf, "GPU_OPEN_EVENTS", |event: GpuOpenEvent| {
            let comm = {
                let event_comm = std::str::from_utf8(&event.comm)
                    .unwrap_or("")
                    .trim_matches(char::from(0));
                if event_comm.is_empty() {
                    get_process_name(event.metadata.pid)
                } else {
                    event_comm.to_string()
                }
            };

            let filename = std::str::from_utf8(&event.filename)
                .unwrap_or("<invalid>")
                .trim_matches(char::from(0));

            let gpu_type = if filename.starts_with("/dev/nvidia") {
                "NVIDIA"
            } else if filename.starts_with("/dev/dri/") {
                "DRI"
            } else {
                "Unknown"
            };

            info!(
                "GPU_OPEN pid={} comm={} gpu_index={} type={} file={} cgroup_id={}",
                event.metadata.pid,
                comm,
                event.gpu_index,
                gpu_type,
                filename,
                event.metadata.cgroup_id,
            );

            // Transport OpenTelemetry Metric
            telemetry::record_gpu_open_event(filename);
        })?;

        Ok(())
    }
}
