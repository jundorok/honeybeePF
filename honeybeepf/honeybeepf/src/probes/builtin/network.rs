use std::net::Ipv4Addr;

use anyhow::Result;
use aya::Bpf;
use honeybeepf_common::ConnectionEvent;
use tracing::info;

use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};

// honeybeepf-ebpf/src/probes/builtin/network.rs
// AF_INET from Linux kernel UAPI (include/linux/socket.h)
// This is a stable kernel ABI constant, safe to hardcode
const AF_INET: u16 = libc::AF_INET as u16;

pub struct NetworkLatencyProbe;

impl Probe for NetworkLatencyProbe {
    fn attach(&self, bpf: &mut Bpf) -> Result<()> {
        info!("Attaching network latency probes...");
        
        // Attach tracepoint to the 'connect' system call entry.
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf",
                category: "syscalls",
                name: "sys_enter_connect",
            },
        )?;
        
        // Spawn a background handler to process events from the eBPF ring buffer.
        spawn_ringbuf_handler(bpf, "NETWORK_EVENTS", |event: ConnectionEvent| {
            // FILTER: Only process IPv4 (AF_INET) events and ignore invalid destination addresses.
            // This filters out noise like 0.0.0.0:0 and non-IPv4 traffic.
            if event.address_family != AF_INET || event.dest_addr == 0 {
                return;
            }

            // Convert raw binary data from kernel space to human-readable Rust types.
            // u32/u16 are converted from Big-Endian (network byte order) to Host-Endian.
            let dest_ip = Ipv4Addr::from(u32::from_be(event.dest_addr));
            let dest_port = u16::from_be(event.dest_port);

            // Log the captured outbound connection attempt.
            info!(
                target: "kernel_monitor",
                pid = event.metadata.pid,
                dest = %dest_ip,
                port = dest_port,
                cgroup_id = event.metadata.cgroup_id,
                "New outbound connection detected"
            );
        })?;
        
        Ok(())
    }
}