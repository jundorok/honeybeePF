use std::net::Ipv4Addr;

use anyhow::Result;
use aya::Ebpf;
use honeybeepf_common::ConnectionEvent;
use log::info;

use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};

pub struct NetworkLatencyProbe;

impl Probe for NetworkLatencyProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        info!("Attaching network latency probes...");
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf",
                category: "syscalls",
                name: "sys_enter_connect",
            },
        )?;
        
        spawn_ringbuf_handler(bpf, "NETWORK_EVENTS", |event: ConnectionEvent| {
            let dest_ip = Ipv4Addr::from(u32::from_be(event.dest_addr));
            let dest_port = u16::from_be(event.dest_port);

            info!(
                "PID {} connecting to {}:{} (cgroup_id={}, ts={})",
                event.metadata.pid, dest_ip, dest_port, event.metadata.cgroup_id, event.metadata.timestamp
            );
        })?;
        
        Ok(())
    }
}
