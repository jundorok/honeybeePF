use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::KProbe;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// TCP connection event data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpConnectEvent {
    pub pid: u32,
    pub tid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub latency_ns: u64,
    pub ret_code: i32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

pub struct TcpConnectProbe {
    running: Arc<AtomicBool>,
}

impl Default for TcpConnectProbe {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for TcpConnectProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        // Attach kprobe to tcp_v4_connect entry
        let tcp_connect_entry: &mut KProbe = bpf
            .program_mut("tcp_v4_connect_entry")
            .context("Failed to find tcp_v4_connect_entry program")?
            .try_into()
            .context("Program is not a KProbe")?;

        tcp_connect_entry.load()?;
        tcp_connect_entry
            .attach("tcp_v4_connect", 0)
            .context("Failed to attach tcp_v4_connect_entry")?;

        info!("Attached kprobe: tcp_v4_connect (entry)");

        // Attach kretprobe to tcp_v4_connect exit
        let tcp_connect_exit: &mut KProbe = bpf
            .program_mut("tcp_v4_connect_exit")
            .context("Failed to find tcp_v4_connect_exit program")?
            .try_into()
            .context("Program is not a KProbe")?;

        tcp_connect_exit.load()?;
        tcp_connect_exit
            .attach("tcp_v4_connect", 0)
            .context("Failed to attach tcp_v4_connect_exit")?;

        info!("Attached kretprobe: tcp_v4_connect (exit)");

        // Spawn event handler
        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("tcp_connect", 1);
        info!("TcpConnectProbe attached successfully");

        Ok(())
    }
}

impl TcpConnectProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.take_map("TCP_CONNECT_EVENTS")
                .context("Failed to find TCP_CONNECT_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<TcpConnectEvent>() {
                        let event: TcpConnectEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const TcpConnectEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let daddr = format_ipv4(event.daddr);
                        let saddr = format_ipv4(event.saddr);
                        let success = event.ret_code == 0;

                        info!(
                            "TCP_CONNECT pid={} comm={} {}:{} -> {}:{} latency={}µs ret={} cgroup={}",
                            event.pid,
                            comm,
                            saddr,
                            event.sport,
                            daddr,
                            event.dport,
                            event.latency_ns / 1000,
                            event.ret_code,
                            event.cgroup_id,
                        );

                        // Send metrics
                        telemetry::record_tcp_connect_event(
                            &daddr,
                            event.dport,
                            event.latency_ns,
                            success,
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

/// Format IPv4 address for display
pub fn format_ipv4(addr: u32) -> String {
    let bytes = addr.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}
