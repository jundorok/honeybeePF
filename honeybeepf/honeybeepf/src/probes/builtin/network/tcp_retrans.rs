use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// TCP retransmission event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpRetransEvent {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub state: u8,
    pub retrans_count: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

pub struct TcpRetransProbe {
    running: Arc<AtomicBool>,
}

impl Default for TcpRetransProbe {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for TcpRetransProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        let program: &mut TracePoint = bpf
            .program_mut("tcp_retransmit_skb")
            .context("Failed to find tcp_retransmit_skb program")?
            .try_into()
            .context("Program is not a TracePoint")?;

        program.load()?;
        program
            .attach("tcp", "tcp_retransmit_skb")
            .context("Failed to attach tcp_retransmit_skb tracepoint")?;

        info!("Attached tracepoint: tcp/tcp_retransmit_skb");

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("tcp_retrans", 1);
        info!("TcpRetransProbe attached successfully");

        Ok(())
    }
}

impl TcpRetransProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.take_map("TCP_RETRANS_EVENTS")
                .context("Failed to find TCP_RETRANS_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<TcpRetransEvent>() {
                        let event: TcpRetransEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const TcpRetransEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let daddr = super::tcp_connect::format_ipv4(event.daddr);
                        let state_name = tcp_state_name(event.state);

                        info!(
                            "TCP_RETRANS pid={} comm={} -> {}:{} state={} count={} cgroup={}",
                            event.pid,
                            comm,
                            daddr,
                            event.dport,
                            state_name,
                            event.retrans_count,
                            event.cgroup_id,
                        );

                        telemetry::record_tcp_retrans_event(
                            &daddr,
                            event.dport,
                            state_name,
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

fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}
