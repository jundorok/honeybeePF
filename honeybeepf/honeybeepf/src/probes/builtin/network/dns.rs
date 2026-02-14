//! DNS query monitoring probe.
//!
//! ## Why eBPF?
//! - **No DNS server access needed**: Monitor from client side
//! - **Application-transparent**: No resolver library patching
//! - **Full query visibility**: See all DNS queries, even from static binaries
//!
//! ## Use Cases
//! - Service dependency discovery via DNS
//! - Detecting DNS tunneling or exfiltration
//! - Debugging DNS resolution issues
//! - Monitoring DNS latency

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::UProbe;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// DNS query event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DnsEvent {
    pub pid: u32,
    pub tid: u32,
    pub query_type: u16,
    pub latency_ns: u64,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub query_name: [u8; 256],
}

pub struct DnsProbe {
    running: Arc<AtomicBool>,
}

impl Default for DnsProbe {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for DnsProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        // Attach to getaddrinfo in libc
        let libc_path = find_libc_path()?;
        
        let program: &mut UProbe = bpf
            .program_mut("getaddrinfo_entry")
            .context("Failed to find getaddrinfo_entry program")?
            .try_into()
            .context("Program is not a UProbe")?;
        
        program.load()?;
        program
            .attach(Some("getaddrinfo"), 0, &libc_path, None)
            .context("Failed to attach uprobe to getaddrinfo")?;
        
        info!("Attached uprobe: getaddrinfo @ {}", libc_path);
        
        // Attach uretprobe for latency measurement
        let program_ret: &mut UProbe = bpf
            .program_mut("getaddrinfo_exit")
            .context("Failed to find getaddrinfo_exit program")?
            .try_into()
            .context("Program is not a UProbe")?;
        
        program_ret.load()?;
        program_ret
            .attach(Some("getaddrinfo"), 0, &libc_path, None)
            .context("Failed to attach uretprobe to getaddrinfo")?;
        
        info!("Attached uretprobe: getaddrinfo @ {}", libc_path);
        
        self.spawn_event_handler(bpf)?;
        
        telemetry::record_active_probe("dns", 1);
        info!("DnsProbe attached successfully");
        
        Ok(())
    }
}

impl DnsProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.map_mut("DNS_EVENTS")
                .context("Failed to find DNS_EVENTS map")?,
        )?;

        let running = self.running.clone();
        
        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;
            
            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<DnsEvent>() {
                        let event: DnsEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const DnsEvent)
                        };
                        
                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));
                        
                        let query_name = std::str::from_utf8(&event.query_name)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));
                        
                        let query_type = dns_type_name(event.query_type);
                        
                        info!(
                            "DNS_QUERY pid={} comm={} name={} type={} latency={}µs cgroup={}",
                            event.pid,
                            comm,
                            query_name,
                            query_type,
                            event.latency_ns / 1000,
                            event.cgroup_id,
                        );
                        
                        telemetry::record_dns_query_event(
                            query_name,
                            query_type,
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

fn find_libc_path() -> Result<String> {
    // Common libc paths
    let paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
    ];
    
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    anyhow::bail!("Could not find libc.so")
}

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        2 => "NS",
        12 => "PTR",
        6 => "SOA",
        16 => "TXT",
        33 => "SRV",
        _ => "OTHER",
    }
}
