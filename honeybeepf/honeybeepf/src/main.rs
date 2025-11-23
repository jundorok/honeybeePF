use anyhow::{Context, Result};
use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Bpf, include_bytes_aligned};
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;
use honeybeepf_common::ConnectionEvent;

#[derive(Debug, Parser)]
struct Opt {
    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        if opt.verbose { "info" } else { "warn" }
    ))
    .init();


    // eBPF maps are stored in locked kernel memory (can't be swapped to disk). 
    // - `RLIMIT_MEMLOCK` - resource limit for locked-in-memory pages
    // - `RLIM_INFINITY` - removes the limit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("Failed to increase rlimit");
    }

    let mut bpf = Bpf::load(include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/honeybeepf")
    ))?;
    // build.rs compiles BPF code → writes bytecode to $OUT_DIR/honeybeepf and then parses the ELF file and loads all programs/maps into the kernel
    // Initialize BPF logger
    // if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
    //     warn!("Failed to initialize eBPF logger: {}", e);
    // }

    // Load and attach the tracepoint program
    let program: &mut TracePoint = bpf
        .program_mut("honeybeepf")
        .context("Failed to find honeybeepf program")?
        .try_into()?;
    
    program.load()?;

    // Category: syscalls
    // Event: sys_enter_connect
    // Full path: /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/
    program.attach("syscalls", "sys_enter_connect")
        .context("Failed to attach tracepoint")?;

    info!("Tracepoint attached to syscalls:sys_enter_connect");

    
    // 1. `bpf.take_map("EVENTS")` - gets the map by name from eBPF program
    // 2. `AsyncPerfEventArray::try_from()` - converts to async-compatible reader
    // 3. This is the userspace side of the kernel→userspace event channel
    // ┌─────────────┐
    // │ eBPF (CPU 0)│ → PerfEventArray buffer (CPU 0) ┐
    // ├─────────────┤                                  │
    // │ eBPF (CPU 1)│ → PerfEventArray buffer (CPU 1)  ├→ Userspace
    // ├─────────────┤                                  │
    // │ eBPF (CPU 2)│ → PerfEventArray buffer (CPU 2) ┘
    // └─────────────┘
    let mut perf_array = PerfEventArray::try_from(
        bpf.take_map("EVENTS")
            .context("Failed to get EVENTS map")?
    )?;

    // Spawn tasks to read events from each CPU since 
    // eBPF code runs on whichever CPU the process is scheduled on
    // Each CPU writes to its own buffer (lockless, fast)
    // We need one reader task per CPU
    // Get online CPUs
    let cpus = online_cpus()?;
    for cpu_id in cpus {
        // Open perf buffer for this CPU
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::task::spawn_blocking(move || {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<ConnectionEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers);
                match events {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &buffers[i];
                            let ptr = buf.as_ptr() as *const ConnectionEvent;
                            let event = unsafe { ptr.read_unaligned() };

                            // Convert network byte order to host byte order
                            let dest_ip = Ipv4Addr::from(u32::from_be(event.dest_addr));
                            let dest_port = u16::from_be(event.dest_port);

                            println!(
                                "[CPU {}] PID {} connecting to {}:{} (cgroup_id={}, ts={})",
                                cpu_id,
                                event.pid,
                                dest_ip,
                                dest_port,
                                event.cgroup_id,
                                event.timestamp
                            );

                            // TODO
                            // otel metric
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });
    }

    info!("Monitoring active. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting...");
    std::process::exit(0);
}