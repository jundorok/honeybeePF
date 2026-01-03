use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::signal;
use honeybeepf_common::ConnectionEvent;

const POLL_INTERVAL_MS: u64 = 10;

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


    // Initialize the RingBuf map. 
    // Note: We use take_map instead of map_mut because RingBuf in aya 
    // is often used as a stateful iterator.
    let mut ring_buf = RingBuf::try_from(
        bpf.take_map("EVENTS")
            .context("Failed to get EVENTS map")?
    )?;

    // RingBuf handles events from all CPUs in a single shared buffer.
    // No need to loop through online_cpus().
    tokio::task::spawn_blocking(move || {
        info!("Started RingBuf event listener.");
        loop {
            let mut has_work = false;
            // next() will return the next available event item.
            while let Some(item) = ring_buf.next() {
                has_work = true;

                // Explicitly cast the item to get the raw pointer
                let ptr = item.as_ptr() as *const ConnectionEvent;
                
                // Safety: read_unaligned is used to handle potentially unaligned data from kernel
                let event = unsafe { ptr.read_unaligned() };

                // Convert network byte order to host byte order
                let dest_ip = Ipv4Addr::from(u32::from_be(event.dest_addr));
                let dest_port = u16::from_be(event.dest_port);

                println!(
                    "PID {} connecting to {}:{} (cgroup_id={}, ts={})",
                    event.pid,
                    dest_ip,
                    dest_port,
                    event.cgroup_id,
                    event.timestamp
                );
            }
            // If no events were found, sleep for a short duration to prevent 100% CPU usage.
            // This is the standard way to handle polling in a blocking thread.
            if !has_work {
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
        }
    });

    info!("Monitoring active. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting...");
    std::process::exit(0);
}