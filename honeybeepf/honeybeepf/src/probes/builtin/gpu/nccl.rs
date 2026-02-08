//! Userspace handler for NCCL communication probes.
//!
//! Attaches uprobes to libnccl.so functions to monitor GPU collective
//! communication patterns in AI training clusters.

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::{Ebpf, programs::UProbe};
use honeybeepf_common::{NcclEvent, NcclOpType};
use log::{info, warn};

use crate::probes::{Probe, spawn_ringbuf_handler};

/// NCCL library search paths (ordered by priority)
const NCCL_LIB_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libnccl.so.2",
    "/usr/lib/libnccl.so.2",
    "/usr/local/lib/libnccl.so.2",
    "/opt/nvidia/lib/libnccl.so.2",
    "/usr/lib/x86_64-linux-gnu/libnccl.so",
    "/usr/lib/libnccl.so",
];

/// Find libnccl.so path using priority: env var > standard paths > ldconfig
fn find_nccl_library() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("HONEYBEEPF_NCCL_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            info!("Using NCCL library from env: {}", path);
            return Some(p);
        }
        warn!("HONEYBEEPF_NCCL_PATH set but file not found: {}", path);
    }

    if let Some(p) = NCCL_LIB_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
    {
        info!("Found NCCL library at: {}", p.display());
        return Some(p);
    }

    find_via_ldconfig()
}

fn find_via_ldconfig() -> Option<PathBuf> {
    let output = std::process::Command::new("ldconfig")
        .args(["-p"])
        .output()
        .ok()?;

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("libnccl.so"))
        .find_map(|line| {
            line.split("=>")
                .nth(1)
                .map(|p| PathBuf::from(p.trim()))
                .filter(|p| p.exists())
        })
        .inspect(|p| info!("Found NCCL library via ldconfig: {}", p.display()))
}

/// NCCL function to probe with its entry/exit program names
struct NcclProbeConfig {
    symbol: &'static str,
    entry_prog: &'static str,
    exit_prog: &'static str,
}

const NCCL_PROBES: &[NcclProbeConfig] = &[
    NcclProbeConfig {
        symbol: "ncclAllReduce",
        entry_prog: "nccl_allreduce_enter",
        exit_prog: "nccl_allreduce_exit",
    },
    NcclProbeConfig {
        symbol: "ncclBroadcast",
        entry_prog: "nccl_broadcast_enter",
        exit_prog: "nccl_broadcast_exit",
    },
    NcclProbeConfig {
        symbol: "ncclAllGather",
        entry_prog: "nccl_allgather_enter",
        exit_prog: "nccl_allgather_exit",
    },
    NcclProbeConfig {
        symbol: "ncclReduceScatter",
        entry_prog: "nccl_reducescatter_enter",
        exit_prog: "nccl_reducescatter_exit",
    },
    NcclProbeConfig {
        symbol: "ncclSend",
        entry_prog: "nccl_send_enter",
        exit_prog: "nccl_send_exit",
    },
    NcclProbeConfig {
        symbol: "ncclRecv",
        entry_prog: "nccl_recv_enter",
        exit_prog: "nccl_recv_exit",
    },
    NcclProbeConfig {
        symbol: "ncclGroupStart",
        entry_prog: "nccl_group_start_enter",
        exit_prog: "nccl_group_start_exit",
    },
    NcclProbeConfig {
        symbol: "ncclGroupEnd",
        entry_prog: "nccl_group_end_enter",
        exit_prog: "nccl_group_end_exit",
    },
    NcclProbeConfig {
        symbol: "ncclGetVersion",
        entry_prog: "nccl_get_version_enter",
        exit_prog: "nccl_get_version_exit",
    },
];

fn op_type_name(op: NcclOpType) -> &'static str {
    match op {
        NcclOpType::AllReduce => "AllReduce",
        NcclOpType::Broadcast => "Broadcast",
        NcclOpType::AllGather => "AllGather",
        NcclOpType::ReduceScatter => "ReduceScatter",
        NcclOpType::AllToAll => "AllToAll",
        NcclOpType::Send => "Send",
        NcclOpType::Recv => "Recv",
        NcclOpType::GroupStart => "GroupStart",
        NcclOpType::GroupEnd => "GroupEnd",
        NcclOpType::CommInitRank => "CommInitRank",
        NcclOpType::GetVersion => "GetVersion",
        NcclOpType::Unknown => "Unknown",
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_duration(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2} s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2} µs", ns as f64 / 1_000.0)
    } else {
        format!("{} ns", ns)
    }
}

pub struct NcclCommProbe;

impl Probe for NcclCommProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        let nccl_path = match find_nccl_library() {
            Some(p) => p,
            None => {
                warn!("NCCL library not found. NCCL probes will not be attached.");
                warn!("Set HONEYBEEPF_NCCL_PATH environment variable to specify the path.");
                return Ok(());
            }
        };

        let nccl_path_str = nccl_path.to_string_lossy();
        info!("Attaching NCCL probes to: {}", nccl_path_str);

        let mut attached_count = 0;

        for probe_config in NCCL_PROBES {
            // Both entry and exit must succeed for the probe pair to work
            let entry_result = attach_uprobe(
                bpf,
                probe_config.entry_prog,
                &nccl_path_str,
                probe_config.symbol,
            );
            let exit_result = attach_uprobe(
                bpf,
                probe_config.exit_prog,
                &nccl_path_str,
                probe_config.symbol,
            );

            match (entry_result, exit_result) {
                (Ok(_), Ok(_)) => {
                    info!("  Attached probe pair: {}", probe_config.symbol);
                    attached_count += 1;
                }
                (Err(e), _) => {
                    warn!(
                        "  Skipping {}: entry probe failed: {}",
                        probe_config.symbol, e
                    );
                }
                (_, Err(e)) => {
                    // Entry succeeded but exit failed - this is a problem
                    // The entry probe is already loaded, but without exit it won't emit events
                    // This is acceptable as PendingNcclOp will just accumulate (bounded by MAX_PENDING_OPS)
                    warn!(
                        "  Skipping {}: exit probe failed: {}",
                        probe_config.symbol, e
                    );
                }
            }
        }

        if attached_count == 0 {
            warn!("No NCCL probes were attached. Check if symbols exist in the library.");
            return Ok(());
        }

        info!("Successfully attached {} NCCL probe pairs", attached_count);

        // Handle NCCL events
        spawn_ringbuf_handler(bpf, "NCCL_EVENTS", |event: NcclEvent| {
            let comm = std::str::from_utf8(&event.comm)
                .unwrap_or("<invalid>")
                .trim_matches(char::from(0));

            let op_type = NcclOpType::from(event.op_type);
            let op_name = op_type_name(op_type);

            // Format output based on operation type
            if event.bytes_transferred > 0 {
                info!(
                    "NCCL_{} pid={} comm={} count={} bytes={} duration={} ret={} cgroup_id={}",
                    op_name,
                    event.metadata.pid,
                    comm,
                    event.count,
                    format_bytes(event.bytes_transferred),
                    format_duration(event.duration_ns),
                    event.ret_code,
                    event.metadata.cgroup_id,
                );
            } else {
                // Simple operations like GroupStart/End, GetVersion
                info!(
                    "NCCL_{} pid={} comm={} duration={} ret={} cgroup_id={}",
                    op_name,
                    event.metadata.pid,
                    comm,
                    format_duration(event.duration_ns),
                    event.ret_code,
                    event.metadata.cgroup_id,
                );
            }
        })?;

        Ok(())
    }
}

/// Attach a uprobe or uretprobe to a function
fn attach_uprobe(bpf: &mut Ebpf, program_name: &str, target: &str, symbol: &str) -> Result<()> {
    let program: &mut UProbe = bpf
        .program_mut(program_name)
        .with_context(|| format!("Failed to find program: {}", program_name))?
        .try_into()
        .with_context(|| format!("Program {} is not a UProbe", program_name))?;

    program.load()?;

    program
        .attach(Some(symbol), 0, target, None)
        .with_context(|| format!("Failed to attach uprobe to {}:{}", target, symbol))?;

    Ok(())
}
