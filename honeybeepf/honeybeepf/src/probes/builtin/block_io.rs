use anyhow::Result;
use aya::Bpf;
use honeybeepf_common::{BlockIoEvent, BlockIoEventType};
use log::{info, warn};

use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};

pub struct BlockIoProbe;

impl Probe for BlockIoProbe {
    fn attach(&self, bpf: &mut Bpf) -> Result<()> {
        info!("Attaching block IO probes...");

        // Try kernel 6.8+ tracepoints first
        let start_attached = attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_block_io_start",
                category: "block",
                name: "block_io_start",
            },
        );

        let done_attached = attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_block_io_done",
                category: "block",
                name: "block_io_done",
            },
        );

        // Check if kernel 6.8+ tracepoints are available
        match (start_attached, done_attached) {
            (Ok(true), Ok(true)) => {
                info!("Using block_io_start/block_io_done tracepoints (kernel 6.8+)");
            }
            _ => {
                // Fallback to kernel 5.15+ compatible tracepoints
                warn!("block_io_start/done not available, using fallback tracepoints (kernel 5.15+)");
                
                attach_tracepoint(
                    bpf,
                    TracepointConfig {
                        program_name: "honeybeepf_block_rq_issue",
                        category: "block",
                        name: "block_rq_issue",
                    },
                )?;
                
                attach_tracepoint(
                    bpf,
                    TracepointConfig {
                        program_name: "honeybeepf_block_rq_complete",
                        category: "block",
                        name: "block_rq_complete",
                    },
                )?;
            }
        }

        spawn_ringbuf_handler(bpf, "BLOCK_IO_EVENTS", |event: BlockIoEvent| {
            let rwbs = std::str::from_utf8(&event.rwbs)
                .unwrap_or("<invalid>")
                .trim_matches(char::from(0));
            let comm = std::str::from_utf8(&event.comm)
                .unwrap_or("<invalid>")
                .trim_matches(char::from(0));

            let type_str = match BlockIoEventType::from(event.event_type) {
                BlockIoEventType::Start => "START",
                BlockIoEventType::Done => "DONE",
                BlockIoEventType::Unknown => "UNKNOWN",
            };

            info!(
                "BlockIO {} pid={} dev={}:{} sector={} nr_sector={} bytes={} rwbs={} comm={}",
                type_str,
                event.metadata.pid,
                event.dev >> 20,
                event.dev & 0xFFFFF,
                event.sector,
                event.nr_sector,
                event.bytes,
                rwbs,
                comm
            );
        })?;
        
        Ok(())
    }
}