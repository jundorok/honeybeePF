use aya_ebpf::{
    EbpfContext,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use honeybeepf_common::BlockIoEvent;

use crate::probes::{emit_event, HoneyBeeEvent};

const MAX_EVENT_SIZE: u32 = 1024 * 1024;

#[map]
pub static BLOCK_IO_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

#[tracepoint]
pub fn honeybeepf_block_io_start(ctx: TracePointContext) -> u32 {
    emit_event::<BlockIoStart>(&BLOCK_IO_EVENTS, &ctx)
}

#[tracepoint]
pub fn honeybeepf_block_io_done(ctx: TracePointContext) -> u32 {
    emit_event::<BlockIoDone>(&BLOCK_IO_EVENTS, &ctx)
}

#[repr(C)]
struct BlockIoTrace {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    dev: u32,
    sector: u64,
    nr_sector: u32,
    bytes: u32,
    rwbs: [u8; 8],
    comm: [u8; 16],
    cmd: [u8; 4], // Optional, often present
}

use honeybeepf_common::{BlockIoEventType, EventMetadata};

#[repr(transparent)]
pub struct BlockIoStart(BlockIoEvent);

impl HoneyBeeEvent for BlockIoStart {
    fn metadata(&mut self) -> &mut EventMetadata { self.0.metadata() }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.0.fill(ctx)?;
        self.0.event_type = BlockIoEventType::Start as u8;
        Ok(())
    }
}

#[repr(transparent)]
pub struct BlockIoDone(BlockIoEvent);

impl HoneyBeeEvent for BlockIoDone {
    fn metadata(&mut self) -> &mut EventMetadata { self.0.metadata() }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.0.fill(ctx)?;
        self.0.event_type = BlockIoEventType::Done as u8;
        Ok(())
    }
}

impl HoneyBeeEvent for BlockIoEvent {
    fn metadata(&mut self) -> &mut EventMetadata { &mut self.metadata }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();
        
        let header_ptr = ctx.as_ptr() as *const BlockIoTrace;

        self.dev = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).dev) as *const u32)
                .map_err(|_| 1u32)?
        };

        self.sector = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).sector) as *const u64)
                .map_err(|_| 1u32)?
        };

        self.nr_sector = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).nr_sector) as *const u32)
                .map_err(|_| 1u32)?
        };

        self.bytes = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).bytes) as *const u32)
                .map_err(|_| 1u32)?
        };

        self.rwbs = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).rwbs) as *const [u8; 8])
                .map_err(|_| 1u32)?
        };

        self.comm = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).comm) as *const [u8; 16])
                .map_err(|_| 1u32)?
        };
        
        // Event type is set by the caller
        self.event_type = BlockIoEventType::Unknown as u8;
        
        Ok(())
    }
}
