//! File access tracepoint for monitoring sensitive file accesses.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, FileAccessEvent, MAX_FILENAME_LEN};

use crate::probes::{HoneyBeeEvent, emit_event};

const MAX_EVENT_SIZE: u32 = 1024 * 1024;

#[map]
pub static FILE_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

/// Tracepoint for sys_enter_openat - fires when a process calls openat().
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    emit_event::<TracePointContext, FileAccessEvent>(&FILE_ACCESS_EVENTS, &ctx)
}

impl HoneyBeeEvent<TracePointContext> for FileAccessEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();

        // Read openat arguments from tracepoint context
        // Layout: header (16 bytes) + dfd (8) + filename (8) + flags (8) + mode (8)
        let filename_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1u32)? };
        let flags: i64 = unsafe { ctx.read_at(32).map_err(|_| 1u32)? };
        let mode: i64 = unsafe { ctx.read_at(40).map_err(|_| 1u32)? };

        self.flags = flags as u32;
        self.mode = mode as u32;
        self.tid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;

        // Read process comm
        if let Ok(comm) = bpf_get_current_comm() {
            self.comm = comm;
        }

        // Read filename from userspace
        if filename_ptr != 0 {
            let filename_slice = &mut self.filename[..MAX_FILENAME_LEN];
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(filename_ptr as *const u8, filename_slice)
            };
        }

        Ok(())
    }
}
