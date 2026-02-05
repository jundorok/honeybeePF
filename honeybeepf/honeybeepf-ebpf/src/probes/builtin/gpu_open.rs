use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, GpuOpenEvent};

use crate::probes::HoneyBeeEvent;
use super::gpu_utils::get_gpu_index;

const MAX_EVENT_SIZE: u32 = 1024 * 1024;

#[repr(u32)]
pub enum EmitGpuStatus {
    Success = 0,
    Failure = 1,
    NotGpuDevice = 2,
}

#[map]
pub static GPU_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);


#[repr(C)]
struct SysEnterOpenat {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    __syscall_nr: i32,
    _pad: i32,
    dfd: i64,
    filename: u64,
    flags: i64,
    mode: i64,
}

impl HoneyBeeEvent<TracePointContext> for GpuOpenEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();

        let header_ptr = ctx.as_ptr() as *const SysEnterOpenat;
        let filename_ptr: u64 = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).filename) as *const u64)
                .map_err(|_| EmitGpuStatus::Failure as u32)?
        };
        if filename_ptr == 0 {
            return Err(EmitGpuStatus::Failure as u32);
        }
        let mut filename_buf: [u8; 64] = [0u8; 64];
        let filename_len = unsafe {
            bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename_buf)
                .map_err(|_| EmitGpuStatus::Failure as u32)?
                .len()
        };
        let gpu_index = get_gpu_index(&filename_buf[..filename_len]);
        if gpu_index < 0 {
            return Err(EmitGpuStatus::NotGpuDevice as u32);
        }
        let flags: i64 = unsafe {
            aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).flags) as *const i64)
                .map_err(|_| EmitGpuStatus::Failure as u32)?
        };

        self.gpu_index = gpu_index;
        self.fd = -1; // Not available at enter, would need exit tracepoint TODO
        self.flags = flags as i32;

        // comm will be filled by userspace using /proc/{pid}/comm
        self.comm = [0u8; 16];
        self.filename = [0u8; 64];
        let copy_len = if filename_len < 64 { filename_len } else { 63 };
        let mut i = 0;
        while i < copy_len {
            self.filename[i] = filename_buf[i];
            i += 1;
        }

        Ok(())
    }
}

fn emit_gpu_event(ringbuf: &RingBuf, ctx: &TracePointContext) -> u32 {
    if let Some(mut slot) = ringbuf.reserve::<GpuOpenEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };

        match event.fill(ctx) {
            Ok(_) => {
                slot.submit(0);
                EmitGpuStatus::Success as u32
            }
            Err(e) if e == EmitGpuStatus::NotGpuDevice as u32 => {
                slot.discard(0);
                EmitGpuStatus::Success as u32  // Silent discard for non-GPU devices
            }
            Err(e) => {
                slot.discard(0);
                e
            }
        }
    } else {
        EmitGpuStatus::Failure as u32
    }
}

#[tracepoint]
pub fn honeybeepf_gpu_open_enter(ctx: TracePointContext) -> u32 {
    emit_gpu_event(&GPU_OPEN_EVENTS, &ctx)
}
