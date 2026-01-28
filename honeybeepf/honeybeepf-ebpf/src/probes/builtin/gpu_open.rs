use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, GpuCloseEvent, GpuFdInfo, GpuFdKey, GpuOpenEvent, PendingGpuOpen};

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

#[map]
pub static GPU_CLOSE_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

/// Temporary storage: pid_tgid -> PendingGpuOpen (for enter->exit matching)
#[map]
pub static PENDING_GPU_OPENS: LruHashMap<u64, PendingGpuOpen> = LruHashMap::with_max_entries(1024, 0);

/// Track open GPU fds: (pid, fd) -> GpuFdInfo
#[map]
pub static GPU_FDS: LruHashMap<GpuFdKey, GpuFdInfo> = LruHashMap::with_max_entries(1024, 0);


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

#[repr(C)]
struct SysExitOpenat {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    __syscall_nr: i32,
    _pad: i32,
    ret: i64,
}

#[repr(C)]
struct SysEnterClose {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    __syscall_nr: i32,
    _pad: i32,
    fd: i64,
}

/// sys_enter_openat: Check if GPU device, store pending info
#[tracepoint]
pub fn honeybeepf_gpu_open_enter(ctx: TracePointContext) -> u32 {
    let header_ptr = ctx.as_ptr() as *const SysEnterOpenat;
    
    // Read filename pointer
    let filename_ptr: u64 = match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).filename) as *const u64)
    } {
        Ok(ptr) => ptr,
        Err(_) => return EmitGpuStatus::Failure as u32,
    };
    
    if filename_ptr == 0 {
        return EmitGpuStatus::Failure as u32;
    }

    // Read filename
    let mut filename_buf: [u8; 64] = [0u8; 64];
    let filename_len = match unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename_buf)
    } {
        Ok(s) => s.len(),
        Err(_) => return EmitGpuStatus::Failure as u32,
    };

    // Check if it's a GPU device
    let gpu_index = get_gpu_index(&filename_buf[..filename_len]);
    if gpu_index < 0 {
        return EmitGpuStatus::NotGpuDevice as u32; // Not a GPU, ignore
    }

    // Read flags
    let flags: i64 = match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).flags) as *const i64)
    } {
        Ok(f) => f,
        Err(_) => return EmitGpuStatus::Failure as u32,
    };

    // Store pending open info (will be completed in sys_exit_openat)
    let pid_tgid = bpf_get_current_pid_tgid();
    let mut pending = PendingGpuOpen {
        gpu_index,
        flags: flags as i32,
        filename: [0u8; 64],
    };
    
    // Copy filename
    let copy_len = if filename_len < 64 { filename_len } else { 63 };
    let mut i = 0;
    while i < copy_len {
        pending.filename[i] = filename_buf[i];
        i += 1;
    }

    let _ = PENDING_GPU_OPENS.insert(&pid_tgid, &pending, 0);
    
    EmitGpuStatus::Success as u32
}

/// sys_exit_openat: Get fd, emit open event, store in GPU_FDS map
#[tracepoint]
pub fn honeybeepf_gpu_open_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check if we have a pending GPU open for this thread
    let pending = match unsafe { PENDING_GPU_OPENS.get(&pid_tgid) } {
        Some(p) => *p,
        None => return EmitGpuStatus::Success as u32, // Not a GPU open, ignore
    };

    // Remove from pending
    let _ = PENDING_GPU_OPENS.remove(&pid_tgid);

    // Read return value (fd)
    let header_ptr = ctx.as_ptr() as *const SysExitOpenat;
    let fd: i64 = match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).ret) as *const i64)
    } {
        Ok(f) => f,
        Err(_) => return EmitGpuStatus::Failure as u32,
    };

    // If open failed (fd < 0), don't track
    if fd < 0 {
        return EmitGpuStatus::Success as u32;
    }

    // Store in GPU_FDS map for close tracking
    let fd_key = GpuFdKey {
        pid,
        fd: fd as i32,
    };
    let fd_info = GpuFdInfo {
        gpu_index: pending.gpu_index,
        _pad: 0,
    };
    let _ = GPU_FDS.insert(&fd_key, &fd_info, 0);

    // Emit GPU open event
    if let Some(mut slot) = GPU_OPEN_EVENTS.reserve::<GpuOpenEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };
        event.init_base();
        event.gpu_index = pending.gpu_index;
        event.fd = fd as i32;
        event.flags = pending.flags;
        event.comm = [0u8; 16];
        event.filename = pending.filename;
        slot.submit(0);
    }

    EmitGpuStatus::Success as u32
}

/// sys_enter_close: Check if GPU fd, emit close event, remove from map
#[tracepoint]
pub fn honeybeepf_gpu_close(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Read fd being closed
    let header_ptr = ctx.as_ptr() as *const SysEnterClose;
    let fd: i64 = match unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).fd) as *const i64)
    } {
        Ok(f) => f,
        Err(_) => return EmitGpuStatus::Failure as u32,
    };

    // Check if this fd is a GPU fd
    let fd_key = GpuFdKey {
        pid,
        fd: fd as i32,
    };
    
    let gpu_info = match unsafe { GPU_FDS.get(&fd_key) } {
        Some(info) => *info,
        None => return EmitGpuStatus::Success as u32, // Not a GPU fd, ignore
    };

    // Remove from tracking map
    let _ = GPU_FDS.remove(&fd_key);

    // Emit GPU close event
    if let Some(mut slot) = GPU_CLOSE_EVENTS.reserve::<GpuCloseEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };
        event.metadata = EventMetadata::default();
        unsafe {
            event.metadata.pid = pid;
            event.metadata.cgroup_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
            event.metadata.timestamp = aya_ebpf::helpers::bpf_ktime_get_ns();
        }
        event.gpu_index = gpu_info.gpu_index;
        event.fd = fd as i32;
        slot.submit(0);
    }

    EmitGpuStatus::Success as u32
}

// Keep HoneyBeeEvent impl for compatibility (though we don't use emit_gpu_event anymore)
impl HoneyBeeEvent for GpuOpenEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, _ctx: &TracePointContext) -> Result<(), u32> {
        // Not used in new implementation
        Ok(())
    }
}
