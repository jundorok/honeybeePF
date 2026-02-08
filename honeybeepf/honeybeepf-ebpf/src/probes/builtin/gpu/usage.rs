//! GPU device open/close tracking probes.
//!
//! Monitors GPU device file operations to track which processes are using GPUs.

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, GpuCloseEvent, GpuFdInfo, GpuOpenEvent, PendingGpuOpen};

use super::utils::get_gpu_index;
use crate::probes::{
    HoneyBeeEvent,
    builtin::syscall_types::{SysEnterClose, SysEnterOpenat, SysExitOpenat},
};

const MAX_EVENT_SIZE: u32 = 1024 * 1024;
const MAX_PENDING_OPENS: u32 = 10240;
const MAX_GPU_FDS: u32 = 10240;

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

/// Map to store pending GPU opens (key: tid, value: PendingGpuOpen)
#[map]
pub static PENDING_GPU_OPENS: HashMap<u64, PendingGpuOpen> =
    HashMap::with_max_entries(MAX_PENDING_OPENS, 0);

/// Map to track GPU file descriptors (key: pid << 32 | fd, value: GpuFdInfo)
#[map]
pub static GPU_FD_MAP: HashMap<u64, GpuFdInfo> = HashMap::with_max_entries(MAX_GPU_FDS, 0);

impl HoneyBeeEvent<TracePointContext> for GpuOpenEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, _ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();
        Ok(())
    }
}

impl HoneyBeeEvent<TracePointContext> for GpuCloseEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, _ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();
        Ok(())
    }
}

/// sys_enter_openat: Check if GPU device and store pending info
#[tracepoint]
pub fn honeybeepf_gpu_open_enter(ctx: TracePointContext) -> u32 {
    match try_gpu_open_enter(&ctx) {
        Ok(_) => EmitGpuStatus::Success as u32,
        Err(e) => e,
    }
}

fn try_gpu_open_enter(ctx: &TracePointContext) -> Result<(), u32> {
    let header_ptr = ctx.as_ptr() as *const SysEnterOpenat;

    // Read filename pointer
    let filename_ptr: u64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).filename) as *const u64)
            .map_err(|_| EmitGpuStatus::Failure as u32)?
    };
    if filename_ptr == 0 {
        return Err(EmitGpuStatus::Failure as u32);
    }

    // Read filename
    let mut filename_buf: [u8; 64] = [0u8; 64];
    let filename_len = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename_buf)
            .map_err(|_| EmitGpuStatus::Failure as u32)?
            .len()
    };

    // Check if GPU device
    let gpu_index = get_gpu_index(&filename_buf[..filename_len]);
    if gpu_index < 0 {
        return Err(EmitGpuStatus::NotGpuDevice as u32);
    }

    // Read flags
    let flags: i64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).flags) as *const i64)
            .map_err(|_| EmitGpuStatus::Failure as u32)?
    };

    // Store pending open info
    let tid = ctx.tgid() as u64;
    let pending = PendingGpuOpen {
        gpu_index,
        flags: flags as i32,
        filename: filename_buf,
    };

    PENDING_GPU_OPENS
        .insert(&tid, &pending, 0)
        .map_err(|_| EmitGpuStatus::Failure as u32)?;

    Ok(())
}

/// sys_exit_openat: Get fd and emit open event
#[tracepoint]
pub fn honeybeepf_gpu_open_exit(ctx: TracePointContext) -> u32 {
    match try_gpu_open_exit(&ctx) {
        Ok(_) => EmitGpuStatus::Success as u32,
        Err(_) => EmitGpuStatus::Success as u32, // Silent fail for non-pending opens
    }
}

fn try_gpu_open_exit(ctx: &TracePointContext) -> Result<(), u32> {
    let tid = ctx.tgid() as u64;

    // Check if we have a pending GPU open for this thread
    let pending = unsafe {
        PENDING_GPU_OPENS
            .get(&tid)
            .ok_or(EmitGpuStatus::NotGpuDevice as u32)?
    };

    // Read return value (fd)
    let header_ptr = ctx.as_ptr() as *const SysExitOpenat;
    let fd: i64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).ret) as *const i64)
            .map_err(|_| EmitGpuStatus::Failure as u32)?
    };

    // Remove pending entry
    let _ = PENDING_GPU_OPENS.remove(&tid);

    // If open failed, don't emit event
    if fd < 0 {
        return Err(EmitGpuStatus::Failure as u32);
    }

    let pid = ctx.tgid();

    // Store fd -> gpu_index mapping for close tracking
    let fd_key = ((pid as u64) << 32) | (fd as u32 as u64);
    let fd_info = GpuFdInfo {
        gpu_index: pending.gpu_index,
        _pad: 0,
    };
    let _ = GPU_FD_MAP.insert(&fd_key, &fd_info, 0);

    // Emit GPU open event
    if let Some(mut slot) = GPU_OPEN_EVENTS.reserve::<GpuOpenEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };

        if event.fill(ctx).is_err() {
            slot.discard(0);
            return Err(EmitGpuStatus::Failure as u32);
        }

        event.gpu_index = pending.gpu_index;
        event.fd = fd as i32;
        event.flags = pending.flags;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        event.filename = pending.filename;

        slot.submit(0);
    }

    Ok(())
}

/// sys_enter_close: Check if GPU fd and emit close event
#[tracepoint]
pub fn honeybeepf_gpu_close(ctx: TracePointContext) -> u32 {
    match try_gpu_close(&ctx) {
        Ok(_) => EmitGpuStatus::Success as u32,
        Err(_) => EmitGpuStatus::Success as u32, // Silent fail for non-GPU fds
    }
}

fn try_gpu_close(ctx: &TracePointContext) -> Result<(), u32> {
    let header_ptr = ctx.as_ptr() as *const SysEnterClose;

    // Read fd being closed
    let fd: i64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(&((*header_ptr).fd) as *const i64)
            .map_err(|_| EmitGpuStatus::Failure as u32)?
    };

    if fd < 0 {
        return Err(EmitGpuStatus::NotGpuDevice as u32);
    }

    let pid = ctx.tgid();
    let fd_key = ((pid as u64) << 32) | (fd as u32 as u64);

    // Check if this fd is a GPU device
    let fd_info = unsafe {
        GPU_FD_MAP
            .get(&fd_key)
            .ok_or(EmitGpuStatus::NotGpuDevice as u32)?
    };

    let gpu_index = fd_info.gpu_index;

    // Remove from GPU fd map
    let _ = GPU_FD_MAP.remove(&fd_key);

    // Emit GPU close event
    if let Some(mut slot) = GPU_CLOSE_EVENTS.reserve::<GpuCloseEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };

        if event.fill(ctx).is_err() {
            slot.discard(0);
            return Err(EmitGpuStatus::Failure as u32);
        }

        event.gpu_index = gpu_index;
        event.fd = fd as i32;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

        slot.submit(0);
    }

    Ok(())
}
