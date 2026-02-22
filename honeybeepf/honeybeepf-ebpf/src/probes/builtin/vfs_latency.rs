//! VFS latency kprobes for monitoring slow/large file system operations.
//!
//! Attaches to vfs_read and vfs_write to measure I/O latency.
//! 
//! For vfs_read, events are emitted only when:
//! - It's a regular file (not socket/pipe)
//! - AND (bytes >= MIN_BYTES OR latency >= threshold)
//!
//! For vfs_write, events are emitted when latency exceeds the configured threshold.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use honeybeepf_common::{MAX_FILENAME_LEN, VfsLatencyEvent};

const MAX_EVENT_SIZE: u32 = 1024 * 1024;
const MAX_ENTRIES: u32 = 10240;

/// Default threshold in nanoseconds (10ms)
const DEFAULT_THRESHOLD_NS: u64 = 10_000_000;

/// Minimum bytes for read to be interesting (1MB)
const MIN_READ_BYTES: u64 = 1024 * 1024;

/// VFS operation type constants
const VFS_OP_READ: u8 = 0;
const VFS_OP_WRITE: u8 = 1;

/// File mode mask for regular file check (S_IFREG = 0o100000)
const S_IFREG: u16 = 0o100000;
const S_IFMT: u16 = 0o170000;

#[map]
pub static VFS_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

/// Map to store start time and context for in-flight operations.
/// Key: tid (thread id), Value: (start_time_ns, op_type, file_ptr)
#[map]
static VFS_START: HashMap<u32, (u64, u8, u64)> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Configurable threshold in nanoseconds
#[map]
pub static VFS_THRESHOLD_NS: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

// ============================================================
// vfs_read probes (filtered: regular files + large/slow only)
// ============================================================

/// Entry probe for vfs_read
/// ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
#[kprobe]
pub fn vfs_read_entry(ctx: ProbeContext) -> u32 {
    match try_vfs_entry(&ctx, VFS_OP_READ) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Exit probe for vfs_read
#[kretprobe]
pub fn vfs_read_exit(ctx: RetProbeContext) -> u32 {
    match try_vfs_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// ============================================================
// vfs_write probes
// ============================================================

/// Entry probe for vfs_write
/// ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
#[kprobe]
pub fn vfs_write_entry(ctx: ProbeContext) -> u32 {
    match try_vfs_entry(&ctx, VFS_OP_WRITE) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// Exit probe for vfs_write
#[kretprobe]
pub fn vfs_write_exit(ctx: RetProbeContext) -> u32 {
    match try_vfs_exit(&ctx, VFS_OP_WRITE) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// ============================================================
// Common implementation
// ============================================================

#[inline(always)]
fn try_vfs_entry(ctx: &ProbeContext, op_type: u8) -> Result<u32, u32> {
    let tid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    let start_time = unsafe { bpf_ktime_get_ns() };

    // Get file pointer (first argument)
    let file_ptr: u64 = ctx.arg(0).ok_or(1u32)?;

    // Store start time, op type, and file pointer
    VFS_START
        .insert(&tid, &(start_time, op_type, file_ptr), 0)
        .map_err(|_| 1u32)?;

    Ok(0)
}

/// Special exit handler for vfs_read with size-first filtering
/// This reduces overhead by checking bytes/latency before doing expensive inode checks
#[inline(always)]
fn try_vfs_read_exit(ctx: &RetProbeContext) -> Result<u32, u32> {
    let tid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Look up start time
    let (start_time, stored_op, file_ptr) = match unsafe { VFS_START.get(&tid) } {
        Some(val) => *val,
        None => return Ok(0),
    };

    // Clean up the entry
    let _ = VFS_START.remove(&tid);

    // Verify operation type matches
    if stored_op != VFS_OP_READ {
        return Ok(0);
    }

    // Get return value (bytes read, or negative error)
    let ret: i64 = ctx.ret().unwrap_or(0);
    if ret < 0 {
        return Ok(0); // Ignore errors
    }
    let bytes = ret as u64;

    // Calculate latency
    let end_time = unsafe { bpf_ktime_get_ns() };
    let latency_ns = end_time.saturating_sub(start_time);

    // Get threshold (default 10ms)
    let threshold = match unsafe { VFS_THRESHOLD_NS.get(&0) } {
        Some(t) => *t,
        None => DEFAULT_THRESHOLD_NS,
    };

    // FAST PATH: Skip small and fast reads (99% of cases)
    // This check is cheap - just comparing already-computed values
    if bytes < MIN_READ_BYTES && latency_ns < threshold {
        return Ok(0);
    }

    // SLOW PATH: Only for large or slow reads, check if it's a regular file
    // This involves reading kernel memory, so we do it only when necessary
    if !is_regular_file(file_ptr) {
        return Ok(0);
    }

    // Reserve space in ring buffer
    let mut reservation = match VFS_EVENTS.reserve::<VfsLatencyEvent>(0) {
        Some(ptr) => ptr,
        None => return Ok(0),
    };

    let event = reservation.as_mut_ptr();

    // Fill metadata
    unsafe {
        (*event).metadata.pid = pid;
        (*event).metadata.timestamp = end_time;
        (*event).metadata.cgroup_id = 0;

        (*event).tid = tid;
        (*event).op_type = VFS_OP_READ;
        (*event).latency_ns = latency_ns;
        (*event).bytes = bytes;
        (*event).offset = 0;

        // Get comm
        if let Ok(comm) = bpf_get_current_comm() {
            (*event).comm = comm;
        }

        // Try to read filename from struct file
        read_filename_from_file(file_ptr, &mut (*event).filename);
    }

    reservation.submit(0);

    Ok(0)
}

#[inline(always)]
fn try_vfs_exit(ctx: &RetProbeContext, op_type: u8) -> Result<u32, u32> {
    let tid = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Look up start time
    let (start_time, stored_op, file_ptr) = match unsafe { VFS_START.get(&tid) } {
        Some(val) => *val,
        None => return Ok(0),
    };

    // Clean up the entry
    let _ = VFS_START.remove(&tid);

    // Verify operation type matches
    if stored_op != op_type {
        return Ok(0);
    }

    // Calculate latency
    let end_time = unsafe { bpf_ktime_get_ns() };
    let latency_ns = end_time.saturating_sub(start_time);

    // Get threshold (default 10ms)
    let threshold = match unsafe { VFS_THRESHOLD_NS.get(&0) } {
        Some(t) => *t,
        None => DEFAULT_THRESHOLD_NS,
    };

    // Only emit event if latency exceeds threshold
    if latency_ns < threshold {
        return Ok(0);
    }

    // Get return value (bytes read/written, or negative error)
    let ret: i64 = ctx.ret().unwrap_or(0);
    if ret < 0 {
        return Ok(0); // Ignore errors
    }
    let bytes = ret as u64;

    // Reserve space in ring buffer
    let mut reservation = match VFS_EVENTS.reserve::<VfsLatencyEvent>(0) {
        Some(ptr) => ptr,
        None => return Ok(0),
    };

    let event = reservation.as_mut_ptr();

    // Fill metadata
    unsafe {
        (*event).metadata.pid = pid;
        (*event).metadata.timestamp = end_time;
        (*event).metadata.cgroup_id = 0;

        (*event).tid = tid;
        (*event).op_type = op_type;
        (*event).latency_ns = latency_ns;
        (*event).bytes = bytes;
        (*event).offset = 0;

        // Get comm
        if let Ok(comm) = bpf_get_current_comm() {
            (*event).comm = comm;
        }

        // Try to read filename from struct file
        read_filename_from_file(file_ptr, &mut (*event).filename);
    }

    reservation.submit(0);

    Ok(0)
}

/// Check if file is a regular file (not socket, pipe, device, etc.)
/// Reads struct file -> f_inode -> i_mode and checks S_ISREG
#[inline(always)]
fn is_regular_file(file_ptr: u64) -> bool {
    // struct file offsets (kernel version dependent)
    // f_inode is typically at offset 32 on x86_64 (after f_path)
    const F_INODE_OFFSET: usize = 32;
    // i_mode is at offset 0 in struct inode
    const I_MODE_OFFSET: usize = 0;

    // Read inode pointer: file->f_inode
    let inode_ptr: u64 = match unsafe {
        bpf_probe_read_kernel((file_ptr + F_INODE_OFFSET as u64) as *const u64)
    } {
        Ok(ptr) => ptr,
        Err(_) => return false,
    };

    if inode_ptr == 0 {
        return false;
    }

    // Read i_mode: inode->i_mode
    let i_mode: u16 = match unsafe {
        bpf_probe_read_kernel((inode_ptr + I_MODE_OFFSET as u64) as *const u16)
    } {
        Ok(mode) => mode,
        Err(_) => return false,
    };

    // Check if it's a regular file: (i_mode & S_IFMT) == S_IFREG
    (i_mode & S_IFMT) == S_IFREG
}

/// Read filename from struct file -> f_path.dentry -> d_name
/// This is kernel version dependent but works on most modern kernels
#[inline(always)]
fn read_filename_from_file(file_ptr: u64, filename: &mut [u8; MAX_FILENAME_LEN]) {
    // struct file offsets (may vary by kernel version)
    // f_path is typically at offset 16 on x86_64
    // struct path { struct vfsmount *mnt; struct dentry *dentry; }
    // dentry is at offset 8 within path
    // d_name (struct qstr) contains the name

    const F_PATH_OFFSET: usize = 16; // offset of f_path in struct file
    const DENTRY_OFFSET: usize = 8; // offset of dentry in struct path
    const D_NAME_OFFSET: usize = 32; // offset of d_name in struct dentry
    const QSTR_NAME_OFFSET: usize = 8; // offset of name ptr in struct qstr

    // Read dentry pointer: file->f_path.dentry
    let dentry_ptr: u64 = match unsafe {
        bpf_probe_read_kernel(
            (file_ptr + F_PATH_OFFSET as u64 + DENTRY_OFFSET as u64) as *const u64,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => return,
    };

    if dentry_ptr == 0 {
        return;
    }

    // Read name pointer: dentry->d_name.name
    let name_ptr: u64 = match unsafe {
        bpf_probe_read_kernel(
            (dentry_ptr + D_NAME_OFFSET as u64 + QSTR_NAME_OFFSET as u64) as *const u64,
        )
    } {
        Ok(ptr) => ptr,
        Err(_) => return,
    };

    if name_ptr == 0 {
        return;
    }

    // Read the actual filename string using bpf_probe_read_kernel_str_bytes
    let _ = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, filename)
    };
}
