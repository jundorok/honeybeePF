//! File access tracepoint for monitoring sensitive file accesses.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, FileAccessEvent, MAX_FILENAME_LEN, MAX_SUFFIX_LEN};

use crate::probes::{HoneyBeeEvent, emit_event};

const MAX_EVENT_SIZE: u32 = 1024 * 1024;
const MAX_WATCHED_PATHS: u32 = 64;
const MAX_WATCHED_SUFFIXES: u32 = 32;

#[map]
pub static FILE_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

/// Map of watched path hashes (exact match). Key is the hash of the path, value is 1 if watched.
#[map]
pub static WATCHED_PATHS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_WATCHED_PATHS, 0);

/// Map of watched suffix hashes (suffix match). Key is the hash of the suffix, value is suffix length.
#[map]
pub static WATCHED_SUFFIXES: HashMap<u64, u32> = HashMap::with_max_entries(MAX_WATCHED_SUFFIXES, 0);

/// Tracepoint for sys_enter_openat - fires when a process calls openat().
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<u32, u32> {
    // Read filename pointer from tracepoint context
    let filename_ptr: u64 = unsafe { ctx.read_at(24).map_err(|_| 1u32)? };
    if filename_ptr == 0 {
        return Ok(0);
    }

    // Read filename into stack buffer
    let mut filename_buf = [0u8; MAX_FILENAME_LEN];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename_buf) };

    // First, check exact path match
    let hash = simple_hash(&filename_buf);
    if unsafe { WATCHED_PATHS.get(&hash).is_some() } {
        // Exact match found, emit event
        return Ok(emit_event::<TracePointContext, FileAccessEvent>(
            &FILE_ACCESS_EVENTS,
            ctx,
        ));
    }

    // Second, check suffix match
    if check_suffix_match(&filename_buf) {
        return Ok(emit_event::<TracePointContext, FileAccessEvent>(
            &FILE_ACCESS_EVENTS,
            ctx,
        ));
    }

    // No match, skip
    Ok(0)
}

/// Check if filename ends with any watched suffix
#[inline(always)]
fn check_suffix_match(filename: &[u8; MAX_FILENAME_LEN]) -> bool {
    // Find the length of the filename
    let mut filename_len: usize = 0;
    while filename_len < MAX_FILENAME_LEN && filename[filename_len] != 0 {
        filename_len += 1;
    }

    if filename_len == 0 {
        return false;
    }

    // Try different suffix lengths (from MAX_SUFFIX_LEN down to 1)
    // We check common suffix lengths that might be in the map
    let mut suffix_len: usize = if filename_len < MAX_SUFFIX_LEN {
        filename_len
    } else {
        MAX_SUFFIX_LEN
    };

    while suffix_len > 0 {
        if suffix_len <= filename_len {
            // Extract suffix and hash it
            let start = filename_len - suffix_len;
            let suffix_hash = hash_slice(filename, start, suffix_len);

            // Check if this suffix is in the watched suffixes map
            if let Some(&stored_len) = unsafe { WATCHED_SUFFIXES.get(&suffix_hash) } {
                if stored_len as usize == suffix_len {
                    return true;
                }
            }
        }
        suffix_len -= 1;
    }

    false
}

/// Hash a slice of the filename buffer
#[inline(always)]
fn hash_slice(data: &[u8; MAX_FILENAME_LEN], start: usize, len: usize) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    let mut i = 0;
    while i < len && (start + i) < MAX_FILENAME_LEN {
        let b = data[start + i];
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        i += 1;
    }
    hash
}

/// Simple FNV-1a style hash for path matching
#[inline(always)]
fn simple_hash(data: &[u8; MAX_FILENAME_LEN]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
    let mut i = 0;
    while i < MAX_FILENAME_LEN {
        let b = data[i];
        if b == 0 {
            break;
        }
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime
        i += 1;
    }
    hash
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
            let _ =
                unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, filename_slice) };
        }

        Ok(())
    }
}
