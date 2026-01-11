#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_ktime_get_ns,
        bpf_get_current_cgroup_id,
        bpf_probe_read_user,
    },
};
use honeybeepf_common::ConnectionEvent;

const AF_INET: u16 = 2;
const MAX_EVENT_SIZE: u32 = 1024 * 1024;

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

#[tracepoint]
pub fn honeybeepf(ctx: TracePointContext) -> u32 {
    match try_connect_trace(ctx) {
        Ok(()) => 0,
        Err(ret) => ret,
    }
}

fn try_connect_trace(ctx: TracePointContext) -> Result<(), u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let timestamp = unsafe { bpf_ktime_get_ns() };

    let sockaddr_ptr: u64 = unsafe {
        ctx.read_at(24).map_err(|_| 1u32)?
    };

    if sockaddr_ptr == 0 {
        return Err(1);
    }

    let sa_family: u16 = unsafe {
        bpf_probe_read_user(sockaddr_ptr as *const u16)
            .map_err(|_| 1u32)?
    };

    // Attempt to reserve a slot in the ring buffer
    if let Some(mut slot) = EVENTS.reserve::<ConnectionEvent>(0) {
        let event = { slot.as_mut_ptr() };
        
        // Initialize common event fields safely using the reserved slot
        unsafe {
            (*event).pid = pid;
            (*event).cgroup_id = cgroup_id;
            (*event).timestamp = timestamp;
            (*event).address_family = sa_family;
            (*event).dest_addr = 0;
            (*event).dest_port = 0;
        }

        if sa_family == AF_INET {
            // Read IPv4 specific data
            // Use a temporary variable to avoid returning early and leaking the slot
            let res = unsafe { 
                bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn) 
            };

            match res {
                Ok(sockaddr) => {
                    unsafe {
                        (*event).dest_port = sockaddr.sin_port;
                        (*event).dest_addr = sockaddr.sin_addr;
                    }
                }
                Err(_) => {
                    // If reading fails, we must still handle the slot. 
                    // Discarding is safer than submitting garbage data.
                    slot.discard(0);
                    return Err(1);
                }
            }
        }

        // Successfully filled the event, now submit it to userspace
        slot.submit(0);
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}