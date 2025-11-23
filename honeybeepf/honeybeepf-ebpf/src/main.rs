#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_get_current_cgroup_id},
};
use aya_log_ebpf::info;
use honeybeepf_common::ConnectionEvent;

const AF_INET: u16 = 2;

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[map]
static EVENTS: PerfEventArray<ConnectionEvent> = PerfEventArray::new(0);

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
        aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const u16)
            .map_err(|_| 1u32)?
    };

    let mut event = ConnectionEvent {
        pid,
        cgroup_id,
        timestamp,
        dest_addr: 0,
        dest_port: 0,
        address_family: sa_family,
    };

    if sa_family == AF_INET {
        let sockaddr: SockaddrIn = unsafe {
            aya_ebpf::helpers::bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn)
                .map_err(|_| 1u32)?
        };

        event.dest_port = sockaddr.sin_port;
        event.dest_addr = sockaddr.sin_addr;

        info!(
            &ctx,
            "Connection from PID {}: dest={}:{}", 
            pid,
            u32::from_be(sockaddr.sin_addr),
            u16::from_be(sockaddr.sin_port)
        );
    }

    EVENTS.output(&ctx, &event, 0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}