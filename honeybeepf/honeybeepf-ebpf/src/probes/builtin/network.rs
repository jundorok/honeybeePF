use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{bpf_probe_read_user},
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

use crate::probes::{emit_event, HoneyBeeEvent};

#[map]
static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

#[tracepoint]
pub fn honeybeepf(ctx: TracePointContext) -> u32 {
    emit_event::<ConnectionEvent>(&NETWORK_EVENTS, &ctx)
}

use honeybeepf_common::EventMetadata;

impl HoneyBeeEvent for ConnectionEvent {
    fn metadata(&mut self) -> &mut EventMetadata { &mut self.metadata }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        self.init_base();

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

        self.address_family = sa_family;
        self.dest_addr = 0;
        self.dest_port = 0;

        if sa_family == AF_INET {
            let sockaddr = unsafe {
                bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn)
                    .map_err(|_| 1u32)?
            };
            self.dest_port = sockaddr.sin_port;
            self.dest_addr = sockaddr.sin_addr;
        }

        Ok(())
    }
}
