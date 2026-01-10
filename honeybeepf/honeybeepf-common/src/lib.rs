#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EventMetadata {
    pub pid: u32,
    pub _pad: u32,
    pub cgroup_id: u64,
    pub timestamp: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventMetadata {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionEvent {
    pub metadata: EventMetadata,
    pub dest_addr: u32,
    pub dest_port: u16,
    pub address_family: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionEvent {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CommonConfig {
    pub probe_block_io: u8,
    pub probe_network_latency: u8,
    pub probe_interval: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommonConfig {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockIoEvent {
    pub metadata: EventMetadata,
    pub dev: u32,
    pub sector: u64,
    pub nr_sector: u32,
    pub bytes: u32,
    pub rwbs: [u8; 8],
    pub comm: [u8; 16],
    pub event_type: u8, // 1: start, 2: done
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockIoEvent {}
