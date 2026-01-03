#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionEvent {
    pub pid: u32,
    pub cgroup_id: u64,
    pub timestamp: u64,
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
    pub probe_interval: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommonConfig {}
