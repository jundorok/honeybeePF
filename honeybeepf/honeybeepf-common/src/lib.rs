#![no_std]

pub const MAX_SSL_BUF_SIZE: usize = 4096;

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
pub struct GpuOpenEvent {
    pub metadata: EventMetadata,
    pub gpu_index: i32,
    pub fd: i32,
    pub flags: i32,
    pub comm: [u8; 16],
    pub filename: [u8; 64],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GpuOpenEvent {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GpuCloseEvent {
    pub metadata: EventMetadata,
    pub gpu_index: i32,
    pub fd: i32,
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GpuCloseEvent {}

/// Pending GPU open info (stored between sys_enter_openat and sys_exit_openat)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingGpuOpen {
    pub gpu_index: i32,
    pub flags: i32,
    pub filename: [u8; 64],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PendingGpuOpen {}

/// GPU FD info (stored to track which fds are GPU devices)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GpuFdInfo {
    pub gpu_index: i32,
    pub _pad: i32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GpuFdInfo {}

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
    pub probe_gpu_usage: u8,
    pub probe_llm: u8,
    pub probe_interval: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommonConfig {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockIoEventType {
    Unknown = 0,
    Start = 1,
    Done = 2,
    // Add future types here as needed
}

impl From<u8> for BlockIoEventType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Start,
            2 => Self::Done,
            _ => Self::Unknown,
        }
    }
}

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
    pub event_type: u8, // Casts to BlockIoEventType
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockIoEvent {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmDirection {
    Read = 0,
    Write = 1,
    Handshake = 2,
    Unknown = 255,
}

impl From<u8> for LlmDirection {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Handshake,
            _ => Self::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LlmEvent {
    pub metadata: EventMetadata,
    pub is_handshake: u8, // 0 or 1 - separate from rw since handshake can occur during read/write
    pub rw: u8,           // Uses LlmDirection
    pub len: u32,
    pub buf_filled: u32,
    pub buf: [u8; MAX_SSL_BUF_SIZE],
    pub latency_ns: u64,
    pub comm: [u8; 16],
}

// Manual Default implementation for LlmEvent (derives don't work well with large arrays in no_std)
impl Default for LlmEvent {
    fn default() -> Self {
        Self {
            metadata: EventMetadata::default(),
            is_handshake: 0,
            rw: 0,
            len: 0,
            buf_filled: 0,
            buf: [0u8; MAX_SSL_BUF_SIZE],
            latency_ns: 0,
            comm: [0u8; 16],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LlmEvent {}

/// Lightweight event emitted on sched_process_exec to trigger SSL re-discovery.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExecEvent {
    pub pid: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
