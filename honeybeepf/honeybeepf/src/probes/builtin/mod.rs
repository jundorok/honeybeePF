//! Built-in eBPF probes for system observability.

pub mod network;
pub mod filesystem;
pub mod scheduler;

// GPU module disabled - use NVIDIA tools instead
// pub mod gpu;

pub use network::{TcpConnectProbe, TcpRetransProbe, DnsProbe};
pub use filesystem::{VfsLatencyProbe, FileAccessProbe};
pub use scheduler::{RunqueueLatencyProbe, OffCpuProbe};