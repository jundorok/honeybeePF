//! Built-in eBPF probes for system observability.
//!
//! ## Structure
//! ```
//! builtin/
//! ├── network/      # TCP, DNS, retransmission tracking
//! ├── filesystem/   # VFS latency, file access auditing
//! ├── scheduler/    # Runqueue latency, off-CPU analysis
//! └── gpu/          # (deprecated) Use NVIDIA tools instead
//! ```

pub mod filesystem;
pub mod network;
pub mod scheduler;

// GPU module disabled - use NVIDIA tools (DCGM, nsys) instead
// pub mod gpu;

// Re-export all probes for convenience
pub use filesystem::{FileAccessProbe, VfsLatencyProbe};
pub use network::{DnsProbe, TcpConnectProbe, TcpRetransProbe};
pub use scheduler::{OffCpuProbe, RunqueueLatencyProbe};
