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

pub mod network;
pub mod filesystem;
pub mod scheduler;

// GPU module disabled - use NVIDIA tools (DCGM, nsys) instead
// pub mod gpu;

// Re-export all probes for convenience
pub use network::{TcpConnectProbe, TcpRetransProbe, DnsProbe};
pub use filesystem::{VfsLatencyProbe, FileAccessProbe};
pub use scheduler::{RunqueueLatencyProbe, OffCpuProbe};