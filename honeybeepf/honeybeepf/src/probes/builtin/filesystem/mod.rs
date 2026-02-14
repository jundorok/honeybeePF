//! Filesystem observability probes.
//!
//! ## Probes
//! - **VfsLatencyProbe**: Measure read/write latency at VFS layer
//! - **FileAccessProbe**: Audit access to sensitive files
//!
//! ## Why eBPF for Filesystem?
//! - Pre-filter slow I/O in kernel (reduce noise)
//! - Works across all filesystems (ext4, xfs, nfs, etc.)
//! - Know exactly which file and process caused slow I/O
//! - Security auditing without auditd overhead

pub mod vfs_latency;
pub mod file_access;

pub use vfs_latency::VfsLatencyProbe;
pub use file_access::FileAccessProbe;
