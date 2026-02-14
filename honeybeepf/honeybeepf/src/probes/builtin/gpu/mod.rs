//! GPU probes - **DEPRECATED**
//!
//! GPU monitoring is better handled by NVIDIA tools:
//! - **DCGM**: Data Center GPU Manager for production monitoring
//! - **nsys**: Nsight Systems for profiling
//! - **nvidia-smi**: Quick GPU status checks
//! - **NCCL_DEBUG=INFO**: NCCL communication debugging
//!
//! eBPF cannot see GPU internals (SM utilization, memory bandwidth, etc.)
//! Only use eBPF for GPU if you need:
//! - Security auditing of /dev/nvidia* access
//! - Blocking unauthorized GPU access (LSM BPF)
//!
//! All GPU probes removed - use NVIDIA tools instead
