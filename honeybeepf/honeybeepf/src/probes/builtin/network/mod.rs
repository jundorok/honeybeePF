//! Network observability probes.
//!
//! ## Probes
//! - **TcpConnectProbe**: TCP connection tracking and latency measurement
//! - **TcpRetransProbe**: TCP retransmission monitoring for network quality
//! - **DnsProbe**: DNS query tracking via libc hooks
//!
//! ## Why eBPF for Network?
//! - See failed connections (not just established ones)
//! - Kernel-level timestamps for accurate latency
//! - No application modification required
//! - Works with any language/runtime

pub mod dns;
pub mod tcp_connect;
pub mod tcp_retrans;

pub use dns::DnsProbe;
pub use tcp_connect::TcpConnectProbe;
pub use tcp_retrans::TcpRetransProbe;
