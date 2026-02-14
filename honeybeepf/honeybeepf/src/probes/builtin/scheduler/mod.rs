//! Scheduler observability probes.
//!
//! ## Probes
//! - **RunqueueLatencyProbe**: Measure time waiting in CPU run queue
//! - **OffCpuProbe**: Analyze why tasks are blocked (off-CPU)
//!
//! ## Why eBPF for Scheduler?
//! - See inside kernel scheduler (invisible to profilers)
//! - Identify CPU contention and noisy neighbors
//! - Debug "low CPU but slow" problems (off-CPU time)
//! - Track who woke a blocked task

pub mod offcpu;
pub mod runqueue;

pub use offcpu::OffCpuProbe;
pub use runqueue::RunqueueLatencyProbe;
