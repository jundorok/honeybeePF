//! GPU-related userspace probe handlers.
//!
//! This module contains all userspace handlers for GPU monitoring:
//! - `usage`: GPU device open/close event handling
//! - `nccl`: NCCL collective communication event handling

pub mod nccl;
pub mod usage;
