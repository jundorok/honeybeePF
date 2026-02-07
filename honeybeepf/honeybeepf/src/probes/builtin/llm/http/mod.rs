//! HTTP parsing for LLM API traffic
//!
//! This module handles HTTP/1.1 and HTTP/2 parsing to extract
//! LLM request/response data.

pub mod protocol;
pub mod utils;
pub mod providers;

// Re-export main types
pub use protocol::{ProtocolParser, Http11Parser, Http2Parser};
pub use providers::{ProviderRegistry, ConfigurableProvider};
