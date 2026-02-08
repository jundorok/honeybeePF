use std::collections::HashSet;

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::probes::discovery;

/// SSL library pattern for libssl and libcrypto.
static SSL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"libssl\.so\..*|libcrypto\.so\..*").unwrap());

/// Find all SSL libraries across running processes and system defaults.
pub fn find_all_targets() -> Result<HashSet<String>> {
    discovery::find_libraries_all(&SSL_PATTERN, Some("libssl.so"))
}

/// Find SSL libraries for specific PIDs only (for re-discovery).
pub fn find_targets_for_pids(pids: &[u32]) -> Result<HashSet<String>> {
    discovery::find_libraries_for_pids(pids, &SSL_PATTERN)
}
