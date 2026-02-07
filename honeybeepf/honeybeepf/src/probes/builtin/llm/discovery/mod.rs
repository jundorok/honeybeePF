pub mod dynamic;
pub mod binary;

use anyhow::Result;
use std::collections::HashSet;

/// Facade for target discovery — full scan of all processes (used at startup).
pub fn find_all_targets() -> Result<HashSet<String>> {
    let mut targets = HashSet::new();

    if let Ok(libs) = dynamic::find_ssl_libraries() {
        targets.extend(libs);
    }

    Ok(targets)
}

/// Targeted scan of specific PIDs only (used for re-discovery).
pub fn find_targets_for_pids(pids: &[u32]) -> Result<HashSet<String>> {
    let mut targets = HashSet::new();

    if let Ok(libs) = dynamic::find_ssl_for_pids(pids) {
        targets.extend(libs);
    }

    Ok(targets)
}
