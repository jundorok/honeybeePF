//! GPU device path utilities.
//!
//! Helper functions to parse GPU device paths and extract GPU indices.

pub const NVIDIA_PREFIX: &[u8] = b"/dev/nvidia";
pub const DRI_RENDER_PREFIX: &[u8] = b"/dev/dri/renderD";
pub const DRI_CARD_PREFIX: &[u8] = b"/dev/dri/card";

pub fn starts_with(filename: &[u8], prefix: &[u8]) -> bool {
    if filename.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if filename[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn parse_number_at(bytes: &[u8], start: usize) -> Option<(i32, usize)> {
    if start >= bytes.len() || bytes[start] < b'0' || bytes[start] > b'9' {
        return None;
    }

    let mut num: i32 = 0;
    let mut pos = start;
    while pos < bytes.len() && bytes[pos] >= b'0' && bytes[pos] <= b'9' {
        num = num * 10 + (bytes[pos] - b'0') as i32;
        pos += 1;
    }
    Some((num, pos))
}

/// Extract GPU index from NVIDIA device path like /dev/nvidia0, /dev/nvidia1
/// Returns -1 for /dev/nvidiactl, /dev/nvidia-uvm, etc.
fn extract_nvidia_gpu_index(filename: &[u8]) -> i32 {
    const PREFIX_LEN: usize = 11; // "/dev/nvidia"

    match parse_number_at(filename, PREFIX_LEN) {
        Some((index, end_pos)) => {
            // Make sure string ends after the number (or is null-terminated)
            if end_pos < filename.len() && filename[end_pos] != 0 {
                -1
            } else {
                index
            }
        }
        None => -1,
    }
}

/// Extract GPU index from DRI device path like /dev/dri/renderD128, /dev/dri/card0
fn extract_dri_gpu_index(filename: &[u8]) -> i32 {
    if starts_with(filename, DRI_RENDER_PREFIX) {
        const PREFIX_LEN: usize = 16; // "/dev/dri/renderD"
        match parse_number_at(filename, PREFIX_LEN) {
            // renderD devices start at 128, so subtract 128 to get logical index
            Some((index, _)) => index - 128,
            None => -1,
        }
    } else if starts_with(filename, DRI_CARD_PREFIX) {
        const PREFIX_LEN: usize = 13; // "/dev/dri/card"
        match parse_number_at(filename, PREFIX_LEN) {
            Some((index, _)) => index,
            None => -1,
        }
    } else {
        -1
    }
}

/// Check if a filename is a GPU device and return the GPU index
/// Returns -1 if not a GPU device
pub fn get_gpu_index(filename: &[u8]) -> i32 {
    if starts_with(filename, NVIDIA_PREFIX) {
        return extract_nvidia_gpu_index(filename);
    }

    if starts_with(filename, DRI_CARD_PREFIX) || starts_with(filename, DRI_RENDER_PREFIX) {
        return extract_dri_gpu_index(filename);
    }

    -1
}
