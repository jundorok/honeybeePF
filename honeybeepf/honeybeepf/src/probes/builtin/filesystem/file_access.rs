use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use log::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::probes::Probe;
use crate::telemetry;

/// File access event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub tid: u32,
    pub flags: u32,
    pub mode: u32,
    pub ino: u64,
    pub dev: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

pub struct FileAccessProbe {
    pub watched_paths: Vec<String>,
    running: Arc<AtomicBool>,
}

impl Default for FileAccessProbe {
    fn default() -> Self {
        Self {
            watched_paths: vec![
                "/etc/passwd".into(),
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
                "/root/.ssh".into(),
            ],
            running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Probe for FileAccessProbe {
    fn attach(&self, bpf: &mut Ebpf) -> Result<()> {
        let program: &mut TracePoint = bpf
            .program_mut("sys_enter_openat")
            .context("Failed to find sys_enter_openat program")?
            .try_into()
            .context("Program is not a TracePoint")?;

        program.load()?;
        program
            .attach("syscalls", "sys_enter_openat")
            .context("Failed to attach sys_enter_openat tracepoint")?;

        info!("Attached tracepoint: syscalls/sys_enter_openat");
        info!("Watching {} sensitive paths", self.watched_paths.len());

        self.spawn_event_handler(bpf)?;

        telemetry::record_active_probe("file_access", 1);
        info!("FileAccessProbe attached successfully");

        Ok(())
    }
}

impl FileAccessProbe {
    fn spawn_event_handler(&self, bpf: &mut Ebpf) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            bpf.take_map("FILE_ACCESS_EVENTS")
                .context("Failed to find FILE_ACCESS_EVENTS map")?,
        )?;

        let running = self.running.clone();

        std::thread::spawn(move || {
            let mut ring_buf = ring_buf;

            while running.load(Ordering::Relaxed) {
                if let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<FileAccessEvent>() {
                        let event: FileAccessEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const FileAccessEvent)
                        };

                        let comm = std::str::from_utf8(&event.comm)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let filename = std::str::from_utf8(&event.filename)
                            .unwrap_or("<invalid>")
                            .trim_matches(char::from(0));

                        let flags_str = format_open_flags(event.flags);

                        info!(
                            "FILE_ACCESS pid={} comm={} file={} flags={} cgroup={}",
                            event.pid, comm, filename, flags_str, event.cgroup_id,
                        );

                        telemetry::record_file_access_event(
                            filename,
                            &flags_str,
                            comm,
                            event.cgroup_id,
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        Ok(())
    }
}

fn format_open_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    // Access mode
    match flags & 0b11 {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => {}
    }

    // Common flags
    if flags & 0o100 != 0 {
        parts.push("O_CREAT");
    }
    if flags & 0o1000 != 0 {
        parts.push("O_TRUNC");
    }
    if flags & 0o2000 != 0 {
        parts.push("O_APPEND");
    }

    parts.join("|")
}
