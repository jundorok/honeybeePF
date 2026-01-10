# Adding New Probes to HoneyBeePF

This guide outlines the steps to add a new eBPF tracepoint probe to the HoneyBeePF agent. The architecture involves three main components: data structure definition, kernel-side eBPF implementation, and userspace probe logic.

---

## 1. Define Common Data Structures
First, define the event struct that will be shared between the kernel and userspace.

**File:** `honeybeepf-common/src/lib.rs`

1.  Create a struct representing your event data.
2.  Include `EventMetadata` as the first field for standard metadata (PID, cgroup, timestamp).
3.  Implement `aya::Pod` for userspace compatibility.

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MyCustomEvent {
    pub metadata: EventMetadata, // Common fields (pid, cgroup_id, timestamp)
    pub my_field: u32,
    pub some_data: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MyCustomEvent {}
```

---

## 2. Kernel-Side Implementation
Implement the eBPF program that attaches to the tracepoint and emits events.

**Location:** `honeybeepf-ebpf/src/probes/custom/`

1.  **Create a new file** (e.g., `my_probe.rs`) and declare it in `mod.rs`.
2.  **Define the RingBuf map** to transport events.
3.  **Implement `HoneyBeeEvent`** for your struct.
4.  **Write the tracepoint function** using `emit_event`.

```rust
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use honeybeepf_common::{EventMetadata, MyCustomEvent};
use crate::probes::{emit_event, HoneyBeeEvent};

#[map]
const MAX_EVENT_SIZE: u32 = 1024 * 1024;

pub static MY_CUSTOM_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);


// 1. Implement the trait to populate your specific fields
impl HoneyBeeEvent for MyCustomEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, ctx: &TracePointContext) -> Result<(), u32> {
        // Init base metadata (pid, etc.) automatically
        self.init_base();
        
        // Populate your custom fields
        // Example: Reading a kernel integer argument
        self.my_field = unsafe { ctx.read_at(16).map_err(|_| 1u32)? };
        
        Ok(())
    }
}

// 2. Define the tracepoint program
#[tracepoint]
pub fn honeybeepf_my_probe(ctx: TracePointContext) -> u32 {
    // Generic helper handles reservation, filling, and submission
    emit_event::<MyCustomEvent>(&MY_CUSTOM_EVENTS, &ctx)
}
```

---

## 3. Userspace Implementation
Implement the userspace agent logic to attach the probe and consume events.

**Location:** `honeybeepf/src/probes/custom/`

1.  **Create a new file** (e.g., `my_probe.rs`) and declare it in `mod.rs`.
2.  **Define a struct** for your probe (e.g., `MyCustomProbe`).
3.  **Implement the `Probe` trait**.

```rust
use anyhow::Result;
use aya::Bpf;
use honeybeepf_common::MyCustomEvent;
use log::info;
use crate::probes::{attach_tracepoint, spawn_ringbuf_handler, Probe, TracepointConfig};

pub struct MyCustomProbe;

impl Probe for MyCustomProbe {
    fn attach(&self, bpf: &mut Bpf) -> Result<()> {
        info!("Attaching my custom probe...");

        // 1. Attach to the kernel tracepoint
        attach_tracepoint(
            bpf,
            TracepointConfig {
                program_name: "honeybeepf_my_probe", // Must match kernel function name
                category: "syscalls",                // Tracepoint category (e.g., /sys/kernel/debug/tracing/events/...)
                name: "sys_enter_openat",            // Tracepoint name
            },
        )?;

        // 2. Spawn a handler for the RingBuf
        spawn_ringbuf_handler(bpf, "MY_CUSTOM_EVENTS", |event: MyCustomEvent| {
            info!(
                "Event received: pid={} field={}",
                event.metadata.pid, event.my_field
            );
        })?;

        Ok(())
    }
}
```
