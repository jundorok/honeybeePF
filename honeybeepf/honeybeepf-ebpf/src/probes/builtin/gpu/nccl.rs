use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use honeybeepf_common::{EventMetadata, NcclEvent, NcclOpType, PendingNcclOp};

use crate::probes::HoneyBeeEvent;

const MAX_EVENT_SIZE: u32 = 1024 * 1024;
const MAX_PENDING_OPS: u32 = 10240;

#[map]
pub static NCCL_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_EVENT_SIZE, 0);

#[map]
pub static PENDING_NCCL_OPS: HashMap<u64, PendingNcclOp> =
    HashMap::with_max_entries(MAX_PENDING_OPS, 0);

impl HoneyBeeEvent<RetProbeContext> for NcclEvent {
    fn metadata(&mut self) -> &mut EventMetadata {
        &mut self.metadata
    }

    fn fill(&mut self, _ctx: &RetProbeContext) -> Result<(), u32> {
        self.init_base();
        Ok(())
    }
}

// ===== ncclAllReduce =====
#[uprobe]
pub fn nccl_allreduce_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry(&ctx, NcclOpType::AllReduce as u8, true) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_allreduce_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::AllReduce as u8)
}

// ===== ncclBroadcast =====
// signature: ncclBroadcast(const void* sendbuff, void* recvbuff,
//                          size_t count, ncclDataType_t datatype,
//                          int root, ncclComm_t comm, cudaStream_t stream)

#[uprobe]
pub fn nccl_broadcast_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry(&ctx, NcclOpType::Broadcast as u8, true) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_broadcast_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::Broadcast as u8)
}

// ===== ncclAllGather =====
// signature: ncclAllGather(const void* sendbuff, void* recvbuff,
//                          size_t sendcount, ncclDataType_t datatype,
//                          ncclComm_t comm, cudaStream_t stream)

#[uprobe]
pub fn nccl_allgather_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry(&ctx, NcclOpType::AllGather as u8, true) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_allgather_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::AllGather as u8)
}

// ===== ncclReduceScatter =====
// signature: ncclReduceScatter(const void* sendbuff, void* recvbuff,
//                              size_t recvcount, ncclDataType_t datatype,
//                              ncclRedOp_t op, ncclComm_t comm,
//                              cudaStream_t stream)

#[uprobe]
pub fn nccl_reducescatter_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry(&ctx, NcclOpType::ReduceScatter as u8, true) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_reducescatter_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::ReduceScatter as u8)
}

// ===== ncclSend =====
// signature: ncclSend(const void* sendbuff, size_t count,
//                     ncclDataType_t datatype, int peer,
//                     ncclComm_t comm, cudaStream_t stream)

#[uprobe]
pub fn nccl_send_enter(ctx: ProbeContext) -> u32 {
    // ncclSend: count is arg1, datatype is arg2
    match try_nccl_entry_p2p(&ctx, NcclOpType::Send as u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_send_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::Send as u8)
}

// ===== ncclRecv =====
// signature: ncclRecv(void* recvbuff, size_t count,
//                     ncclDataType_t datatype, int peer,
//                     ncclComm_t comm, cudaStream_t stream)

#[uprobe]
pub fn nccl_recv_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry_p2p(&ctx, NcclOpType::Recv as u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_recv_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::Recv as u8)
}

// ===== ncclGroupStart / ncclGroupEnd =====
// Used to batch multiple NCCL operations

#[uprobe]
pub fn nccl_group_start_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry_simple(&ctx, NcclOpType::GroupStart as u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_group_start_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::GroupStart as u8)
}

#[uprobe]
pub fn nccl_group_end_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry_simple(&ctx, NcclOpType::GroupEnd as u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_group_end_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::GroupEnd as u8)
}

// ===== ncclGetVersion (for testing without GPU) =====
// signature: ncclGetVersion(int* version)

#[uprobe]
pub fn nccl_get_version_enter(ctx: ProbeContext) -> u32 {
    match try_nccl_entry_simple(&ctx, NcclOpType::GetVersion as u8) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[uretprobe]
pub fn nccl_get_version_exit(ctx: RetProbeContext) -> u32 {
    emit_nccl_event(&ctx, NcclOpType::GetVersion as u8)
}

// ===== Common entry logic =====

/// Entry for collective operations with count and datatype args
/// (AllReduce, Broadcast, AllGather, ReduceScatter)
#[inline(always)]
fn try_nccl_entry(ctx: &ProbeContext, op_type: u8, _has_count: bool) -> Result<(), u32> {
    let tid = bpf_get_current_pid_tgid();

    // For collective ops: arg2 = count, arg3 = datatype
    let count: u64 = ctx.arg(2).unwrap_or(0);
    let datatype: u32 = ctx.arg(3).unwrap_or(0);
    let datatype_size = nccl_datatype_to_bytes(datatype);

    let pending = PendingNcclOp {
        op_type,
        _pad: [0; 3],
        count,
        datatype_size,
        _pad2: 0,
        start_ns: unsafe { bpf_ktime_get_ns() },
    };

    PENDING_NCCL_OPS
        .insert(&tid, &pending, 0)
        .map_err(|_| 1u32)?;

    Ok(())
}

/// Entry for P2P operations (Send, Recv) - count is arg1, datatype is arg2
#[inline(always)]
fn try_nccl_entry_p2p(ctx: &ProbeContext, op_type: u8) -> Result<(), u32> {
    let tid = bpf_get_current_pid_tgid();

    let count: u64 = ctx.arg(1).unwrap_or(0);
    let datatype: u32 = ctx.arg(2).unwrap_or(0);
    let datatype_size = nccl_datatype_to_bytes(datatype);

    let pending = PendingNcclOp {
        op_type,
        _pad: [0; 3],
        count,
        datatype_size,
        _pad2: 0,
        start_ns: unsafe { bpf_ktime_get_ns() },
    };

    PENDING_NCCL_OPS
        .insert(&tid, &pending, 0)
        .map_err(|_| 1u32)?;

    Ok(())
}

/// Entry for simple operations without count/datatype (GroupStart, GroupEnd, GetVersion)
#[inline(always)]
fn try_nccl_entry_simple(ctx: &ProbeContext, op_type: u8) -> Result<(), u32> {
    let tid = bpf_get_current_pid_tgid();
    let _ = ctx; // unused but kept for consistency

    let pending = PendingNcclOp {
        op_type,
        _pad: [0; 3],
        count: 0,
        datatype_size: 0,
        _pad2: 0,
        start_ns: unsafe { bpf_ktime_get_ns() },
    };

    PENDING_NCCL_OPS
        .insert(&tid, &pending, 0)
        .map_err(|_| 1u32)?;

    Ok(())
}

// ===== Common exit logic =====

/// Emit NCCL event on function exit. Always clears pending state.
#[inline(always)]
fn emit_nccl_event(ctx: &RetProbeContext, op_type: u8) -> u32 {
    let tid = bpf_get_current_pid_tgid();

    let pending = match unsafe { PENDING_NCCL_OPS.get(&tid) } {
        Some(p) => *p,
        None => {
            // No pending op found - entry probe didn't fire or was cleaned up
            return 0;
        }
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let duration_ns = now.saturating_sub(pending.start_ns);

    // Read return value (ncclResult_t: 0 = success)
    let ret_code: i32 = ctx.ret().unwrap_or(-1);

    // Always clean up pending state
    let _ = PENDING_NCCL_OPS.remove(&tid);

    if let Some(mut slot) = NCCL_EVENTS.reserve::<NcclEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };

        if event.fill(ctx).is_err() {
            slot.discard(0);
            return 1;
        }

        event.op_type = op_type;
        event.ret_code = ret_code;
        event.count = pending.count;
        event.datatype_size = pending.datatype_size;
        event.duration_ns = duration_ns;
        event.bytes_transferred = pending.count * pending.datatype_size as u64;
        event.comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

        slot.submit(0);
    }

    0
}

/// Convert NCCL datatype enum to byte size
#[inline(always)]
fn nccl_datatype_to_bytes(dt: u32) -> u32 {
    // NCCL datatype values from nccl.h
    match dt {
        0 => 1,  // ncclInt8 / ncclChar
        1 => 1,  // ncclUint8
        2 => 4,  // ncclInt32 / ncclInt
        3 => 4,  // ncclUint32
        4 => 8,  // ncclInt64
        5 => 8,  // ncclUint64
        6 => 2,  // ncclFloat16 / ncclHalf
        7 => 4,  // ncclFloat32 / ncclFloat
        8 => 8,  // ncclFloat64 / ncclDouble
        9 => 2,  // ncclBfloat16
        10 => 1, // ncclFp8E4M3
        11 => 1, // ncclFp8E5M2
        _ => 4,  // Default to 4 bytes (float)
    }
}
