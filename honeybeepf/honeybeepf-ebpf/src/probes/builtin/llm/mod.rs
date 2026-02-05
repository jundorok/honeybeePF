//! eBPF probes for SSL/TLS interception to capture LLM API traffic.
//!
//! Attaches uprobes to OpenSSL's SSL_read/SSL_write functions to capture
//! encrypted traffic after decryption, enabling LLM request/response monitoring.

use aya_ebpf::{
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use honeybeepf_common::{LlmEvent, LlmDirection};

pub mod maps;
mod helpers;

use maps::*;
use helpers::{Session, LlmEventExt, get_current_tid};


#[uprobe]
pub fn probe_ssl_rw_enter(ctx: ProbeContext) -> u32 {
    let tid = get_current_tid();
    Session::clear(tid);
    Session::start(tid, ctx.arg(1).unwrap_or(0), None);
    0
}

#[uretprobe]
pub fn probe_ssl_read_exit(ctx: RetProbeContext) -> u32 {
    emit_llm_event(&ctx, LlmDirection::Read as u8, false)
}

#[uretprobe]
pub fn probe_ssl_write_exit(ctx: RetProbeContext) -> u32 {
    emit_llm_event(&ctx, LlmDirection::Write as u8, false)
}

#[uprobe]
pub fn probe_ssl_rw_ex_enter(ctx: ProbeContext) -> u32 {
    let tid = get_current_tid();
    Session::clear(tid);
    Session::start(tid, ctx.arg(1).unwrap_or(0), Some(ctx.arg(3).unwrap_or(0)));
    0
}

#[uretprobe]
pub fn probe_ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    emit_llm_event(&ctx, LlmDirection::Read as u8, false)
}

#[uretprobe]
pub fn probe_ssl_write_ex_exit(ctx: RetProbeContext) -> u32 {
    emit_llm_event(&ctx, LlmDirection::Write as u8, false)
}

#[uprobe]
pub fn probe_ssl_do_handshake_enter(_ctx: ProbeContext) -> u32 {
    let tid = get_current_tid();
    Session::start(tid, 0, None);
    0
}

#[uretprobe]
pub fn probe_ssl_do_handshake_exit(ctx: RetProbeContext) -> u32 {
    emit_llm_event(&ctx, LlmDirection::Handshake as u8, true)
}

#[inline(always)]
fn emit_llm_event(ctx: &RetProbeContext, rw: u8, is_handshake: bool) -> u32 {
    let tid = get_current_tid();
    if let Some(mut slot) = SSL_EVENTS.reserve::<LlmEvent>(0) {
        let event = unsafe { &mut *slot.as_mut_ptr() };
        if event.capture_data(ctx, rw, is_handshake).is_ok() {
            slot.submit(0);
        } else {
            slot.discard(0);
            Session::clear(tid);
        }
    } else {
        Session::clear(tid);
    }
    0
}
