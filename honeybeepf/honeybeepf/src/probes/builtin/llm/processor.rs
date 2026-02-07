use std::time::Instant;
use tiktoken_rs::CoreBPE;
use log::{info, warn};
use crate::probes::builtin::llm::types::LlmDirection;
use crate::probes::builtin::llm::http::{self, ProtocolParser};

// Buffer size constants
const INITIAL_BUFFER_CAPACITY: usize = 8 * 1024;         // 8KB initial allocation
const MAX_REQUEST_BUFFER_SIZE: usize = 8 * 1024 * 1024;  // 8MB max for request (images, large context)
const MAX_RESPONSE_BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16MB max for response (streaming)
const DETECTION_BUFFER_THRESHOLD: usize = 4096;           // Give up detection after 4KB

/// State definition: lifecycle of an LLM connection
enum ProcessorState {
    /// Initial state: detecting protocol and request
    Detecting, 
    /// Buffering request body
    ProcessingRequest {
        start_time: Instant,
        parser: Box<dyn ProtocolParser>,
    },
    /// Request finished, buffering response
    ProcessingResponse {
        start_time: Instant,
        parser: Box<dyn ProtocolParser>,
        est_input_tokens: u64,
    },
    /// Finished or Invalid
    Finished, 
}

pub struct StreamProcessor {
    state: ProcessorState,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    last_activity: Instant,
}

impl StreamProcessor {
    pub fn new() -> Self {
        Self {
            state: ProcessorState::Detecting,
            write_buf: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
            read_buf: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
            last_activity: Instant::now(),
        }
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn is_llm(&self) -> bool {
        !matches!(self.state, ProcessorState::Detecting | ProcessorState::Finished)
    }

    pub fn est_input_tokens(&self) -> u64 {
        match &self.state {
            ProcessorState::ProcessingResponse { est_input_tokens, .. } => *est_input_tokens,
            _ => 0,
        }
    }

    pub fn handle_event(&mut self, direction: LlmDirection, data: &[u8], bpe: &CoreBPE, pid: u32, extract_tokens: bool) {
        self.last_activity = Instant::now();

        // Early return if finished (except for new Write which triggers reset)
        if matches!(self.state, ProcessorState::Finished) {
            if direction == LlmDirection::Write {
                self.reset();
            } else {
                return; // Ignore Read events after completion
            }
        }

        // 1. Buffer Management
        match direction {
            LlmDirection::Write => {
                if self.write_buf.len() + data.len() > MAX_REQUEST_BUFFER_SIZE {
                     warn!("LLM request buffer exceeded {}MB limit (PID: {}), discarding stream",
                           MAX_REQUEST_BUFFER_SIZE / (1024 * 1024), pid);
                     self.reset();
                     return;
                }
                self.write_buf.extend_from_slice(data);
            }
            LlmDirection::Read => {
                if self.read_buf.len() + data.len() > MAX_RESPONSE_BUFFER_SIZE {
                    warn!("LLM response buffer exceeded {}MB limit (PID: {}), discarding stream",
                          MAX_RESPONSE_BUFFER_SIZE / (1024 * 1024), pid);
                    self.reset();
                    return;
                }
                self.read_buf.extend_from_slice(data);
            }
            _ => return,
        }

        // 2. State Machine Transition
        // Take ownership of current state to enable transitions
        let current_state = std::mem::replace(&mut self.state, ProcessorState::Finished);

        self.state = match current_state {
            
            // [State 1] Detecting
            ProcessorState::Detecting => {
                // Try H1
                if let Some(path) = http::Http11Parser.detect_request(&self.write_buf) {
                    info!("[LLM] Detected HTTP/1.1: {} (PID: {})", path, pid);
                    ProcessorState::ProcessingRequest {
                        start_time: Instant::now(),
                        parser: Box::new(http::Http11Parser),
                    }
                }
                // Try H2
                else if let Some(path) = http::Http2Parser.detect_request(&self.write_buf) {
                    info!("[LLM] Detected HTTP/2: {} (PID: {})", path, pid);
                    ProcessorState::ProcessingRequest {
                        start_time: Instant::now(),
                        parser: Box::new(http::Http2Parser),
                    }
                }
                else {
                    // Not detected yet
                    if self.write_buf.len() > DETECTION_BUFFER_THRESHOLD {
                        // Buffer too large and still not detected -> likely not LLM
                         ProcessorState::Finished
                    } else {
                        ProcessorState::Detecting // Keep detecting
                    }
                }
            },

            // [State 2] Processing Request
            ProcessorState::ProcessingRequest { start_time, parser } => {
                if direction == LlmDirection::Read {
                    // Write finished (implied by Read starting), calculate input tokens
                    let text = parser.extract_request_text(&self.write_buf);
                    let est_tokens = bpe.encode_with_special_tokens(&text).len() as u64;

                    // Transition to Response phase
                    ProcessorState::ProcessingResponse {
                        start_time,
                        parser,
                        est_input_tokens: est_tokens,
                    }
                } else {
                    // Still writing -> keep state
                    ProcessorState::ProcessingRequest { start_time, parser }
                }
            },

            // [State 3] Processing Response
            ProcessorState::ProcessingResponse { start_time, parser, est_input_tokens } => {
                // Try parsing response
                if let Some(usage) = parser.parse_response(&self.read_buf) {
                    let latency = start_time.elapsed();
                    let model_str = usage.model.as_deref().unwrap_or("unknown");

                    if !extract_tokens {
                        // Latency-only mode: skip token details
                        info!("LLM | PID: {} | Model: {} | Latency: {:.2}s",
                              pid, model_str, latency.as_secs_f64());
                    } else if usage.prompt_tokens == 0 && usage.completion_tokens == 0 {
                         info!("LLM FAILED/ERROR | PID: {} | Model: {} | Latency: {:.2}s | Est. Input: {}",
                               pid, model_str, latency.as_secs_f64(), est_input_tokens);
                    } else {
                         let thoughts_str = usage.thoughts_tokens
                             .map(|t| format!(", Thoughts: {}", t))
                             .unwrap_or_default();
                         info!("LLM SUCCESS | PID: {} | Model: {} | Latency: {:.2}s | Tokens: {} (Prompt: {}, Compl: {}{}) | Est. Input: {}",
                               pid, model_str, latency.as_secs_f64(),
                               usage.prompt_tokens + usage.completion_tokens,
                               usage.prompt_tokens, usage.completion_tokens,
                               thoughts_str, est_input_tokens);
                    }

                    ProcessorState::Finished
                } else {
                    // Incomplete -> keep state
                    ProcessorState::ProcessingResponse { start_time, parser, est_input_tokens }
                }
            },

            // [State 4] Finished
            ProcessorState::Finished => ProcessorState::Finished,
        };

    }

    fn reset(&mut self) {
        self.state = ProcessorState::Detecting;
        self.write_buf.clear();
        self.read_buf.clear();
    }
}
