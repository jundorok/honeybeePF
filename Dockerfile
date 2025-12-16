# Multi-stage build for honeybeepf eBPF honeypot

# ================================
# Stage 1: Builder
# ================================
FROM rust:1-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    clang \
    llvm \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly and components
RUN rustup toolchain install nightly --component rust-src

# Install bpf-linker
RUN cargo install bpf-linker

# Set working directory
WORKDIR /build

# Copy workspace files
COPY honeybeepf/Cargo.toml honeybeepf/Cargo.lock ./
COPY honeybeepf/honeybeepf ./honeybeepf
COPY honeybeepf/honeybeepf-common ./honeybeepf-common
COPY honeybeepf/honeybeepf-ebpf ./honeybeepf-ebpf

# Build eBPF program first
WORKDIR /build/honeybeepf-ebpf
RUN cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core

# Build userspace program
WORKDIR /build/honeybeepf
RUN cargo build --release

FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /build/target/release/honeybeepf /usr/local/bin/honeybeepf

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/honeybeepf"]

# Default command (can be overridden)
CMD ["--verbose"]