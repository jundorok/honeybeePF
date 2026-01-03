FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:latest-rust-nightly AS chef
WORKDIR /app

RUN rustup component add rust-src
RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev pkg-config build-essential \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-multilib g++-multilib \
    && cargo install bpf-linker --version 0.9.15

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

ARG TARGETARCH
RUN case ${TARGETARCH} in \
    "amd64") rustup target add x86_64-unknown-linux-gnu ;; \
    "arm64") rustup target add aarch64-unknown-linux-gnu ;; \
    "386")   rustup target add i686-unknown-linux-gnu ;; \
    esac

RUN cargo chef cook --release --recipe-path recipe.json --target $(case ${TARGETARCH} in "amd64"*) echo "x86_64-unknown-linux-gnu" ;; "arm64"*) echo "aarch64-unknown-linux-gnu" ;; "386"*) echo "i686-unknown-linux-gnu" ;; esac)

COPY . .

RUN cargo +nightly build --release --package honeybeepf-ebpf --target=bpfel-unknown-none -Z build-std=core

RUN case ${TARGETARCH} in \
    "amd64") \
        cargo build --release --package honeybeepf --target x86_64-unknown-linux-gnu && \
        cp target/x86_64-unknown-linux-gnu/release/honeybeepf /app/honeybeepf-bin ;; \
    "arm64") \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --package honeybeepf --target aarch64-unknown-linux-gnu && \
        cp target/aarch64-unknown-linux-gnu/release/honeybeepf /app/honeybeepf-bin ;; \
    "386") \
        cargo build --release --package honeybeepf --target i686-unknown-linux-gnu && \
        cp target/i686-unknown-linux-gnu/release/honeybeepf /app/honeybeepf-bin ;; \
    esac

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y libelf1 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/honeybeepf-bin /usr/local/bin/honeybeepf

ENTRYPOINT ["/usr/local/bin/honeybeepf"]