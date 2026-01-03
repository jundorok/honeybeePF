FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS chef

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=nightly

RUN apt-get update && apt-get install -y \
    curl git clang llvm libelf-dev pkg-config build-essential \
    libclang-dev llvm-dev zlib1g-dev \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VERSION} --component rust-src \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef
RUN cargo install bpf-linker --version 0.9.15

WORKDIR /app/honeybeepf

FROM chef AS planner
COPY . /app
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/honeybeepf/recipe.json recipe.json

ARG TARGETARCH

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get update && apt-get install -y gcc-aarch64-linux-gnu; \
    elif [ "$TARGETARCH" = "386" ]; then \
        apt-get update && apt-get install -y gcc-multilib; \
    fi && rm -rf /var/lib/apt/lists/*

RUN case ${TARGETARCH} in \
    "amd64") rustup target add x86_64-unknown-linux-gnu ;; \
    "arm64") rustup target add aarch64-unknown-linux-gnu ;; \
    "386")   rustup target add i686-unknown-linux-gnu ;; \
    esac

RUN cargo chef cook --release --recipe-path recipe.json --target $(case ${TARGETARCH} in "amd64"*) echo "x86_64-unknown-linux-gnu" ;; "arm64"*) echo "aarch64-unknown-linux-gnu" ;; "386"*) echo "i686-unknown-linux-gnu" ;; esac)

COPY . /app

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