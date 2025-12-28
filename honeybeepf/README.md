# honeybeepf

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package honeybeepf --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/honeybeepf` can be
copied to a Linux server or VM and run there.


## CI/CD & Self-hosted Runner

To overcome the resource limitations of standard GitHub-hosted runners when building heavy eBPF programs, this project utilizes **Self-hosted Runners** with a **Binary Injection** strategy.

### Runner Setup Guide
Team members contributing build resources should follow these steps on their Ubuntu servers:

#### Step 1: Install GitHub Agent
1. Navigate to **Settings > Actions > Runners** in the repository.
2. Click **'New self-hosted runner'**, select **Linux**, and choose the **ARM64** architecture.
3. Execute the provided shell scripts in your terminal.

> **Note:** If you lack administrative permissions to see the Settings tab, please contact the project maintainer for a registration token.

## Step 2: Configure Build Environment

```
# 1. Install System Libraries
sudo apt update
sudo apt install -y clang llvm libelf-dev pkg-config build-essential

# 2. Setup Rust Nightly
rustup toolchain install nightly --component rust-src
rustup default nightly

# 3. Install eBPF Linker
cargo install bpf-linker
```

## Step 3: Post-Setup & Permissions

To prevent permission errors during Docker builds and ensure service persistence:

```
# Add runner user to docker group
sudo usermod -aG docker $USER
# Apply immediately (or log out and back in)
newgrp docker

# Configure runner as a system service
sudo ./svc.sh install
sudo ./svc.sh start
```


## License

With the exception of eBPF code, honeybeepf is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

