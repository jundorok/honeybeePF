# honeybeePF

Custom eBPF service using [Aya](https://github.com/aya-rs/aya).

## Prerequisites
Install Rustup
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install Rust (stable + nightly toolchain required for eBPF):
```bash
rustup install stable
rustup toolchain install nightly --component rust-src
rustup default stable
```

Install eBPF build tools:
```bash
cargo install bpf-linker
cargo install cargo-generate
```

Kernel headers (choose one):
```bash
# Ubuntu / Debian
sudo apt update
sudo apt install linux-headers-$(uname -r)

# Fedora / RHEL
sudo dnf install kernel-devel
```

## Notes
- Nightly is required for eBPF program compilation.
- Ensure `bpf-linker` is in PATH.
- Run binaries with sudo for loader access.

## License
MIT
