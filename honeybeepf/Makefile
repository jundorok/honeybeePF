.PHONY: build build-release build-linux test clean package deploy help

# Default target
help:
	@echo "HoneybeePF Build Commands"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build debug version (local platform)"
	@echo "  build-release  Build release version (local platform)"
	@echo "  build-linux    Build for Linux (requires Docker on macOS)"
	@echo "  test           Run tests"
	@echo "  clean          Clean build artifacts"
	@echo "  package        Create distribution package"
	@echo "  deploy         Deploy to remote host (set HOST=user@server)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-release"
	@echo "  make build-linux"
	@echo "  make deploy HOST=root@192.168.1.100"
	@echo "  make package"

# Build commands
build:
	cargo build -p honeybeepf

build-release:
	cargo build --release -p honeybeepf

# Linux build (uses Docker/cross on non-Linux)
build-linux:
ifeq ($(shell uname -s),Linux)
	cargo build --release -p honeybeepf
else
	@echo "Building for Linux using Docker..."
	@docker run --rm -v $(PWD):/workspace -w /workspace \
		rust:latest \
		bash -c "rustup install nightly && \
			rustup component add rust-src --toolchain nightly && \
			cargo install bpf-linker && \
			cargo build --release -p honeybeepf"
endif

# Test
test:
	cargo test

# Clean
clean:
	cargo clean
	rm -rf dist/

# Package
package: build-release
	cargo xtask package

# Deploy (requires HOST variable)
deploy:
ifndef HOST
	$(error HOST is required. Usage: make deploy HOST=user@server)
endif
	cargo xtask deploy --host $(HOST) --release

# Install dependencies (for CI/local dev)
setup:
	rustup install nightly
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker || true
