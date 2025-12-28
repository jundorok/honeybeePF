# Use a stable Ubuntu image for the runtime environment
FROM ubuntu:22.04.3

# Install essential runtime libraries for eBPF and networking
# - libelf1: Required for processing eBPF objects
# - ca-certificates: Required for secure external communications
RUN apt-get update && apt-get install -y \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Inject the binary built by the host during the CI process
# The binary is sourced from the staged 'dist/' directory
COPY dist/honeybeepf /usr/local/bin/honeybeepf

# Validate that the binary exists and ensure it has execution permissions
RUN if [ ! -f /usr/local/bin/honeybeepf ]; then \
COPY --chmod=755 dist/honeybeepf /usr/local/bin/honeybeepf
# Set the entry point to start the service
ENTRYPOINT ["/usr/local/bin/honeybeepf"]