# Multi-stage build for fks_auth Rust service
FROM rust:1.84-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files first (for better dependency caching)
COPY Cargo.toml Cargo.lock* ./

# Create a dummy source to build dependencies (better caching)
# This allows Docker to cache the dependency layer separately from source code
# Use cache mounts so dependencies are cached for the real build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src/ ./src/

# Build the application with BuildKit cache mount for Cargo registry
# Dependencies are already cached from the dummy build above
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/fks_auth /app/fks_auth

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user first
RUN useradd -u 1000 -m -s /bin/bash appuser

# Copy binary from builder with correct ownership
COPY --from=builder --chown=appuser:appuser /app/fks_auth /app/fks_auth

# Environment variables
ENV SERVICE_NAME=fks_auth \
    SERVICE_PORT=8009 \
    RUST_LOG=info

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8009/health || exit 1

# Expose service port
EXPOSE 8009

# Run service
CMD ["./fks_auth"]

