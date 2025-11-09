FROM rust:1.84-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (for better caching)
COPY Cargo.toml ./

# Copy source code
COPY src/ ./src/

# Build the application
# Cargo.lock will be generated automatically if missing or incompatible
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/fks_auth /app/fks_auth

# Environment variables
ENV SERVICE_NAME=fks_auth \
    SERVICE_PORT=8009 \
    RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8009/health || exit 1

# Expose service port
EXPOSE 8009

# Create non-root user
RUN useradd -u 1000 -m appuser && chown -R appuser /app
USER appuser

# Run service
CMD ["./fks_auth"]

