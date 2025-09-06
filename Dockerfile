### Dev Rust Auth Service Dockerfile
## Multi-stage build producing a small runtime image

FROM rust:1.81-slim AS build
WORKDIR /app

# Create dummy layer to cache dependencies
COPY Cargo.toml .
RUN mkdir src && echo 'fn main() {println!("placeholder")}' > src/main.rs && cargo build --release || true

# Copy real source
COPY src ./src
RUN cargo build --release

FROM debian:stable-slim AS runtime
WORKDIR /app
# Install curl for Docker HEALTHCHECK (previously health checks failed: curl not found)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -m appuser
COPY --from=build /app/target/release/fks_auth /usr/local/bin/fks_auth

ENV SERVICE_NAME=fks-auth \
  SERVICE_TYPE=auth

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:4100/health || exit 1

EXPOSE 4100
USER appuser
CMD ["/usr/local/bin/fks_auth"]
