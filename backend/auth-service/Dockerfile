# syntax=docker/dockerfile:1

################################################################################
# STAGE 1: BUILDER - Compiles the Rust application
################################################################################
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies to speed up subsequent builds
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Build the final application binary
COPY src ./src
RUN cargo build --release && \
    strip /build/target/release/auth-service

################################################################################
# STAGE 2: RUNTIME - Creates the final, minimal production image
################################################################################
FROM debian:bookworm-slim

# Install runtime dependencies + Tini
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpq5 \
    libssl3 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m -u 1001 appuser

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder --chown=appuser:appuser /build/target/release/auth-service /app/auth-service

# Set default environment variables
ENV RUST_LOG=info \
    HOST=0.0.0.0 \
    PORT=3000

EXPOSE 3000

# Health check to ensure the service is running correctly
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to the non-root user
USER appuser

# Use Tini as the entrypoint to handle signals properly (PID 1 problem)
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/auth-service"]