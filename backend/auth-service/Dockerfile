# ---------- Build stage ----------
FROM rust:1.82-slim AS builder

# Install only essential build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libpq-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./

# Copy migrations directory (required for embed_migrations!)
COPY migrations ./migrations

# Create dummy src to build dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src target/release/deps/auth_service*

# Copy real source and build
COPY src ./src

# Build the binary
RUN cargo build --release

# ---------- Runtime stage ----------
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies including wget for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libpq5 libssl3 wget && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 10001 appuser

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service

# Make sure it's executable
RUN chmod +x /usr/local/bin/auth-service

# Default envs
ENV APP_ENV=production \
    RUST_LOG=info

# Expose service port
EXPOSE 3000

USER appuser

CMD ["/usr/local/bin/auth-service"]