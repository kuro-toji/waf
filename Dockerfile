# Build stage
# Use a current stable Rust. The previous pin (1.75) shipped cargo
# 1.75, which cannot parse lock file version 4 — Cargo.lock is
# written by the developer's local cargo (>=1.78) and would fail
# to build with 'lock file version 4 was found, but this version
# of Cargo does not understand this lock file'. 1.83 covers every
# edition 2024 feature the workspace uses; bump as the toolchain
# moves.
FROM rust:1.83-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests. We need the per-crate Cargo.toml files
# in place before the dummy build so cargo can resolve the workspace
# members and cache their dependency graphs.
COPY Cargo.toml Cargo.lock* ./
COPY waf-common/Cargo.toml        waf-common/Cargo.toml
COPY waf-engine/Cargo.toml        waf-engine/Cargo.toml
COPY waf-rate-limiter/Cargo.toml  waf-rate-limiter/Cargo.toml
COPY waf-bot-detector/Cargo.toml  waf-bot-detector/Cargo.toml
COPY waf-core/Cargo.toml          waf-core/Cargo.toml
COPY waf-admin/Cargo.toml         waf-admin/Cargo.toml

# Create dummy source for dependency caching
RUN mkdir -p src \
        waf-common/src \
        waf-engine/src \
        waf-rate-limiter/src \
        waf-bot-detector/src \
        waf-core/src \
        waf-admin/src && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > waf-common/src/lib.rs && \
    echo "fn main() {}" > waf-engine/src/lib.rs && \
    echo "fn main() {}" > waf-rate-limiter/src/lib.rs && \
    echo "fn main() {}" > waf-bot-detector/src/lib.rs && \
    echo "fn main() {}" > waf-core/src/main.rs && \
    echo "fn main() {}" > waf-admin/src/lib.rs

# Build dependencies only
RUN cargo build --release --workspace && \
    rm -rf src

# Copy actual source
COPY . .

# Build all binaries
RUN cargo build --release --workspace

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /app/target/release/waf-core /app/waf-core
COPY --from=builder /app/target/release/waf-admin /app/waf-admin

# Copy rules
COPY --from=builder /app/rules /app/rules

# Create non-root user
RUN useradd -m -u 1000 waf

USER waf

# Expose ports
EXPOSE 8080 9090 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/waf-core"]