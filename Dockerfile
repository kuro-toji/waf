# Build stage
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./

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