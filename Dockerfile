# ==============================================================================
# GLASTOR® pii-veil — Ultra-Lightweight Production Dockerfile (< 15 MB)
# Multi-stage build compiling static Rust binary into Google Distroless Static
# ==============================================================================

# Stage 1: Build static musl binary
FROM rust:alpine AS builder

WORKDIR /build

# Install musl development dependencies and ca-certificates
RUN apk add --no-cache musl-dev gcc make ca-certificates

# Copy manifests to pre-cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/veil-core/Cargo.toml crates/veil-core/
COPY crates/veil-cli/Cargo.toml crates/veil-cli/
COPY crates/veil-ffi/Cargo.toml crates/veil-ffi/

# Copy source code and brand assets
COPY assets assets
COPY public public
COPY crates crates

# Build static release binary with LTO and symbols stripped
RUN cargo build --release --target x86_64-unknown-linux-musl -p pii-veil-cli && \
    strip /build/target/x86_64-unknown-linux-musl/release/veil

# Stage 2: Final Minimal Distroless Image (Zero-CVE, Non-Root, < 15 MB)
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="GLASTOR® pii-veil" \
      org.opencontainers.image.description="Sub-millisecond Reversible PII & Secret DLP Proxy & Scanner for LLMs" \
      org.opencontainers.image.vendor="GLASTOR® Core" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/glastor-core/pii-veil"

WORKDIR /app

# Copy stripped static binary from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/veil /usr/local/bin/veil

# Default environment configuration (bind to all interfaces on 8080)
ENV VEIL_LISTEN="0.0.0.0:8080"

# Expose HTTP / SSE proxy port
EXPOSE 8080

# Run as non-root user (UID 65532 is distroless nonroot)
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/veil"]
CMD ["proxy", "--listen", "0.0.0.0:8080"]
