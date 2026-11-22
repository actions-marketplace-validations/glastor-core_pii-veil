FROM rust:1.85-slim AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/bench-pii-veil /usr/local/bin/bench-pii-veil
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bench-pii-veil"]
