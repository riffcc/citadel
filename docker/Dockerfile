# Citadel Lens Node Docker Image
# Build from the repo root with:
#   docker build -f docker/Dockerfile -t riffcc/citadel:latest .

FROM rust:latest AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p citadel-lens

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    wget \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 lens

COPY --from=builder /build/target/release/lens-node /usr/local/bin/
COPY --from=builder /build/target/release/lens-admin /usr/local/bin/

RUN mkdir -p /data && chown lens:lens /data

USER lens
WORKDIR /data

ENV RUST_LOG=lens_node=info,citadel_lens=info

EXPOSE 8080 9000 9000/udp

CMD ["lens-node", "--data-dir", "/data"]
