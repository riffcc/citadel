# Citadel Lens Node Docker Image
# Multi-stage build for minimal final image

FROM rust:1.94 AS builder

# No external C dependencies needed - ReDB is pure Rust

WORKDIR /build

# Copy lockfile for reproducible builds
COPY citadel/Cargo.lock ./

# Create a minimal workspace Cargo.toml for Docker
RUN cat > Cargo.toml << 'EOF'
[workspace]
resolver = "2"
members = ["crates/citadel-lens", "crates/citadel-topology", "crates/citadel-dht", "crates/citadel-protocols", "crates/citadel-spore", "crates/citadel-docs", "crates/citadel-crdt", "crates/citadel-ygg", "crates/yggdrasil-rs"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "AGPL-3.0-or-later"
authors = ["Lagun Project Contributors"]
repository = "https://github.com/lagun-project/citadel"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
blake3 = "1"
blake2 = "0.10"
ed25519-dalek = "2"
hex = "0.4"
rand = "0.8"
pretty_assertions = "1"
serde_bytes = "0.11"
EOF

# Copy the two-generals dependency (required by citadel-protocols)
COPY two-generals ./two-generals

# Copy all required crates
COPY citadel/crates/citadel-lens ./crates/citadel-lens
COPY citadel/crates/citadel-topology ./crates/citadel-topology
COPY citadel/crates/citadel-dht ./crates/citadel-dht
COPY citadel/crates/citadel-protocols ./crates/citadel-protocols
COPY citadel/crates/citadel-spore ./crates/citadel-spore
COPY citadel/crates/citadel-docs ./crates/citadel-docs
COPY citadel/crates/citadel-crdt ./crates/citadel-crdt
COPY citadel/crates/citadel-ygg ./crates/citadel-ygg
COPY citadel/crates/yggdrasil-rs ./crates/yggdrasil-rs

# Fix two-generals paths for Docker build structure
RUN sed -i 's|path = "../../../two-generals/rust"|path = "../../two-generals/rust"|' crates/citadel-protocols/Cargo.toml && \
    sed -i 's|path = "../../../two-generals/rust-adaptive-flooding"|path = "../../two-generals/rust-adaptive-flooding"|' crates/citadel-protocols/Cargo.toml

# Build release binary
RUN cargo build --release -p citadel-lens

# Runtime image (trixie for glibc 2.38+)
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    wget \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 lens

# Copy binary
COPY --from=builder /build/target/release/lens-node /usr/local/bin/
COPY --from=builder /build/target/release/lens-admin /usr/local/bin/

# Create data directory
RUN mkdir -p /data && chown lens:lens /data

USER lens
WORKDIR /data

# Environment variables
# LENS_DATA_DIR: Data directory (default: /data)
# LENS_API_BIND: HTTP API bind address (default: 0.0.0.0:8080)
# LENS_P2P_BIND: P2P mesh bind address (default: 0.0.0.0:9000)
# CITADEL_PEERS: Comma-separated citadel peers (DNS or IP, port optional - defaults to 9000)
# ADMIN_PUBLIC_KEY: Hex-encoded ed25519 public key for admin
ENV LENS_DATA_DIR=/data
ENV RUST_LOG=lens_node=info,citadel_lens=info

# 8080: HTTP API
# 9000: TCP P2P mesh + UDP TGP (Two Generals Protocol)
EXPOSE 8080 9000 9000/udp

CMD ["lens-node"]
