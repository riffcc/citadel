# Citadel Docker

Dynamic cluster management for Citadel mesh networks.

## Quick Start

```bash
# Build the binary first (cross-compile for Docker)
cross build --release -p citadel-lens --target aarch64-unknown-linux-gnu

# Start a 5-node cluster
./citadel.py up 5

# View logs
./citadel.py logs

# Stop cluster
./citadel.py down
```

## Commands

| Command | Description |
|---------|-------------|
| `./citadel.py up [N]` | Start N-node cluster (default: 5) |
| `./citadel.py down` | Stop cluster |
| `./citadel.py logs [service]` | View logs (optionally for specific service) |
| `./citadel.py ps` | List running containers |
| `./citadel.py shell N` | Shell into node N |
| `./citadel.py api [endpoint]` | Call API on load balancer |

## Options

| Option | Description |
|--------|-------------|
| `--docker-rust-build` | Build Rust in Docker (slow fallback) |

## Build Modes

**Default (cross-compile on host):**
```bash
# Apple Silicon
cross build --release -p citadel-lens --target aarch64-unknown-linux-gnu

# Intel Mac
cross build --release -p citadel-lens --target x86_64-unknown-linux-gnu

# Linux (native)
cargo build --release -p citadel-lens
```

**Fallback (Rust in Docker):**
```bash
./citadel.py up 5 --docker-rust-build
```

## Endpoints

After starting a cluster:

| Endpoint | Description |
|----------|-------------|
| `http://localhost:8080` | Node 1 API (direct) |
| `http://localhost:8085` | Load balancer API |
| `http://localhost:8404/stats` | HAProxy stats |

## Hot Reload

The containers watch for binary changes. Rebuild and nodes auto-restart:

```bash
# Terminal 1: Cluster running
./citadel.py up 5

# Terminal 2: Rebuild (nodes detect change and restart)
cross build --release -p citadel-lens --target aarch64-unknown-linux-gnu
```

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Available options:
- `CITADEL_API_PORT` - Load balancer port (default: 8085)
- `HAPROXY_STATS_PORT` - HAProxy stats port (default: 8404)
- `RUST_LOG` - Log level (default: info)
- `ADMIN_PUBLIC_KEY` - Admin public key for authorization

## Peer Distribution

Nodes connect to up to 3 predecessors to distribute load:

```
Node 1: (genesis, no peers)
Node 2: citadel-1
Node 3: citadel-1, citadel-2
Node 4: citadel-1, citadel-2, citadel-3
Node 5: citadel-2, citadel-3, citadel-4
...
```

## Files

| File | Description |
|------|-------------|
| `citadel.py` | CLI tool |
| `Dockerfile.citadel-node` | Minimal runtime image with inotify-tools |
| `docker-compose.generated.yml` | Generated compose file (gitignored) |
| `haproxy.cfg` | Generated HAProxy config (gitignored) |
| `.env.example` | Example environment config |
