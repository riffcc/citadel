# Citadel Docker

The Docker contract is intentionally small now:

- `docker/Dockerfile` builds the `lens-node` and `lens-admin` image from this repo.
- `docker-compose.yml` is the only compose file for local mesh bring-up.

## Quick Start

From the repo root:

```bash
docker compose up --build -d
docker compose logs -f lens-node-1
docker compose down
```

## What It Does

- Builds `riffcc/citadel:latest` from `docker/Dockerfile`
- Starts the mesh with explicit `lens-node` CLI flags instead of hidden runtime env wiring
- Keeps runtime env use small: `RUST_LOG` everywhere, `CITADEL_PEERS` only where a node needs bootstrap peers

## Endpoints

- `http://localhost:8080` - node 1 API
- `http://localhost:8081` - node 2 API
- `http://localhost:8082` - node 3 API

## Notes

- Node 1 is the genesis node and starts without peers.
- Other nodes join through the bootstrap peers defined in `docker-compose.yml`.
- If you change the Rust code, rebuild with `docker compose up --build -d`.
