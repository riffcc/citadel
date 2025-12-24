#!/usr/bin/env python3
"""
Citadel cluster management.

Usage:
    ./citadel.py up [N]              Start N-node cluster (default: 5)
    ./citadel.py down                Stop cluster
    ./citadel.py logs [service]      View logs
    ./citadel.py ps                  List containers
    ./citadel.py shell N             Shell into node N
    ./citadel.py api [endpoint]      Call API on load balancer

Options:
    --docker-rust-build   Build Rust in Docker instead of cross-compiling on host.
                          Slower but doesn't require cross-compile toolchain.

Default: Cross-compile on host (auto-detects Apple Silicon vs Linux)

Examples:
    ./citadel.py up 5                # Start 5-node cluster
    ./citadel.py up 50               # Start 50-node cluster
    ./citadel.py logs citadel-1      # View logs for node 1
    ./citadel.py shell 3             # Shell into node 3
    ./citadel.py api /mesh/state     # Get mesh state from LB
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

import yaml


SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent


def get_cross_compile_target() -> str | None:
    """
    Detect if cross-compilation is needed based on host platform.
    Returns the target triple if cross-compile needed, None for native build.

    - Apple Silicon (macOS ARM64): cross-compile to aarch64-unknown-linux-gnu
    - Intel Mac (macOS x86_64): cross-compile to x86_64-unknown-linux-gnu
    - Linux: native build (no cross-compile needed)
    """
    system = platform.system()
    machine = platform.machine()

    if system == 'Darwin' and machine == 'arm64':
        return 'aarch64-unknown-linux-gnu'
    elif system == 'Darwin' and machine == 'x86_64':
        return 'x86_64-unknown-linux-gnu'
    else:
        return None


def get_binary_path() -> str:
    """Get the path to the lens-node binary based on cross-compile target."""
    target = get_cross_compile_target()
    if target:
        return f'/citadel/target/{target}/release/lens-node'
    else:
        return '/citadel/target/release/lens-node'


def get_peers_for_node(node_num: int, total_nodes: int) -> str:
    """
    Get CITADEL_PEERS for a specific node.

    Each node connects to up to 3 predecessors to distribute connection load.
    This creates a more resilient mesh than all nodes pointing at node 1.

    Examples:
      Node 1: "" (genesis, no peers)
      Node 2: "citadel-1:9000"
      Node 3: "citadel-1:9000,citadel-2:9000"
      Node 4: "citadel-1:9000,citadel-2:9000,citadel-3:9000"
      Node 5: "citadel-2:9000,citadel-3:9000,citadel-4:9000"
    """
    if node_num <= 1:
        return ""

    # Connect to up to 3 predecessors
    start = max(1, node_num - 3)
    end = node_num

    peers = [f'citadel-{i}:9000' for i in range(start, end)]
    return ','.join(peers)


def ensure_base_image():
    """Build the citadel-node base image if needed."""
    image_name = 'citadel-node:latest'

    # Check if image exists
    result = subprocess.run(
        ['docker', 'images', '-q', image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        print(f"Building {image_name}...")
        dockerfile_path = SCRIPT_DIR / 'Dockerfile.citadel-node'
        if not dockerfile_path.exists():
            print(f"Error: {dockerfile_path} not found")
            sys.exit(1)

        subprocess.run([
            'docker', 'build', '-t', image_name,
            '-f', str(dockerfile_path), str(SCRIPT_DIR)
        ], check=True)


def generate_compose(num_nodes: int, docker_rust_build: bool = False) -> dict:
    """Generate docker-compose config for N citadel nodes."""

    binary_path = get_binary_path()
    home = os.path.expanduser('~')
    citadel_src = f'{home}/projects/citadel'

    # Base environment
    base_env = {
        'LENS_DATA_DIR': '/data',
        'LENS_API_ADDR': '0.0.0.0:8080',
        'LENS_P2P_ADDR': '0.0.0.0:9000',
        'RUST_LOG': '${RUST_LOG:-citadel_lens=info,citadel_protocols=info}',
        'ADMIN_PUBLIC_KEY': '${ADMIN_PUBLIC_KEY:-}',
    }

    # Base node config with hot-reload
    node_base = {
        'image': 'citadel-node:latest',
        'command': f'''bash -c "
            while [ ! -f {binary_path} ]; do echo 'Waiting for binary...'; sleep 2; done &&
            while true; do
                {binary_path} &
                PID=$$!
                inotifywait -e close_write {binary_path}
                kill $$PID 2>/dev/null || true
                sleep 1
            done
        "''',
        'networks': ['citadel-mesh'],
        'restart': 'unless-stopped',
    }

    services = {}

    # Add builder service only if docker_rust_build
    if docker_rust_build:
        services['citadel-builder'] = {
            'image': 'rust:1.83-slim-bookworm',
            'working_dir': '/citadel',
            'command': '''bash -c "
                apt-get update && apt-get install -y git pkg-config libssl-dev &&
                cargo build --release -p citadel-lens &&
                echo 'Build complete, watching for changes...' &&
                sleep infinity
            "''',
            'volumes': [
                f'{citadel_src}:/citadel',
                'citadel_cargo:/usr/local/cargo/registry',
                'citadel_target:/citadel/target',
            ],
        }
        node_base['depends_on'] = ['citadel-builder']

    # Generate citadel nodes
    for i in range(1, num_nodes + 1):
        node_peers = get_peers_for_node(i, num_nodes)

        # Use docker volume for target when building in docker, host path otherwise
        if docker_rust_build:
            target_volume = 'citadel_target:/citadel/target:ro'
        else:
            target_volume = f'{citadel_src}/target:/citadel/target:ro'

        node_config = {
            **node_base,
            'hostname': f'citadel-{i}',
            'container_name': f'citadel-{i}',
            'environment': {
                **base_env,
                'CITADEL_PEERS': node_peers,
            },
            'volumes': [
                f'{citadel_src}:/citadel:ro',
                target_volume,
                f'citadel_data_{i}:/data',
            ],
        }

        # First node gets HTTP port exposed
        if i == 1:
            node_config['ports'] = ['8080:8080']

        services[f'citadel-{i}'] = node_config

    # Add HAProxy load balancer
    services['citadel-lb'] = {
        'image': 'haproxy:2.9-alpine',
        'container_name': 'citadel-lb',
        'ports': [
            '${CITADEL_API_PORT:-8085}:8085',
            '${HAPROXY_STATS_PORT:-8404}:8404',
        ],
        'volumes': [
            f'{SCRIPT_DIR}/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro',
        ],
        'depends_on': [f'citadel-{i}' for i in range(1, num_nodes + 1)],
        'networks': ['citadel-mesh'],
        'restart': 'unless-stopped',
    }

    # Build volumes dict
    volumes = {}
    if docker_rust_build:
        volumes['citadel_cargo'] = None
        volumes['citadel_target'] = None
    for i in range(1, num_nodes + 1):
        volumes[f'citadel_data_{i}'] = None

    return {
        'services': services,
        'networks': {'citadel-mesh': {'driver': 'bridge'}},
        'volumes': volumes,
    }


def generate_haproxy_config(num_nodes: int) -> str:
    """Generate HAProxy config for N nodes."""
    servers = '\n'.join(
        f'    server citadel-{i} citadel-{i}:8080 check'
        for i in range(1, num_nodes + 1)
    )

    return f"""global
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    option httplog

frontend http_front
    bind *:8085
    default_backend citadel_nodes

backend citadel_nodes
    balance roundrobin
    option httpchk GET /health
{servers}

frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
"""


def cmd_up(args: list[str]):
    """Start the cluster."""
    docker_rust_build = '--docker-rust-build' in args
    args = [a for a in args if not a.startswith('--')]
    num_nodes = int(args[0]) if args else 5

    target = get_cross_compile_target()

    print(f"Starting {num_nodes}-node Citadel cluster...")

    if docker_rust_build:
        print("  Mode: Building Rust in Docker (slow)")
    elif target:
        print(f"  Mode: Cross-compile to {target}")
        print(f"  Build: cross build --release -p citadel-lens --target {target}")
    else:
        print("  Mode: Native build")
        print("  Build: cargo build --release -p citadel-lens")

    # Ensure base image exists
    ensure_base_image()

    # Generate configs
    compose = generate_compose(num_nodes, docker_rust_build)
    haproxy = generate_haproxy_config(num_nodes)

    # Write configs
    compose_file = SCRIPT_DIR / 'docker-compose.generated.yml'
    haproxy_file = SCRIPT_DIR / 'haproxy.cfg'

    with open(compose_file, 'w') as f:
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)

    with open(haproxy_file, 'w') as f:
        f.write(haproxy)

    print(f"  Generated: {compose_file.name}")
    print(f"  Generated: {haproxy_file.name}")

    # Clean up orphaned citadel containers from previous larger clusters
    # (e.g., if going from 50 nodes to 5, remove citadel-6 through citadel-50)
    # Note: We do this manually instead of --remove-orphans to preserve flagship-dev
    result = subprocess.run(
        ['docker', 'ps', '-a', '--format', '{{.Names}}', '--filter', 'name=citadel-'],
        capture_output=True, text=True
    )
    existing = result.stdout.strip().split('\n') if result.stdout.strip() else []
    orphans = []
    for name in existing:
        # Parse citadel-N containers
        if name.startswith('citadel-') and name != 'citadel-lb':
            try:
                n = int(name.split('-')[1])
                if n > num_nodes:
                    orphans.append(name)
            except ValueError:
                pass
    if orphans:
        print(f"  Removing {len(orphans)} orphaned containers: {', '.join(orphans[:3])}{'...' if len(orphans) > 3 else ''}")
        subprocess.run(['docker', 'rm', '-f'] + orphans, capture_output=True)

    # Start cluster (note: no --remove-orphans as flagship-dev shares the network)
    subprocess.run([
        'docker', 'compose', '-f', str(compose_file),
        'up', '-d'
    ], check=True)

    print()
    print(f"Cluster started with {num_nodes} nodes")
    print(f"  API (node 1):     http://localhost:8080")
    print(f"  API (LB):         http://localhost:8085")
    print(f"  HAProxy stats:    http://localhost:8404/stats")
    print()
    print("Commands:")
    print(f"  ./citadel.py logs              # All logs")
    print(f"  ./citadel.py logs citadel-1    # Node 1 logs")
    print(f"  ./citadel.py ps                # List containers")
    print(f"  ./citadel.py down              # Stop cluster")


def cmd_down():
    """Stop the cluster."""
    compose_file = SCRIPT_DIR / 'docker-compose.generated.yml'
    if compose_file.exists():
        subprocess.run([
            'docker', 'compose', '-f', str(compose_file), 'down'
        ])
    else:
        print("No cluster running (docker-compose.generated.yml not found)")


def cmd_logs(args: list[str]):
    """View logs."""
    compose_file = SCRIPT_DIR / 'docker-compose.generated.yml'
    cmd = ['docker', 'compose', '-f', str(compose_file), 'logs', '-f']
    if args:
        cmd.append(args[0])
    subprocess.run(cmd)


def cmd_ps():
    """List containers."""
    compose_file = SCRIPT_DIR / 'docker-compose.generated.yml'
    subprocess.run([
        'docker', 'compose', '-f', str(compose_file), 'ps'
    ])


def cmd_shell(args: list[str]):
    """Shell into a node."""
    if not args:
        print("Usage: ./citadel.py shell N")
        sys.exit(1)

    node_num = args[0]
    subprocess.run([
        'docker', 'exec', '-it', f'citadel-{node_num}', '/bin/bash'
    ])


def cmd_api(args: list[str]):
    """Call API on load balancer."""
    endpoint = args[0] if args else '/health'
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint

    result = subprocess.run([
        'curl', '-s', f'http://localhost:8085{endpoint}'
    ], capture_output=True, text=True)

    print(result.stdout)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        'up': lambda: cmd_up(args),
        'down': cmd_down,
        'logs': lambda: cmd_logs(args),
        'ps': cmd_ps,
        'shell': lambda: cmd_shell(args),
        'api': lambda: cmd_api(args),
    }

    if cmd in commands:
        commands[cmd]()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
