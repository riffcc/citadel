#!/bin/bash
# Run 5 lens-node instances locally for mesh testing
# Each node gets its own data directory and ports

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/lens-node"

# Check binary exists
if [[ ! -f "$BINARY" ]]; then
    echo "Building lens-node..."
    cargo build --release -p citadel-lens
fi

case "${1:-start}" in
    start)
        echo "Starting 5 lens-nodes..."

        for i in 1 2 3 4 5; do
            DATA_DIR="$PROJECT_DIR/lens-data-$i"
            API_PORT=$((8079 + i))  # 8080, 8081, 8082, 8083, 8084
            P2P_PORT=$((9000 + i))  # 9001, 9002, 9003, 9004, 9005

            if [[ $i -eq 1 ]]; then
                BOOTSTRAP=""
            else
                BOOTSTRAP="127.0.0.1:9001"
            fi

            echo "  Node $i: API=:$API_PORT P2P=:$P2P_PORT"

            mkdir -p "$DATA_DIR"

            if [[ -n "$BOOTSTRAP" ]]; then
                RUST_LOG="lens_node=info,citadel_lens=info" \
                "$BINARY" \
                    --data-dir "$DATA_DIR" \
                    --api-bind "0.0.0.0:$API_PORT" \
                    --p2p-bind "0.0.0.0:$P2P_PORT" \
                    --peers "$BOOTSTRAP" &
            else
                RUST_LOG="lens_node=info,citadel_lens=info" \
                "$BINARY" \
                    --data-dir "$DATA_DIR" \
                    --api-bind "0.0.0.0:$API_PORT" \
                    --p2p-bind "0.0.0.0:$P2P_PORT" &
            fi

            echo $! > "$DATA_DIR/lens.pid"
        done

        echo ""
        echo "5 nodes started. APIs available at:"
        echo "  http://localhost:8080  (node 1)"
        echo "  http://localhost:8081  (node 2)"
        echo "  http://localhost:8082  (node 3)"
        echo "  http://localhost:8083  (node 4)"
        echo "  http://localhost:8084  (node 5)"
        echo ""
        echo "View mesh: curl http://localhost:8080/api/v1/map | jq"
        ;;

    stop)
        echo "Stopping all lens-nodes..."
        pkill -f "lens-node" 2>/dev/null || true

        for i in 1 2 3 4 5; do
            PID_FILE="$PROJECT_DIR/lens-data-$i/lens.pid"
            if [[ -f "$PID_FILE" ]]; then
                rm -f "$PID_FILE"
            fi
        done
        echo "Stopped."
        ;;

    clean)
        "$0" stop
        echo "Cleaning data directories..."
        for i in 1 2 3 4 5; do
            rm -rf "$PROJECT_DIR/lens-data-$i"
        done
        echo "Cleaned."
        ;;

    status)
        echo "Lens node status:"
        for i in 1 2 3 4 5; do
            API_PORT=$((8079 + i))
            if curl -s "http://localhost:$API_PORT/health" > /dev/null 2>&1; then
                echo "  Node $i (:$API_PORT): UP"
            else
                echo "  Node $i (:$API_PORT): DOWN"
            fi
        done
        ;;

    *)
        echo "Usage: $0 {start|stop|clean|status}"
        ;;
esac
