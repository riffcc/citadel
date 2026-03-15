#!/bin/bash
# Safe development script for lens-node
# Only operates within the citadel project directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/lens-data"
BINARY="$PROJECT_DIR/target/release/lens-node"

case "${1:-help}" in
    start)
        echo "Starting lens-node..."
        echo "  Data: $DATA_DIR"
        pkill -f "lens-node" 2>/dev/null || true
        sleep 1
        RUST_LOG="${RUST_LOG:-lens_node=info,citadel_lens=info}" \
            "$BINARY" --data-dir "$DATA_DIR" &
        sleep 2
        if curl -s http://localhost:8080/health > /dev/null; then
            echo "lens-node started successfully"
            echo "  API: http://localhost:8080"
            echo "  Admin socket: $DATA_DIR/admin.sock"
        else
            echo "Failed to start lens-node"
            exit 1
        fi
        ;;
    stop)
        echo "Stopping lens-node..."
        pkill -f "lens-node" 2>/dev/null || echo "No lens-node running"
        ;;
    restart)
        "$0" stop
        sleep 1
        "$0" start
        ;;
    clean)
        echo "Cleaning lens-data directory..."
        "$0" stop
        if [[ -d "$DATA_DIR" ]]; then
            echo "Removing: $DATA_DIR"
            rm -rf "$DATA_DIR"
            echo "Cleaned."
        else
            echo "No data directory to clean."
        fi
        ;;
    status)
        if pgrep -f "lens-node" > /dev/null; then
            echo "lens-node is running (PID: $(pgrep -f lens-node))"
            curl -s http://localhost:8080/health && echo " - HTTP OK"
        else
            echo "lens-node is not running"
        fi
        ;;
    logs)
        if [[ -f "$DATA_DIR/LOG" ]]; then
            tail -f "$DATA_DIR/LOG"
        else
            echo "No log file found"
        fi
        ;;
    help|*)
        echo "Usage: $0 {start|stop|restart|clean|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start lens-node daemon"
        echo "  stop    - Stop lens-node daemon"
        echo "  restart - Restart lens-node daemon"
        echo "  clean   - Stop and remove lens-data directory"
        echo "  status  - Check if lens-node is running"
        echo "  logs    - Tail the log file"
        ;;
esac
