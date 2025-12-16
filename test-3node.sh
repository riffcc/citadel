#!/bin/bash
# Test 3-node mesh locally

set -e

CITADEL_DIR="/mnt/riffcastle/lagun-project/citadel"
BINARY="$CITADEL_DIR/target/release/lens-node"

# Clean up old data
rm -rf /tmp/citadel-test-*
mkdir -p /tmp/citadel-test-genesis /tmp/citadel-test-node2 /tmp/citadel-test-node3

# Start genesis node
echo "Starting genesis node..."
RUST_LOG=citadel_lens=debug,citadel_protocols=debug \
LENS_DATA_DIR=/tmp/citadel-test-genesis \
LENS_API_BIND=127.0.0.1:8080 \
LENS_P2P_BIND=127.0.0.1:9000 \
CITADEL_PEERS="" \
"$BINARY" &
GENESIS_PID=$!
echo "Genesis PID: $GENESIS_PID"

# Wait for genesis to be ready
echo "Waiting for genesis node..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/health >/dev/null 2>&1; then
        echo "Genesis ready!"
        break
    fi
    sleep 0.5
done

# Start node 2
echo "Starting node 2..."
RUST_LOG=citadel_lens=debug,citadel_protocols=debug \
LENS_DATA_DIR=/tmp/citadel-test-node2 \
LENS_API_BIND=127.0.0.1:8081 \
LENS_P2P_BIND=127.0.0.1:9001 \
CITADEL_PEERS="127.0.0.1:9000" \
"$BINARY" &
NODE2_PID=$!
echo "Node2 PID: $NODE2_PID"

# Start node 3
echo "Starting node 3..."
RUST_LOG=citadel_lens=debug,citadel_protocols=debug \
LENS_DATA_DIR=/tmp/citadel-test-node3 \
LENS_API_BIND=127.0.0.1:8082 \
LENS_P2P_BIND=127.0.0.1:9002 \
CITADEL_PEERS="127.0.0.1:9000" \
"$BINARY" &
NODE3_PID=$!
echo "Node3 PID: $NODE3_PID"

echo ""
echo "All nodes started:"
echo "  Genesis: PID $GENESIS_PID, API http://127.0.0.1:8080, P2P 127.0.0.1:9000"
echo "  Node 2:  PID $NODE2_PID, API http://127.0.0.1:8081, P2P 127.0.0.1:9001"
echo "  Node 3:  PID $NODE3_PID, API http://127.0.0.1:8082, P2P 127.0.0.1:9002"
echo ""
echo "Press Ctrl+C to stop all nodes"

# Wait for interrupt
trap "kill $GENESIS_PID $NODE2_PID $NODE3_PID 2>/dev/null; exit" INT TERM
wait
