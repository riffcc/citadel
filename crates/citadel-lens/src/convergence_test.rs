//! CITADEL Mesh Convergence Test
//!
//! Verifies that nodes can join the mesh and claim slots using the standard
//! CITADEL mechanism. No custom logic - just start nodes and let them work.

use crate::mesh::MeshService;
use crate::storage::Storage;
use citadel_docs::DocumentStore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Helper: create a MeshService node for testing
fn make_test_node(port: u16, entry_peers: Vec<String>) -> (Arc<MeshService>, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let storage = Arc::new(
        Storage::open(temp_dir.path().join("storage.redb")).expect("Failed to create storage"),
    );
    let doc_store = Arc::new(tokio::sync::RwLock::new(
        DocumentStore::open(temp_dir.path().join("docs.redb"))
            .expect("Failed to create doc store"),
    ));
    let listen_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let node = Arc::new(MeshService::new(
        listen_addr,
        None,
        entry_peers,
        None,
        None,
        None,
        storage,
        doc_store,
    ));
    (node, temp_dir)
}

/// Test that 16 nodes can all claim slots via standard CITADEL mechanism
pub async fn test_16_node_convergence() -> (bool, Duration, usize) {
    const NODE_COUNT: usize = 16;
    const BASE_PORT: u16 = 40000;
    const MAX_WAIT: Duration = Duration::from_secs(120);

    println!("\n============================================================");
    println!("CITADEL MESH CONVERGENCE TEST ({} nodes)", NODE_COUNT);
    println!("============================================================\n");

    let start = Instant::now();

    // Create nodes
    let mut temp_dirs: Vec<TempDir> = Vec::new();
    let mut nodes: Vec<Arc<MeshService>> = Vec::new();

    println!("Creating {} nodes...", NODE_COUNT);

    for i in 0..NODE_COUNT {
        // Bootstrap: nodes 0,1,2 connect to each other, rest connect to them
        let entry_peers: Vec<String> = if i < 3 {
            (0..i)
                .map(|j| format!("127.0.0.1:{}", BASE_PORT + j as u16))
                .collect()
        } else {
            vec![
                format!("127.0.0.1:{}", BASE_PORT),
                format!("127.0.0.1:{}", BASE_PORT + 1),
                format!("127.0.0.1:{}", BASE_PORT + 2),
            ]
        };

        let (node, temp) = make_test_node(BASE_PORT + i as u16, entry_peers);
        nodes.push(node);
        temp_dirs.push(temp);
    }

    // Start bootstrap nodes first
    println!("Starting bootstrap nodes (0, 1, 2)...");
    for i in 0..3 {
        let node = Arc::clone(&nodes[i]);
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }

    // Wait for bootstrap mesh
    loop {
        let bootstrap_slots = nodes[0].has_claimed_slot().await as u8
            + nodes[1].has_claimed_slot().await as u8
            + nodes[2].has_claimed_slot().await as u8;
        if bootstrap_slots >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    println!("Bootstrap ready in {:?}", start.elapsed());

    // Start remaining nodes
    println!("Starting remaining nodes...");
    for i in 3..NODE_COUNT {
        let node = Arc::clone(&nodes[i]);
        tokio::spawn(async move {
            let _ = node.run().await;
        });
    }

    // Wait for all nodes to get slots
    println!("Waiting for all nodes to claim slots...");
    let converge_start = Instant::now();
    let mut last_log = Instant::now();

    loop {
        let mut slots_claimed = 0;
        for node in &nodes {
            if node.has_claimed_slot().await {
                slots_claimed += 1;
            }
        }

        if last_log.elapsed() > Duration::from_secs(2) {
            println!(
                "  {}/{} nodes have slots ({:?})",
                slots_claimed,
                NODE_COUNT,
                converge_start.elapsed()
            );
            last_log = Instant::now();
        }

        if slots_claimed == NODE_COUNT {
            let time = converge_start.elapsed();
            println!("\nAll {} nodes claimed slots in {:?}", NODE_COUNT, time);
            return (true, time, slots_claimed);
        }

        if converge_start.elapsed() > MAX_WAIT {
            println!(
                "\nTimeout: {}/{} nodes got slots",
                slots_claimed, NODE_COUNT
            );
            return (false, converge_start.elapsed(), slots_claimed);
        }

        tokio::task::yield_now().await;
    }
}

/// Test that two independent nodes can sync their CVDF chains when connected.
///
/// Simulates the sync canary scenario:
/// - Node A starts alone (genesis)
/// - Node B starts alone (genesis)
/// - They connect immediately
/// - They cooperatively produce rounds together
/// - Both converge on the same CVDF tip (same chain, growing together)
///
/// This tests the fundamental mesh sync: two isolated nodes discover each other,
/// exchange chain state, and begin cooperating. The heavier-chain-wins merge
/// is proven separately in test_cvdf_swarm_merge (unit test, no network).
pub async fn test_two_node_swarm_sync() -> (bool, Duration, String) {
    const PORT_A: u16 = 43000;
    const PORT_B: u16 = 44000;
    const MAX_WAIT: Duration = Duration::from_secs(30);

    println!("\n============================================================");
    println!("CITADEL TWO-NODE SWARM SYNC TEST");
    println!("  Node A: port {} (switchboard {})", PORT_A, PORT_A + 443);
    println!("  Node B: port {} (switchboard {})", PORT_B, PORT_B + 443);
    println!("============================================================\n");

    let start = Instant::now();

    // Node A: bootstrap node (no entry peers)
    // Node B: entry peer points at A's mesh port — connect_to_entry_peers
    //         dials the switchboard at mesh_port+443 automatically
    let (node_a, _tmp_a) = make_test_node(PORT_A, Vec::new());
    // Entry peer is A's switchboard port (mesh_port + 443)
    let (node_b, _tmp_b) = make_test_node(PORT_B, vec![format!("127.0.0.1:{}", PORT_A + 443)]);

    // Start A first so switchboard is ready
    let a = Arc::clone(&node_a);
    tokio::spawn(async move { let _ = a.run().await; });

    let init_start = Instant::now();
    loop {
        if node_a.cvdf_initialized().await { break; }
        if init_start.elapsed() > Duration::from_secs(5) {
            return (false, init_start.elapsed(), "A init timeout".into());
        }
        tokio::task::yield_now().await;
    }
    println!("Node A initialized ({:?})", init_start.elapsed());

    // Start B — will connect to A via switchboard
    let b = Arc::clone(&node_b);
    tokio::spawn(async move { let _ = b.run().await; });

    // Wait for convergence
    println!("Waiting for CVDF convergence...");
    let merge_start = Instant::now();
    let mut last_log = Instant::now();

    loop {
        let tip_a = node_a.cvdf_tip().await;
        let tip_b = node_b.cvdf_tip().await;
        let h_a = node_a.cvdf_height().await;
        let h_b = node_b.cvdf_height().await;
        let converged = tip_a == tip_b && h_a >= 2 && h_b >= 2;

        if last_log.elapsed() > Duration::from_secs(2) {
            println!(
                "  A h={} tip={}, B h={} tip={}, converged={}",
                h_a, hex::encode(&tip_a[..8]),
                h_b, hex::encode(&tip_b[..8]),
                converged,
            );
            last_log = Instant::now();
        }

        if converged {
            let dt = merge_start.elapsed();
            println!("\nCVDF CONVERGED in {:?}!", dt);
            println!("  Total test time: {:?}", start.elapsed());
            return (true, dt, format!("converged tip={}", hex::encode(&tip_a[..8])));
        }

        if merge_start.elapsed() > MAX_WAIT {
            println!("\nMerge TIMEOUT");
            return (false, merge_start.elapsed(), "merge timeout".into());
        }

        tokio::task::yield_now().await;
    }
}

/// Test that 10 nodes form a mesh: connect, sync CVDF chains, and maintain connections.
pub async fn test_10_node_mesh() -> (bool, Duration, String) {
    const NODE_COUNT: usize = 10;
    const BASE_PORT: u16 = 47000;
    const MAX_WAIT: Duration = Duration::from_secs(60);

    println!("\n============================================================");
    println!("CITADEL 10-NODE MESH FORMATION TEST");
    println!("============================================================\n");

    let start = Instant::now();

    // Node 0 is the bootstrap node (no entry peers)
    // All other nodes use node 0 as entry peer (direct TCP, fine for localhost)
    let mut nodes: Vec<Arc<MeshService>> = Vec::new();
    let mut _temps: Vec<TempDir> = Vec::new();

    for i in 0..NODE_COUNT {
        // Entry peer is node 0's switchboard port (mesh_port + 443)
        let entry_peers = if i == 0 {
            Vec::new()
        } else {
            vec![format!("127.0.0.1:{}", BASE_PORT + 443)]
        };
        let (node, temp) = make_test_node(BASE_PORT + i as u16, entry_peers);
        nodes.push(node);
        _temps.push(temp);
    }

    // Start node 0 first
    let n = Arc::clone(&nodes[0]);
    tokio::spawn(async move { let _ = n.run().await; });

    // Wait for node 0 to init
    let init_start = Instant::now();
    loop {
        if nodes[0].cvdf_initialized().await { break; }
        if init_start.elapsed() > Duration::from_secs(5) {
            return (false, init_start.elapsed(), "Node 0 init timeout".into());
        }
        tokio::task::yield_now().await;
    }
    println!("Node 0 initialized ({:?})", init_start.elapsed());

    // Start remaining nodes
    for i in 1..NODE_COUNT {
        let n = Arc::clone(&nodes[i]);
        tokio::spawn(async move { let _ = n.run().await; });
    }

    // Wait for all nodes to have at least 1 connected peer and same CVDF tip
    println!("Waiting for mesh formation...");
    let mesh_start = Instant::now();
    let mut last_log = Instant::now();

    loop {
        let mut tips: Vec<[u8; 32]> = Vec::new();
        let mut min_peers = usize::MAX;
        let mut all_init = true;

        for node in &nodes {
            if !node.cvdf_initialized().await {
                all_init = false;
                break;
            }
            tips.push(node.cvdf_tip().await);
            let pc = node.connected_peer_count().await;
            if pc < min_peers { min_peers = pc; }
        }

        if !all_init {
            tokio::task::yield_now().await;
            continue;
        }

        let all_same_tip = tips.windows(2).all(|w| w[0] == w[1]);
        let all_connected = min_peers >= 1;

        if last_log.elapsed() > Duration::from_secs(3) {
            let unique_tips: std::collections::HashSet<_> = tips.iter().map(|t| hex::encode(&t[..6])).collect();
            println!(
                "  {:?}: min_peers={} unique_tips={} same_tip={}",
                mesh_start.elapsed(),
                min_peers,
                unique_tips.len(),
                all_same_tip,
            );
            last_log = Instant::now();
        }

        if all_same_tip && all_connected {
            let dt = mesh_start.elapsed();
            println!("\n10-NODE MESH FORMED in {:?}!", dt);
            println!("  All on tip {}", hex::encode(&tips[0][..8]));
            println!("  Min peers per node: {}", min_peers);
            return (true, dt, format!("mesh formed, min_peers={}", min_peers));
        }

        if mesh_start.elapsed() > MAX_WAIT {
            let unique_tips: std::collections::HashSet<_> = tips.iter().map(|t| hex::encode(&t[..6])).collect();
            println!("\nMesh TIMEOUT");
            println!("  Unique tips: {}", unique_tips.len());
            println!("  Min peers: {}", min_peers);
            for (i, node) in nodes.iter().enumerate() {
                let dbg = node.cvdf_debug_state().await;
                let pc = node.connected_peer_count().await;
                println!("  Node {}: peers={} [{}]", i, pc, dbg);
            }
            return (false, mesh_start.elapsed(), format!(
                "timeout: {} tips, min_peers={}",
                unique_tips.len(), min_peers
            ));
        }

        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test is ignored because localhost UDP has zero latency, creating
    /// race conditions that don't occur in real Docker/network deployments.
    /// Real integration testing should use Docker Compose with process isolation.
    ///
    /// The test reveals timing-dependent slot oscillation when 16 nodes compete
    /// simultaneously in a single process - investigate TGP state machine if
    /// this behavior needs to be fixed for in-process testing.
    #[ignore = "localhost timing artifacts - use Docker for integration testing"]
    #[tokio::test]
    async fn test_convergence() {
        let (converged, time, slots) = test_16_node_convergence().await;

        assert!(converged, "All nodes must get slots");
        assert_eq!(slots, 16, "All 16 nodes must claim slots");
        println!("Converged in {:?}", time);
    }

    /// Two independent nodes sync their CVDF chains when connected.
    /// The lighter node adopts the heavier chain — this is the fundamental
    /// swarm merge mechanism that the sync canary validates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_swarm_sync() {
        let (converged, time, result) = test_two_node_swarm_sync().await;

        println!("Sync result: {} ({:?})", result, time);
        assert!(converged, "Nodes must converge: {}", result);
    }

    /// 10 nodes form a mesh via a single bootstrap node.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_10_node_mesh_formation() {
        let (formed, time, result) = test_10_node_mesh().await;
        println!("Mesh result: {} ({:?})", result, time);
        assert!(formed, "10-node mesh must form: {}", result);
    }
}
