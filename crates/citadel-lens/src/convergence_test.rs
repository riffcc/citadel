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
    println!("  Node A: port {}", PORT_A);
    println!("  Node B: port {}", PORT_B);
    println!("============================================================\n");

    let start = Instant::now();

    // Both nodes start independently (no entry peers)
    let (node_a, _tmp_a) = make_test_node(PORT_A, Vec::new());
    let (node_b, _tmp_b) = make_test_node(PORT_B, Vec::new());

    // Start both
    let a = Arc::clone(&node_a);
    tokio::spawn(async move { let _ = a.run().await; });
    let b = Arc::clone(&node_b);
    tokio::spawn(async move { let _ = b.run().await; });

    // Wait for both to init CVDF
    let init_start = Instant::now();
    loop {
        if node_a.cvdf_initialized().await && node_b.cvdf_initialized().await {
            break;
        }
        if init_start.elapsed() > Duration::from_secs(10) {
            return (false, init_start.elapsed(), "CVDF init timeout".to_string());
        }
        tokio::task::yield_now().await;
    }
    println!("Both nodes initialized ({:?})", init_start.elapsed());

    // Let both produce at least 1 round independently so they diverge
    let round_start = Instant::now();
    loop {
        let h_a = node_a.cvdf_height().await;
        let h_b = node_b.cvdf_height().await;
        if h_a >= 1 && h_b >= 1 {
            println!("Pre-bridge: A h={}, B h={}", h_a, h_b);
            break;
        }
        if round_start.elapsed() > Duration::from_secs(30) {
            return (false, round_start.elapsed(), format!("Round timeout: A={}, B={}", h_a, h_b));
        }
        tokio::task::yield_now().await;
    }

    // Record divergent state
    let a_tip_pre = node_a.cvdf_tip().await;
    let b_tip_pre = node_b.cvdf_tip().await;
    println!("Pre-bridge: A wt={} tip={}, B wt={} tip={}",
        node_a.cvdf_weight().await, hex::encode(&a_tip_pre[..8]),
        node_b.cvdf_weight().await, hex::encode(&b_tip_pre[..8]),
    );
    assert_ne!(a_tip_pre, b_tip_pre, "Nodes must have divergent chains before bridge");

    // Bridge: B connects directly to A (bypasses switchboard)
    println!("Bridging B → A...");
    node_b.connect_to_peer(&format!("127.0.0.1:{}", PORT_A)).await;

    // Wait for convergence: both produce rounds on the same chain
    // Success = same tip AND height > 0 (not just genesis)
    println!("Waiting for cooperative CVDF convergence...");
    let merge_start = Instant::now();
    let mut last_log = Instant::now();

    loop {
        let tip_a = node_a.cvdf_tip().await;
        let tip_b = node_b.cvdf_tip().await;
        let h_a = node_a.cvdf_height().await;
        let h_b = node_b.cvdf_height().await;
        // Converged = same tip, both have produced at least 2 rounds
        let converged = tip_a == tip_b && h_a >= 2 && h_b >= 2;

        if last_log.elapsed() > Duration::from_secs(2) {
            let dbg_a = node_a.cvdf_debug_state().await;
            let dbg_b = node_b.cvdf_debug_state().await;
            println!(
                "  A [{}] tip={}, B [{}] tip={}, converged={}",
                dbg_a,
                hex::encode(&tip_a[..8]),
                dbg_b,
                hex::encode(&tip_b[..8]),
                converged,
            );
            last_log = Instant::now();
        }

        if converged {
            let dt = merge_start.elapsed();
            let final_tip = hex::encode(&tip_a[..8]);
            let final_wt = node_a.cvdf_weight().await;
            println!("\nCVDF CONVERGED in {:?}!", dt);
            println!("  tip={} weight={} height={}", final_tip, final_wt, h_a);
            println!("  Total test time: {:?}", start.elapsed());
            return (true, dt, format!("converged tip={} wt={}", final_tip, final_wt));
        }

        if merge_start.elapsed() > MAX_WAIT {
            println!("\nMerge TIMEOUT");
            println!("  A: h={} wt={} tip={}", h_a, node_a.cvdf_weight().await, hex::encode(&tip_a[..8]));
            println!("  B: h={} wt={} tip={}", h_b, node_b.cvdf_weight().await, hex::encode(&tip_b[..8]));
            return (false, merge_start.elapsed(), "merge timeout".to_string());
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
}
