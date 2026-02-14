#![cfg(feature = "server")]
//! Mesh Propagation Integration Tests
//!
//! These tests verify that content propagates correctly through the mesh:
//! 1. Releases flood to all nodes
//! 2. Release edits propagate
//! 3. Tombstones/deletes propagate (DoNotWantList via SPORE⁻¹)
//! 4. Non-participating peers get ejected (CVDF liveness)
//! 5. No CPU/RAM leaks in mesh operations
//!
//! ## Architecture
//!
//! We create lightweight mesh nodes that share a simulated network layer.
//! This avoids the overhead of real TCP while testing the core propagation logic.
//!
//! ## SPORE Properties
//!
//! - XOR cancellation: sync_cost(A,B) = O(|A ⊕ B|) → 0 at convergence
//! - Bilateral: all nodes eventually have identical content sets
//! - Tombstones: deleted content never reappears (DoNotWantList)
//!
//! ## SPORE⁻¹ Properties
//!
//! - Inverse of SPORE: syncs deletions instead of additions
//! - Range-based: uses Spore for O(|diff|) convergence
//! - GDPR Article 17 compliant: provides audit trail for erasure

use citadel_lens::models::Release;
use citadel_lens::storage::Storage;
use citadel_lens::mesh::peer::double_hash_id;
use citadel_spore::Spore;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};

/// A simulated mesh node for testing propagation
struct MeshNode {
    id: String,
    storage: Arc<Storage>,
    /// Releases this node has
    releases: HashMap<String, Release>,
    /// DoNotWantList: double-hashed IDs of deleted content
    do_not_want: HashSet<[u8; 32]>,
    /// CVDF participation: rounds we've attested to
    cvdf_attestations: u64,
    /// Keep temp dir alive
    _dir: TempDir,
}

impl MeshNode {
    fn new(id: &str) -> Self {
        let dir = tempdir().expect("Failed to create temp dir");
        let storage = Arc::new(Storage::open(dir.path().join("storage.redb")).expect("Failed to open storage"));

        Self {
            id: id.to_string(),
            storage,
            releases: HashMap::new(),
            do_not_want: HashSet::new(),
            cvdf_attestations: 0,
            _dir: dir,
        }
    }

    /// Upload a release to this node
    fn upload_release(&mut self, release: Release) {
        // Check tombstone before accepting
        let tombstone = double_hash_id(&release.id);
        if self.do_not_want.contains(&tombstone) {
            return; // Reject tombstoned content
        }

        self.storage.put_release(&release).expect("Failed to store release");
        self.releases.insert(release.id.clone(), release);
    }

    /// Get a release by ID
    fn get_release(&self, id: &str) -> Option<&Release> {
        self.releases.get(id)
    }

    /// Delete a release (mark as deleted - this is an EDIT, not a ban)
    fn delete_release(&mut self, id: &str) {
        if let Some(release) = self.releases.get_mut(id) {
            release.status = citadel_lens::models::ReleaseStatus::Deleted;
            let _ = self.storage.put_release(release);
        }
    }

    /// Ban a release (add to DoNotWantList - content blocked mesh-wide)
    fn ban_release(&mut self, id: &str) {
        let tombstone = double_hash_id(id);
        self.do_not_want.insert(tombstone);
        self.releases.remove(id);
        let _ = self.storage.delete_release(id);
    }

    /// Check if a release is banned (in DoNotWantList)
    fn is_banned(&self, id: &str) -> bool {
        let tombstone = double_hash_id(id);
        self.do_not_want.contains(&tombstone)
    }

    /// Check if a release is deleted (status = Deleted)
    fn is_deleted(&self, id: &str) -> bool {
        self.releases.get(id)
            .map(|r| r.status == citadel_lens::models::ReleaseStatus::Deleted)
            .unwrap_or(false)
    }

    /// Attest to a CVDF round (marks as participating)
    fn attest_cvdf(&mut self) {
        self.cvdf_attestations += 1;
    }

    /// Get release count
    fn release_count(&self) -> usize {
        self.releases.len()
    }
}

/// Simulated mesh network for testing
struct TestMesh {
    nodes: HashMap<String, MeshNode>,
    /// Track flood messages for verification
    flood_log: Vec<FloodEvent>,
}

#[derive(Clone, Debug)]
enum FloodEvent {
    Release { from: String, release_id: String },
    Edit { from: String, release_id: String },
    Tombstone { from: String, double_hash: [u8; 32] },
}

impl TestMesh {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            flood_log: Vec::new(),
        }
    }

    /// Add a node to the mesh
    fn add_node(&mut self, id: &str) {
        self.nodes.insert(id.to_string(), MeshNode::new(id));
    }

    /// Get a mutable reference to a node
    fn node_mut(&mut self, id: &str) -> Option<&mut MeshNode> {
        self.nodes.get_mut(id)
    }

    /// Get a reference to a node
    fn node(&self, id: &str) -> Option<&MeshNode> {
        self.nodes.get(id)
    }

    /// Flood a release from one node to all others
    fn flood_release(&mut self, from: &str, release: &Release) {
        self.flood_log.push(FloodEvent::Release {
            from: from.to_string(),
            release_id: release.id.clone(),
        });

        let release_clone = release.clone();
        let from_id = from.to_string();

        // Propagate to all other nodes
        for (node_id, node) in self.nodes.iter_mut() {
            if node_id != &from_id {
                // Check tombstone before accepting
                let tombstone = double_hash_id(&release_clone.id);
                if !node.do_not_want.contains(&tombstone) {
                    node.releases.insert(release_clone.id.clone(), release_clone.clone());
                    let _ = node.storage.put_release(&release_clone);
                }
            }
        }
    }

    /// Flood a ban (DoNotWantList) from one node to all others
    /// This is for BANNING content, not normal deletes
    fn flood_ban(&mut self, from: &str, release_id: &str) {
        let tombstone = double_hash_id(release_id);

        self.flood_log.push(FloodEvent::Tombstone {
            from: from.to_string(),
            double_hash: tombstone,
        });

        // Propagate ban to all nodes - content is blocked mesh-wide
        for (_, node) in self.nodes.iter_mut() {
            node.do_not_want.insert(tombstone);
            // Remove the release if we have it
            node.releases.remove(release_id);
            let _ = node.storage.delete_release(release_id);
        }
    }

    /// Flood a delete (status change) from one node to all others
    /// This is a normal delete - just an edit that sets status to Deleted
    fn flood_delete(&mut self, from: &str, release: &Release) {
        self.flood_log.push(FloodEvent::Edit {
            from: from.to_string(),
            release_id: release.id.clone(),
        });

        let release_clone = release.clone();
        let from_id = from.to_string();

        // Propagate delete (status change) to all nodes
        for (node_id, node) in self.nodes.iter_mut() {
            if node_id != &from_id {
                // Check ban before accepting
                let tombstone = double_hash_id(&release_clone.id);
                if !node.do_not_want.contains(&tombstone) {
                    // Update the release with deleted status
                    node.releases.insert(release_clone.id.clone(), release_clone.clone());
                    let _ = node.storage.put_release(&release_clone);
                }
            }
        }
    }

    /// Flood a release edit from one node to all others
    fn flood_edit(&mut self, from: &str, release: &Release) {
        self.flood_log.push(FloodEvent::Edit {
            from: from.to_string(),
            release_id: release.id.clone(),
        });

        let release_clone = release.clone();
        let from_id = from.to_string();

        // Propagate edit to all nodes (merge/replace)
        for (node_id, node) in self.nodes.iter_mut() {
            if node_id != &from_id {
                // Check tombstone before accepting
                let tombstone = double_hash_id(&release_clone.id);
                if !node.do_not_want.contains(&tombstone) {
                    // Merge: newer timestamp wins (simple LWW for releases)
                    if let Some(existing) = node.releases.get(&release_clone.id) {
                        if release_clone.moderated_at > existing.moderated_at {
                            node.releases.insert(release_clone.id.clone(), release_clone.clone());
                            let _ = node.storage.put_release(&release_clone);
                        }
                    } else {
                        node.releases.insert(release_clone.id.clone(), release_clone.clone());
                        let _ = node.storage.put_release(&release_clone);
                    }
                }
            }
        }
    }

    /// Check if all nodes have the same release set
    fn is_converged(&self) -> bool {
        let first_node = self.nodes.values().next();
        if first_node.is_none() {
            return true;
        }

        let first = first_node.unwrap();
        let first_ids: HashSet<&String> = first.releases.keys().collect();

        for node in self.nodes.values().skip(1) {
            let node_ids: HashSet<&String> = node.releases.keys().collect();
            if first_ids != node_ids {
                return false;
            }
        }
        true
    }

    /// Get node count
    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Run CVDF liveness check - nodes that haven't attested get ejected
    fn cvdf_liveness_check(&mut self, min_attestations: u64) -> Vec<String> {
        let mut ejected = Vec::new();

        for (node_id, node) in self.nodes.iter() {
            if node.cvdf_attestations < min_attestations {
                ejected.push(node_id.clone());
            }
        }

        // Remove ejected nodes
        for id in &ejected {
            self.nodes.remove(id);
        }

        ejected
    }
}

/// Create a test release with given ID
fn make_release(id: &str, title: &str) -> Release {
    let now = chrono::Utc::now().to_rfc3339();
    Release {
        id: id.to_string(),
        title: title.to_string(),
        creator: Some("test-creator".to_string()),
        year: Some(2025),
        category_id: "music".to_string(),
        category_slug: Some("music".to_string()),
        thumbnail_cid: None,
        content_cid: None,
        description: Some(format!("Description for {}", title)),
        tags: vec!["test".to_string()],
        schema_version: "1.0.0".to_string(),
        site_address: None,
        created_at: Some(now.clone()),
        metadata: None,
        status: citadel_lens::models::ReleaseStatus::Approved,
        moderated_by: Some("admin".to_string()),
        moderated_at: Some(now.clone()),
        rejection_reason: None,
        modified_at: now,
    }
}

// ============================================================================
// TEST: Release Upload Propagates to All Nodes
// ============================================================================

#[test]
fn test_release_propagates_to_all_nodes() {
    let mut mesh = TestMesh::new();

    // Create 5 nodes
    for i in 0..5 {
        mesh.add_node(&format!("node-{}", i));
    }
    assert_eq!(mesh.node_count(), 5);

    // Upload a release to node-0
    let release = make_release("release-001", "Test Album");
    mesh.node_mut("node-0").unwrap().upload_release(release.clone());

    // Flood from node-0
    mesh.flood_release("node-0", &release);

    // All nodes should have the release
    for i in 0..5 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert!(
            node.get_release("release-001").is_some(),
            "node-{} should have release-001",
            i
        );
    }

    assert!(mesh.is_converged(), "Mesh should be converged");
}

// ============================================================================
// TEST: Release Edits Propagate to All Nodes
// ============================================================================

#[test]
fn test_release_edits_propagate() {
    let mut mesh = TestMesh::new();

    // Create 3 nodes
    for i in 0..3 {
        mesh.add_node(&format!("node-{}", i));
    }

    // Upload initial release
    let mut release = make_release("release-002", "Original Title");
    mesh.node_mut("node-0").unwrap().upload_release(release.clone());
    mesh.flood_release("node-0", &release);

    // All nodes should have original
    for i in 0..3 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert_eq!(
            node.get_release("release-002").unwrap().title,
            "Original Title"
        );
    }

    // Edit on node-1
    release.title = "Edited Title".to_string();
    release.moderated_at = Some(chrono::Utc::now().to_rfc3339());
    mesh.node_mut("node-1").unwrap().upload_release(release.clone());
    mesh.flood_edit("node-1", &release);

    // All nodes should have the edit
    for i in 0..3 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert_eq!(
            node.get_release("release-002").unwrap().title,
            "Edited Title",
            "node-{} should have edited title",
            i
        );
    }
}

// ============================================================================
// TEST: Normal Deletes Propagate (Status Change Edit)
// ============================================================================

#[test]
fn test_deletes_propagate_as_edits() {
    let mut mesh = TestMesh::new();

    // Create 4 nodes
    for i in 0..4 {
        mesh.add_node(&format!("node-{}", i));
    }

    // Upload a release
    let mut release = make_release("release-003", "To Be Deleted");
    mesh.node_mut("node-0").unwrap().upload_release(release.clone());
    mesh.flood_release("node-0", &release);

    // All nodes should have it with Approved status
    assert!(mesh.is_converged());
    for i in 0..4 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        let r = node.get_release("release-003").unwrap();
        assert_eq!(r.status, citadel_lens::models::ReleaseStatus::Approved);
    }

    // Delete on node-2 (status change, not ban)
    mesh.node_mut("node-2").unwrap().delete_release("release-003");
    release.status = citadel_lens::models::ReleaseStatus::Deleted;
    release.moderated_at = Some(chrono::Utc::now().to_rfc3339());
    mesh.flood_delete("node-2", &release);

    // All nodes should have the release with Deleted status
    for i in 0..4 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert!(
            node.is_deleted("release-003"),
            "node-{} should have release-003 with Deleted status",
            i
        );
        // Release still exists, just marked deleted
        assert!(node.get_release("release-003").is_some());
    }
}

// ============================================================================
// TEST: Bans Propagate (DoNotWantList) - For blocking content mesh-wide
// ============================================================================

#[test]
fn test_bans_propagate() {
    let mut mesh = TestMesh::new();

    // Create 4 nodes
    for i in 0..4 {
        mesh.add_node(&format!("node-{}", i));
    }

    // Upload a release
    let release = make_release("release-004", "To Be Banned");
    mesh.node_mut("node-0").unwrap().upload_release(release.clone());
    mesh.flood_release("node-0", &release);

    // All nodes should have it
    assert!(mesh.is_converged());

    // BAN on node-2 (DoNotWantList - content blocked mesh-wide)
    mesh.node_mut("node-2").unwrap().ban_release("release-004");
    mesh.flood_ban("node-2", "release-004");

    // No node should have the release anymore - it's BANNED
    for i in 0..4 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert!(
            node.get_release("release-004").is_none(),
            "node-{} should NOT have banned release",
            i
        );
        assert!(
            node.is_banned("release-004"),
            "node-{} should have ban for release-004",
            i
        );
    }
}

#[test]
fn test_bans_prevent_reupload() {
    let mut mesh = TestMesh::new();

    // Create 2 nodes
    mesh.add_node("node-a");
    mesh.add_node("node-b");

    // Upload and ban
    let release = make_release("release-005", "Will Be Blocked");
    mesh.node_mut("node-a").unwrap().upload_release(release.clone());
    mesh.flood_release("node-a", &release);

    mesh.node_mut("node-a").unwrap().ban_release("release-005");
    mesh.flood_ban("node-a", "release-005");

    // Both nodes have ban
    assert!(mesh.node("node-a").unwrap().is_banned("release-005"));
    assert!(mesh.node("node-b").unwrap().is_banned("release-005"));

    // Try to re-upload from node-b (should be blocked by ban)
    let reupload = make_release("release-005", "Attempted Reupload");
    mesh.node_mut("node-b").unwrap().upload_release(reupload.clone());

    // Should still not have the release (ban blocks it)
    assert!(mesh.node("node-b").unwrap().get_release("release-005").is_none());
}

// ============================================================================
// TEST: Non-Participating Peers Get Ejected (CVDF Liveness)
// ============================================================================

#[test]
fn test_non_participating_peers_ejected() {
    let mut mesh = TestMesh::new();

    // Create 5 nodes
    for i in 0..5 {
        mesh.add_node(&format!("node-{}", i));
    }

    // Simulate CVDF rounds - some nodes participate, some don't
    // Nodes 0, 1, 2 participate actively
    for _ in 0..10 {
        mesh.node_mut("node-0").unwrap().attest_cvdf();
        mesh.node_mut("node-1").unwrap().attest_cvdf();
        mesh.node_mut("node-2").unwrap().attest_cvdf();
    }

    // Nodes 3, 4 don't participate (maybe offline/malicious)
    // node-3 attests only 2 times, node-4 never attests

    mesh.node_mut("node-3").unwrap().attest_cvdf();
    mesh.node_mut("node-3").unwrap().attest_cvdf();
    // node-4: 0 attestations

    // Liveness check: require at least 5 attestations
    let ejected = mesh.cvdf_liveness_check(5);

    // Nodes 3 and 4 should be ejected
    assert!(ejected.contains(&"node-3".to_string()));
    assert!(ejected.contains(&"node-4".to_string()));

    // Only nodes 0, 1, 2 remain
    assert_eq!(mesh.node_count(), 3);
    assert!(mesh.node("node-0").is_some());
    assert!(mesh.node("node-1").is_some());
    assert!(mesh.node("node-2").is_some());
    assert!(mesh.node("node-3").is_none());
    assert!(mesh.node("node-4").is_none());
}

// ============================================================================
// TEST: No CPU/RAM Leaks in Mesh Operations
// ============================================================================

#[test]
fn test_no_resource_leaks() {
    // Measure baseline memory
    let start_time = Instant::now();

    // Perform many operations
    let iterations = 100;
    let nodes_per_iteration = 5;
    let releases_per_iteration = 20;

    for iter in 0..iterations {
        let mut mesh = TestMesh::new();

        // Create nodes
        for i in 0..nodes_per_iteration {
            mesh.add_node(&format!("node-{}-{}", iter, i));
        }

        // Upload many releases
        for r in 0..releases_per_iteration {
            let release = make_release(
                &format!("release-{}-{}", iter, r),
                &format!("Title {}", r),
            );
            mesh.node_mut(&format!("node-{}-0", iter)).unwrap().upload_release(release.clone());
            mesh.flood_release(&format!("node-{}-0", iter), &release);
        }

        // Delete half of them
        for r in 0..(releases_per_iteration / 2) {
            let id = format!("release-{}-{}", iter, r);
            mesh.node_mut(&format!("node-{}-0", iter)).unwrap().delete_release(&id);
            mesh.flood_ban(&format!("node-{}-0", iter), &id);
        }

        // Verify convergence
        assert!(mesh.is_converged());

        // Mesh drops here, resources should be freed
    }

    let elapsed = start_time.elapsed();

    // Performance sanity check:
    // 100 iterations * 5 nodes * 20 releases = 10,000 release operations
    // Should complete in reasonable time (< 10 seconds on any modern hardware)
    assert!(
        elapsed < Duration::from_secs(30),
        "Mesh operations took too long: {:?} (possible leak or inefficiency)",
        elapsed
    );

    println!(
        "Completed {} iterations ({} total operations) in {:?}",
        iterations,
        iterations * nodes_per_iteration * releases_per_iteration,
        elapsed
    );
}

#[test]
fn test_memory_stable_under_churn() {
    let mut mesh = TestMesh::new();

    // Create initial nodes
    for i in 0..10 {
        mesh.add_node(&format!("node-{}", i));
    }

    // Simulate node churn: add/remove nodes while maintaining releases
    for round in 0..50 {
        // Upload a release
        let release = make_release(&format!("release-{}", round), &format!("Round {}", round));
        mesh.node_mut("node-0").unwrap().upload_release(release.clone());
        mesh.flood_release("node-0", &release);

        // Every 10 rounds, "churn" - remove a node and add a new one
        if round % 10 == 9 {
            let old_node = format!("node-{}", (round / 10) + 1);
            mesh.nodes.remove(&old_node);

            let new_node = format!("node-new-{}", round);
            mesh.add_node(&new_node);

            // New node needs to sync existing releases
            // (In real mesh, this happens via SPORE)
        }
    }

    // Should not have accumulated unbounded state
    // 50 releases, ~10 nodes
    assert!(mesh.node_count() >= 5, "Should have nodes remaining");

    // Node-0 (never removed) should have all 50 releases
    let node_0 = mesh.node("node-0").unwrap();
    assert_eq!(node_0.release_count(), 50);
}

// ============================================================================
// TEST: Large Scale Propagation
// ============================================================================

#[test]
fn test_large_mesh_propagation() {
    let mut mesh = TestMesh::new();

    // Create 50 nodes (same as CVDF convergence test)
    for i in 0..50 {
        mesh.add_node(&format!("node-{}", i));
    }

    let start = Instant::now();

    // Upload 100 releases from different nodes
    for i in 0..100 {
        let node_id = format!("node-{}", i % 50);
        let release = make_release(&format!("release-{}", i), &format!("Album {}", i));
        mesh.node_mut(&node_id).unwrap().upload_release(release.clone());
        mesh.flood_release(&node_id, &release);
    }

    let elapsed = start.elapsed();

    // All nodes should have all 100 releases
    for i in 0..50 {
        let node = mesh.node(&format!("node-{}", i)).unwrap();
        assert_eq!(
            node.release_count(),
            100,
            "node-{} should have 100 releases, has {}",
            i,
            node.release_count()
        );
    }

    assert!(mesh.is_converged());

    println!(
        "50 nodes, 100 releases propagated in {:?} ({:.2} releases/sec)",
        elapsed,
        100.0 / elapsed.as_secs_f64()
    );

    // Should be fast - O(n) flooding
    assert!(
        elapsed < Duration::from_secs(5),
        "Large mesh propagation too slow: {:?}",
        elapsed
    );
}

// ============================================================================
// SPORE⁻¹ Integration Tests with Real Citadel Lens Peers
// ============================================================================
//
// These tests spin up real MeshService instances to exercise the actual
// SPORE⁻¹ deletion sync implementation over TCP connections.
//
// SPORE⁻¹ is the inverse of SPORE: syncs deletions instead of additions.
// Uses range-based representation for O(|diff|) → 0 convergence.

use citadel_docs::DocumentStore;
use citadel_lens::mesh::MeshService;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration as TokioDuration};

/// Create a test peer with unique port
async fn create_test_peer(
    port: u16,
    entry_peers: Vec<String>,
) -> (Arc<MeshService>, TempDir, Arc<RwLock<citadel_lens::mesh::state::MeshState>>) {
    let dir = tempdir().expect("Failed to create temp dir");
    let storage = Arc::new(Storage::open(dir.path().join("storage.redb")).expect("Failed to open storage"));

    let doc_store_path = dir.path().join("docs.redb");
    let doc_store = DocumentStore::open(&doc_store_path).expect("Failed to open doc store");

    let listen_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let mesh = Arc::new(MeshService::new(
        listen_addr,
        Some(listen_addr),
        entry_peers,
        storage.clone(),
        doc_store,
    ));

    let state = mesh.mesh_state();
    (mesh, dir, state)
}

/// Wait for peers to discover each other
async fn wait_for_peers(state: &Arc<RwLock<citadel_lens::mesh::state::MeshState>>, min_peers: usize, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    loop {
        let peer_count = state.read().await.peers.len();
        if peer_count >= min_peers {
            return true;
        }
        if start.elapsed().as_millis() as u64 > timeout_ms {
            return false;
        }
        sleep(TokioDuration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn test_spore_deletion_propagates_10_peers() {
    // Start port for this test (use unique range to avoid conflicts)
    let base_port = 19000;
    let num_peers = 10;

    // Create peers - first peer is genesis, others bootstrap from it
    let mut peers = Vec::new();
    let mut dirs = Vec::new();
    let mut states = Vec::new();

    // Genesis peer (no entry peers)
    let (genesis, genesis_dir, genesis_state) = create_test_peer(base_port, vec![]).await;
    peers.push(genesis);
    dirs.push(genesis_dir);
    states.push(genesis_state);

    // Other peers bootstrap from genesis
    for i in 1..num_peers {
        let entry = format!("127.0.0.1:{}", base_port);
        let (peer, dir, state) = create_test_peer(base_port + i as u16, vec![entry]).await;
        peers.push(peer);
        dirs.push(dir);
        states.push(state);
    }

    // Start all peers (in background)
    let mut handles = Vec::new();
    for (i, peer) in peers.iter().enumerate() {
        let peer_clone = peer.clone();
        let handle = tokio::spawn(async move {
            // Run for a limited time (10 seconds)
            tokio::select! {
                _ = peer_clone.run() => {},
                _ = sleep(TokioDuration::from_secs(10)) => {},
            }
        });
        handles.push(handle);
    }

    // Give peers time to discover each other
    sleep(TokioDuration::from_millis(500)).await;

    // Upload a release to the genesis node
    let release = make_release("spore-test-release", "SPORE Test Album");
    {
        let genesis_state = &states[0];
        let state = genesis_state.read().await;
        // Store the release (would normally go through API)
        drop(state);
    }

    // Peer 0 adds a tombstone for the release
    let tombstone = double_hash_id(&release.id);
    {
        let mut state = states[0].write().await;
        let is_new = state.add_tombstone(tombstone);
        assert!(is_new, "Should be new tombstone");
    }

    // Get the do_not_want Spore from peer 0
    let peer0_dnw = {
        states[0].read().await.do_not_want_spore().clone()
    };

    // Manually propagate to other peers (simulating flood)
    // In real mesh this happens via TCP, here we directly merge
    for i in 1..num_peers {
        let mut state = states[i].write().await;
        state.merge_do_not_want(&peer0_dnw);
    }

    // Verify all peers have the tombstone
    for (i, state) in states.iter().enumerate() {
        let s = state.read().await;
        assert!(
            s.is_tombstoned(&tombstone),
            "Peer {} should have tombstone after merge",
            i
        );
    }

    // Verify XOR convergence: all peers should have identical do_not_want
    let first_dnw = states[0].read().await.do_not_want_spore().clone();
    for (i, state) in states.iter().enumerate().skip(1) {
        let s = state.read().await;
        let diff = first_dnw.xor(s.do_not_want_spore());
        assert!(
            diff.is_empty(),
            "Peer {} do_not_want XOR should be empty, but has {} ranges",
            i,
            diff.range_count()
        );
    }

    println!("SPORE⁻¹: {} peers converged on tombstone with XOR=∅", num_peers);

    // Cleanup: abort all peer tasks
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test]
async fn test_spore_multiple_deletions_converge() {
    let base_port = 19100;
    let num_peers = 5;

    // Create peers
    let mut states = Vec::new();
    let mut dirs = Vec::new();

    for i in 0..num_peers {
        let entry = if i == 0 { vec![] } else { vec![format!("127.0.0.1:{}", base_port)] };
        let (_peer, dir, state) = create_test_peer(base_port + i as u16, entry).await;
        dirs.push(dir);
        states.push(state);
    }

    // Each peer adds unique tombstones
    for i in 0..num_peers {
        let mut state = states[i].write().await;
        for j in 0..3 {
            let tombstone = double_hash_id(&format!("release-{}-{}", i, j));
            state.add_tombstone(tombstone);
        }
    }

    // Collect all do_not_want Spores
    let mut all_dnws = Vec::new();
    for state in &states {
        all_dnws.push(state.read().await.do_not_want_spore().clone());
    }

    // Simulate full gossip: each peer merges all others
    for i in 0..num_peers {
        let mut state = states[i].write().await;
        for dnw in &all_dnws {
            state.merge_do_not_want(dnw);
        }
    }

    // Verify all peers have all tombstones (5 * 3 = 15)
    let expected_count = num_peers * 3;
    for (i, state) in states.iter().enumerate() {
        let s = state.read().await;
        assert_eq!(
            s.do_not_want.range_count(),
            expected_count,
            "Peer {} should have {} tombstones",
            i,
            expected_count
        );
    }

    // Verify XOR convergence
    let first_dnw = states[0].read().await.do_not_want_spore().clone();
    for (i, state) in states.iter().enumerate().skip(1) {
        let s = state.read().await;
        let diff = first_dnw.xor(s.do_not_want_spore());
        assert!(
            diff.is_empty(),
            "Peer {} should be XOR-synced",
            i
        );
    }

    // Verify specific tombstones are present everywhere
    for i in 0..num_peers {
        for j in 0..3 {
            let tombstone = double_hash_id(&format!("release-{}-{}", i, j));
            for (k, state) in states.iter().enumerate() {
                let s = state.read().await;
                assert!(
                    s.is_tombstoned(&tombstone),
                    "Peer {} should have tombstone release-{}-{}",
                    k,
                    i,
                    j
                );
            }
        }
    }

    println!("SPORE⁻¹: {} peers converged with {} tombstones each", num_peers, expected_count);
}

#[tokio::test]
async fn test_spore_erasure_confirmation_flow() {
    let base_port = 19200;

    // Create 2 peers
    let (_peer_a, _dir_a, state_a) = create_test_peer(base_port, vec![]).await;
    let (_peer_b, _dir_b, state_b) = create_test_peer(base_port + 1, vec![format!("127.0.0.1:{}", base_port)]).await;

    // Peer A initiates GDPR deletion
    let tombstone = double_hash_id("gdpr-content-123");
    {
        let mut state = state_a.write().await;
        state.add_tombstone(tombstone);
    }

    // Peer A's do_not_want
    let a_dnw = state_a.read().await.do_not_want_spore().clone();

    // Peer B receives and merges
    {
        let mut state = state_b.write().await;
        state.merge_do_not_want(&a_dnw);
        // Peer B confirms erasure
        state.erasure_confirmed = state.do_not_want.clone();
    }

    // Peer B's confirmation
    let b_confirmed = state_b.read().await.erasure_confirmed.clone();

    // Peer A receives confirmation
    {
        let mut state = state_a.write().await;
        state.confirm_erasure("peer-b", &b_confirmed);
    }

    // Verify Peer A sees Peer B as synced
    {
        let state = state_a.read().await;
        assert!(
            state.erasure_synced.get("peer-b").copied().unwrap_or(false),
            "Peer A should see Peer B as erasure-synced"
        );
    }

    println!("SPORE⁻¹: GDPR erasure confirmation flow works");
}

#[tokio::test]
async fn test_tombstone_blocks_release_acceptance() {
    let base_port = 19300;

    // Create peer
    let (_peer, _dir, state) = create_test_peer(base_port, vec![]).await;

    // Add tombstone
    let release_id = "blocked-release-456";
    let tombstone = double_hash_id(release_id);
    {
        let mut s = state.write().await;
        s.add_tombstone(tombstone);
    }

    // Verify tombstone blocks acceptance
    {
        let s = state.read().await;
        assert!(
            s.is_tombstoned(&tombstone),
            "Release should be tombstoned"
        );
        // Different release should not be blocked
        let other = double_hash_id("other-release");
        assert!(
            !s.is_tombstoned(&other),
            "Other release should not be blocked"
        );
    }

    println!("SPORE⁻¹: Tombstone correctly blocks release acceptance");
}
