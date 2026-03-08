#![cfg(feature = "server")]
//! Convergence tests for Featured Releases with CRDT merging.
//!
//! These tests verify that FeaturedRelease documents converge correctly
//! across multiple nodes using LWW (Last-Writer-Wins) for admin-editable fields.
//!
//! ## Merge Strategy
//!
//! FeaturedRelease uses LWW based on `modified_at`:
//! - Admin-editable fields: later modified_at wins
//! - Counters (views, clicks): max (preserves all increments)
//! - Created timestamp: min (preserves original)
//!
//! ## Test Scenarios
//!
//! 1. **3-node convergence**: All nodes receive updates in different orders,
//!    verify all converge to identical state.
//!
//! 2. **Partition healing**: Two partitions evolve with different timestamps,
//!    newer edit wins for admin fields.
//!
//! 3. **Concurrent updates**: Two nodes update same document with different
//!    modified_at - later timestamp wins deterministically.
//!
//! ## The Bilateral Property
//!
//! From proofs/CitadelProofs/CRDT/Convergence.lean:
//! - `merge(a, b) = merge(b, a)` (commutative)
//! - `merge(merge(a, b), c) = merge(a, merge(b, c))` (associative)
//! - `merge(a, a) = a` (idempotent)
//!
//! These properties guarantee convergence regardless of message ordering.

use citadel_crdt::TotalMerge;
use citadel_docs::{Document, DocumentStore};
use citadel_lens::models::FeaturedRelease;
use tempfile::{tempdir, TempDir};

/// A node with its document store and backing directory.
/// We keep TempDir alive to prevent directory deletion.
struct TestNode {
    store: DocumentStore,
    _dir: TempDir,
}

impl TestNode {
    fn new() -> Self {
        let dir = tempdir().expect("Failed to create temp dir");
        let store =
            DocumentStore::open(dir.path().join("docs.redb")).expect("Failed to open store");
        Self { store, _dir: dir }
    }
}

/// Simulate sync: send all documents from src to dst (merging)
fn sync_stores(src: &DocumentStore, dst: &mut DocumentStore) {
    let docs: Vec<FeaturedRelease> = src.list().expect("Failed to list docs");
    for doc in docs {
        dst.put(&doc).expect("Failed to put doc");
    }
}

/// Helper to compare two featured releases for equality (ignoring order in sets)
fn releases_equivalent(a: &FeaturedRelease, b: &FeaturedRelease) -> bool {
    a.id == b.id
        && a.release_id == b.release_id
        && a.start_time == b.start_time
        && a.end_time == b.end_time
        && a.promoted == b.promoted
        && a.priority == b.priority
        && a.order == b.order
        && a.views == b.views
        && a.clicks == b.clicks
        && a.custom_title == b.custom_title
        && a.custom_description == b.custom_description
        && a.custom_thumbnail == b.custom_thumbnail
        && a.regions.iter().collect::<std::collections::BTreeSet<_>>()
            == b.regions.iter().collect::<std::collections::BTreeSet<_>>()
        && a.languages
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            == b.languages
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
        && a.tags.iter().collect::<std::collections::BTreeSet<_>>()
            == b.tags.iter().collect::<std::collections::BTreeSet<_>>()
        && a.variant == b.variant
        && a.created == b.created
}

#[test]
fn test_featured_release_convergence_3_nodes() {
    // Create 3 independent nodes
    let mut node_a = TestNode::new();
    let mut node_b = TestNode::new();
    let mut node_c = TestNode::new();

    // Node A creates a featured release
    let featured = FeaturedRelease::new(
        "feat-001".to_string(),
        "release-xyz".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-12-31T23:59:59Z".to_string(),
    );
    node_a.store.put(&featured).expect("Failed to put on A");

    // Sync A -> B -> C (chain topology)
    sync_stores(&node_a.store, &mut node_b.store);
    sync_stores(&node_b.store, &mut node_c.store);

    // All nodes should have the document
    let a_docs: Vec<FeaturedRelease> = node_a.store.list().unwrap();
    let b_docs: Vec<FeaturedRelease> = node_b.store.list().unwrap();
    let c_docs: Vec<FeaturedRelease> = node_c.store.list().unwrap();

    assert_eq!(a_docs.len(), 1, "Node A should have 1 doc");
    assert_eq!(b_docs.len(), 1, "Node B should have 1 doc");
    assert_eq!(c_docs.len(), 1, "Node C should have 1 doc");

    // All should be identical
    assert!(
        releases_equivalent(&a_docs[0], &b_docs[0]),
        "A and B should match"
    );
    assert!(
        releases_equivalent(&b_docs[0], &c_docs[0]),
        "B and C should match"
    );
}

#[test]
fn test_featured_release_survives_partition() {
    // Simulate network partition: nodes A and B evolve independently
    // With LWW, later modified_at wins for admin fields; counters use max
    let mut node_a = TestNode::new();
    let mut node_b = TestNode::new();

    // Both start with the same base document (set old modified_at)
    let mut base = FeaturedRelease::new(
        "feat-001".to_string(),
        "release-xyz".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-12-31T23:59:59Z".to_string(),
    );
    base.modified_at = "2025-01-01T00:00:00Z".to_string(); // Base is old
    node_a.store.put(&base).expect("A put base");
    node_b.store.put(&base).expect("B put base");

    // === PARTITION BEGINS ===

    // Node A: older edit (June 1)
    let mut a_update = base.clone();
    a_update.modified_at = "2025-06-01T00:00:00Z".to_string();
    a_update.regions = vec!["US".to_string()];
    a_update.views = 100;
    a_update.promoted = true;
    node_a.store.put(&a_update).expect("A put update");

    // Node B: newer edit (June 2) - will win for admin fields
    let mut b_update = base.clone();
    b_update.modified_at = "2025-06-02T00:00:00Z".to_string();
    b_update.regions = vec!["EU".to_string()];
    b_update.clicks = 50;
    b_update.tags = vec!["featured".to_string()];
    b_update.promoted = false;
    node_b.store.put(&b_update).expect("B put update");

    // === PARTITION HEALS ===

    // Bidirectional sync
    sync_stores(&node_a.store, &mut node_b.store);
    sync_stores(&node_b.store, &mut node_a.store);

    // Get final state from both
    let a_final: FeaturedRelease = node_a
        .store
        .list::<FeaturedRelease>()
        .unwrap()
        .pop()
        .unwrap();
    let b_final: FeaturedRelease = node_b
        .store
        .list::<FeaturedRelease>()
        .unwrap()
        .pop()
        .unwrap();

    // Should be identical
    assert!(
        releases_equivalent(&a_final, &b_final),
        "After sync, A and B should match"
    );

    // LWW: admin fields from newer (node B)
    assert_eq!(
        a_final.regions,
        vec!["EU".to_string()],
        "Regions from newer (B)"
    );
    assert!(!a_final.promoted, "Promoted from newer (B = false)");
    assert!(
        a_final.tags.contains(&"featured".to_string()),
        "Tags from newer (B)"
    );

    // Counters: max from both (preserves all increments)
    assert_eq!(a_final.views, 100, "Views preserved (max)");
    assert_eq!(a_final.clicks, 50, "Clicks preserved (max)");
}

#[test]
fn test_concurrent_featured_updates_merge() {
    // Two nodes independently update the same document
    // With LWW, later modified_at wins for all admin fields
    let mut node_a = TestNode::new();
    let mut node_b = TestNode::new();

    // Same base document (set old modified_at so updates win)
    let mut base = FeaturedRelease::new(
        "feat-001".to_string(),
        "release-xyz".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-06-30T23:59:59Z".to_string(),
    );
    base.modified_at = "2025-01-01T00:00:00Z".to_string();

    // Node A: older edit (July 1)
    let mut a_version = base.clone();
    a_version.modified_at = "2025-07-01T00:00:00Z".to_string();
    a_version.end_time = "2025-12-31T23:59:59Z".to_string();
    a_version.priority = 800;
    a_version.custom_title = Some("A's Title".to_string());
    a_version.views = 100;
    node_a.store.put(&a_version).expect("A put");

    // Node B: newer edit (July 2) - will win for admin fields
    let mut b_version = base.clone();
    b_version.modified_at = "2025-07-02T00:00:00Z".to_string();
    b_version.start_time = "2024-12-01T00:00:00Z".to_string();
    b_version.end_time = "2025-09-30T23:59:59Z".to_string();
    b_version.priority = 600;
    b_version.custom_title = Some("B's Title".to_string());
    b_version.clicks = 50;
    node_b.store.put(&b_version).expect("B put");

    // Sync both ways
    sync_stores(&node_a.store, &mut node_b.store);
    sync_stores(&node_b.store, &mut node_a.store);

    // Get final state
    let a_final: FeaturedRelease = node_a
        .store
        .list::<FeaturedRelease>()
        .unwrap()
        .pop()
        .unwrap();
    let b_final: FeaturedRelease = node_b
        .store
        .list::<FeaturedRelease>()
        .unwrap()
        .pop()
        .unwrap();

    // Must be deterministically identical
    assert!(
        releases_equivalent(&a_final, &b_final),
        "Merge must be deterministic"
    );

    // LWW: admin fields from newer (node B)
    assert_eq!(
        a_final.start_time, "2024-12-01T00:00:00Z",
        "Start from newer (B)"
    );
    assert_eq!(
        a_final.end_time, "2025-09-30T23:59:59Z",
        "End from newer (B)"
    );
    assert_eq!(a_final.priority, 600, "Priority from newer (B)");
    assert_eq!(
        a_final.custom_title,
        Some("B's Title".to_string()),
        "Title from newer (B)"
    );

    // Counters: max from both
    assert_eq!(a_final.views, 100, "Views: max");
    assert_eq!(a_final.clicks, 50, "Clicks: max");
}

#[test]
fn test_merge_commutativity_property() {
    // Verify merge(a, b) == merge(b, a) for arbitrary inputs
    // With LWW, commutativity holds because modified_at comparison is deterministic
    let a = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-06-30T23:59:59Z".to_string(),
        );
        f.modified_at = "2025-06-01T00:00:00Z".to_string();
        f.views = 100;
        f.regions = vec!["US".to_string(), "EU".to_string()];
        f.promoted = true;
        f
    };

    let b = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-03-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        f.modified_at = "2025-06-02T00:00:00Z".to_string();
        f.clicks = 50;
        f.regions = vec!["JP".to_string()];
        f.tags = vec!["promo".to_string()];
        f
    };

    let ab = a.merge(&b);
    let ba = b.merge(&a);

    assert!(releases_equivalent(&ab, &ba), "merge(a,b) == merge(b,a)");
}

#[test]
fn test_merge_associativity_property() {
    // Verify merge(merge(a, b), c) == merge(a, merge(b, c))
    // With LWW, associativity holds because the newest modified_at always wins
    let a = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-06-30T23:59:59Z".to_string(),
        );
        f.modified_at = "2025-06-01T00:00:00Z".to_string();
        f.views = 100;
        f
    };

    let b = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-03-01T00:00:00Z".to_string(),
            "2025-09-30T23:59:59Z".to_string(),
        );
        f.modified_at = "2025-06-02T00:00:00Z".to_string();
        f.clicks = 50;
        f
    };

    let c = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-02-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        f.modified_at = "2025-06-03T00:00:00Z".to_string();
        f.priority = 900;
        f
    };

    let ab_c = a.merge(&b).merge(&c);
    let a_bc = a.merge(&b.merge(&c));

    assert!(
        releases_equivalent(&ab_c, &a_bc),
        "merge(merge(a,b),c) == merge(a,merge(b,c))"
    );
}

#[test]
fn test_merge_idempotency_property() {
    // Verify merge(a, a) == a
    let a = {
        let mut f = FeaturedRelease::new(
            "feat-001".to_string(),
            "release-xyz".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
            "2025-12-31T23:59:59Z".to_string(),
        );
        f.views = 100;
        f.clicks = 50;
        f.regions = vec!["US".to_string()];
        f.promoted = true;
        f
    };

    let aa = a.merge(&a);

    assert!(releases_equivalent(&a, &aa), "merge(a,a) == a");
}

#[test]
fn test_spore_sync_efficiency() {
    // Verify SPORE tracking works for diffing
    let mut node_a = TestNode::new();
    let mut node_b = TestNode::new();

    // Both have doc 1
    let doc1 = FeaturedRelease::new(
        "feat-001".to_string(),
        "release-1".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-12-31T23:59:59Z".to_string(),
    );
    node_a.store.put(&doc1).expect("A put 1");
    node_b.store.put(&doc1).expect("B put 1");

    // Only A has doc 2
    let doc2 = FeaturedRelease::new(
        "feat-002".to_string(),
        "release-2".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-12-31T23:59:59Z".to_string(),
    );
    node_a.store.put(&doc2).expect("A put 2");

    // Only B has doc 3
    let doc3 = FeaturedRelease::new(
        "feat-003".to_string(),
        "release-3".to_string(),
        "2025-01-01T00:00:00Z".to_string(),
        "2025-12-31T23:59:59Z".to_string(),
    );
    node_b.store.put(&doc3).expect("B put 3");

    // SPORE diff should show only differences
    let diff_a_sees = node_a.store.diff(node_b.store.have_list());
    let diff_b_sees = node_b.store.diff(node_a.store.have_list());

    // A should see it needs doc3
    let doc3_id = doc3.content_id();
    let doc3_u256 = citadel_spore::U256::from_be_bytes(doc3_id.as_bytes());
    assert!(
        diff_a_sees.covers(&doc3_u256),
        "A should detect missing doc3"
    );

    // B should see it needs doc2
    let doc2_id = doc2.content_id();
    let doc2_u256 = citadel_spore::U256::from_be_bytes(doc2_id.as_bytes());
    assert!(
        diff_b_sees.covers(&doc2_u256),
        "B should detect missing doc2"
    );

    // Neither should see doc1 in diff (both have it)
    let doc1_id = doc1.content_id();
    let doc1_u256 = citadel_spore::U256::from_be_bytes(doc1_id.as_bytes());
    assert!(
        !diff_a_sees.covers(&doc1_u256),
        "doc1 should not be in A's diff"
    );
    assert!(
        !diff_b_sees.covers(&doc1_u256),
        "doc1 should not be in B's diff"
    );
}
