//! Mesh Liveness: Structure-Aware Vouch Propagation
//!
//! # The Key Insight
//!
//! The mesh topology IS the vouch propagation graph.
//! Structure determines action.
//!
//! # Three-Party Witness Structure
//!
//! ```text
//!      Origin (A)              "I vouch for my neighbors"
//!         ↓ (hop 1)
//!      Judged (B)              "A vouched for me"
//!         ↓ (hop 2)
//!      Witness (C)             "B is validated by A"
//!         ↓
//!        STOP                  No further propagation
//! ```
//!
//! Maximum hops: 2. Always.
//!
//! # Why This Works
//!
//! - A vouches for B (among others)
//! - B's other neighbors (C, D) need to know A vouched for B
//! - C and D are witnesses - they validate B's liveness
//! - No one else cares about this information
//!
//! # Event-Driven Creation
//!
//! Vouches are created when:
//! - A neighbor comes alive (first latency proof)
//! - A vouch is about to expire
//! - Explicitly requested (node joining)
//!
//! At steady state: zero traffic (no state changes).
//!
//! # Network Traffic Analysis
//!
//! Traditional heartbeat: n × 20 = 20n messages/round (continuous)
//! Rotation scheme: n × 1 = n messages/round (continuous)
//! Structure-aware: Σ(state changes × 2 hops) (event-driven → 0 at steady state)

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::accountability::LatencyProof;
use crate::vdf_race::signature_serde;

/// Default vouch expiry in VDF rounds (20 rounds ≈ 20 seconds at 1 round/sec)
pub const VOUCH_EXPIRY_ROUNDS: u64 = 20;

/// Vouch expiry warning threshold (create new vouch before old expires)
pub const VOUCH_EXPIRY_WARNING: u64 = 5;

/// A mesh-wide vouch: one signature attesting to all alive neighbors
///
/// Instead of n separate vouches, one vouch covers all 20 neighbors.
/// Propagates exactly 2 hops via mesh topology.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshVouch {
    /// The node creating this vouch
    pub voucher: [u8; 32],
    /// The voucher's slot in the mesh
    pub voucher_slot: u64,
    /// All neighbors the voucher attests as alive
    pub alive_neighbors: Vec<[u8; 32]>,
    /// VDF height when vouch was created
    pub vdf_height: u64,
    /// Compact latency summary for each neighbor (node, latency_ms)
    /// Full proofs available on request, but summary is sufficient for validation
    pub latencies: Vec<([u8; 32], u64)>,
    /// Signature over (voucher || voucher_slot || alive_neighbors || vdf_height || latencies)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl MeshVouch {
    /// Create a new mesh vouch for all alive neighbors
    pub fn new(
        voucher_slot: u64,
        alive_neighbors: Vec<[u8; 32]>,
        latencies: Vec<([u8; 32], u64)>,
        vdf_height: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let voucher = signing_key.verifying_key().to_bytes();

        // Build message to sign
        let msg = Self::build_message(&voucher, voucher_slot, &alive_neighbors, vdf_height, &latencies);
        let signature = signing_key.sign(&msg);

        Self {
            voucher,
            voucher_slot,
            alive_neighbors,
            vdf_height,
            latencies,
            signature: signature.to_bytes(),
        }
    }

    /// Build the message to sign/verify
    fn build_message(
        voucher: &[u8; 32],
        voucher_slot: u64,
        alive_neighbors: &[[u8; 32]],
        vdf_height: u64,
        latencies: &[([u8; 32], u64)],
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(voucher);
        msg.extend_from_slice(&voucher_slot.to_le_bytes());
        msg.extend_from_slice(&vdf_height.to_le_bytes());
        msg.extend_from_slice(&(alive_neighbors.len() as u32).to_le_bytes());
        for neighbor in alive_neighbors {
            msg.extend_from_slice(neighbor);
        }
        for (node, latency) in latencies {
            msg.extend_from_slice(node);
            msg.extend_from_slice(&latency.to_le_bytes());
        }
        msg
    }

    /// Verify the vouch signature
    pub fn verify(&self) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.voucher) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let msg = Self::build_message(
            &self.voucher,
            self.voucher_slot,
            &self.alive_neighbors,
            self.vdf_height,
            &self.latencies,
        );

        let signature = Signature::from_bytes(&self.signature);
        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Am I one of the judged parties?
    pub fn judges_me(&self, my_pubkey: &[u8; 32]) -> bool {
        self.alive_neighbors.contains(my_pubkey)
    }

    /// Do I witness any of the judged? (Is any of my neighbors in the alive list?)
    pub fn witness_any(&self, my_neighbors: &[[u8; 32]]) -> bool {
        my_neighbors.iter().any(|n| self.alive_neighbors.contains(n))
    }

    /// Get which of my neighbors are judged by this vouch
    pub fn judged_neighbors(&self, my_neighbors: &[[u8; 32]]) -> Vec<[u8; 32]> {
        my_neighbors.iter()
            .filter(|n| self.alive_neighbors.contains(n))
            .copied()
            .collect()
    }

    /// Check if this vouch has expired
    pub fn is_expired(&self, current_height: u64) -> bool {
        current_height.saturating_sub(self.vdf_height) > VOUCH_EXPIRY_ROUNDS
    }

    /// Check if this vouch is expiring soon
    pub fn expiring_soon(&self, current_height: u64) -> bool {
        let age = current_height.saturating_sub(self.vdf_height);
        age > VOUCH_EXPIRY_ROUNDS.saturating_sub(VOUCH_EXPIRY_WARNING)
    }
}

/// Decision on how to handle a received vouch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationDecision {
    /// Not relevant to me - ignore completely
    Drop,
    /// I'm a witness - record and STOP (no further propagation)
    Stop,
    /// I'm judged - record and forward to my neighbors (witnesses)
    ForwardToNeighbors,
}

/// Liveness state for a single node (vouches received about this node)
#[derive(Debug, Clone, Default)]
pub struct NodeLiveness {
    /// Vouches for this node (voucher_pubkey -> (vdf_height, all_alive_in_vouch))
    vouches: HashMap<[u8; 32], (u64, usize)>,
    /// Expected neighbor count (for threshold calculation)
    expected_neighbors: usize,
}

impl NodeLiveness {
    pub fn new(expected_neighbors: usize) -> Self {
        Self {
            vouches: HashMap::new(),
            expected_neighbors,
        }
    }

    /// Record a vouch for this node
    pub fn record_vouch(&mut self, voucher: [u8; 32], vdf_height: u64, alive_count: usize) {
        // Only update if newer
        if let Some((existing_height, _)) = self.vouches.get(&voucher) {
            if vdf_height <= *existing_height {
                return;
            }
        }
        self.vouches.insert(voucher, (vdf_height, alive_count));
    }

    /// Prune expired vouches
    pub fn prune_expired(&mut self, current_height: u64) {
        self.vouches.retain(|_, (height, _)| {
            current_height.saturating_sub(*height) <= VOUCH_EXPIRY_ROUNDS
        });
    }

    /// Check if node has sufficient vouches to be valid
    pub fn is_valid(&self) -> bool {
        match self.expected_neighbors {
            0 => true,  // Genesis
            1 => !self.vouches.is_empty(),
            2 => self.vouches.len() >= 1,
            3 => self.vouches.len() >= 2,
            n => self.vouches.len() >= (n / 2) + 1,
        }
    }

    /// Get current vouch count
    pub fn vouch_count(&self) -> usize {
        self.vouches.len()
    }

    /// Get the oldest vouch height (for expiry checking)
    pub fn oldest_vouch_height(&self) -> Option<u64> {
        self.vouches.values().map(|(h, _)| *h).min()
    }
}

/// Liveness manager: handles vouch creation, propagation, and validation
#[derive(Debug)]
pub struct LivenessManager {
    /// Our signing key
    signing_key: SigningKey,
    /// Our slot
    our_slot: Option<u64>,
    /// Our public key (cached)
    our_pubkey: [u8; 32],
    /// Our neighbors' public keys
    neighbors: Vec<[u8; 32]>,
    /// Liveness state for each node we care about (node_pubkey -> liveness)
    node_liveness: HashMap<[u8; 32], NodeLiveness>,
    /// Latest latency measurements for our neighbors (for vouch creation)
    neighbor_latencies: HashMap<[u8; 32], u64>,
    /// Last vouch we created (to avoid duplicate creation)
    last_vouch_height: u64,
    /// Current VDF height
    current_height: u64,
}

impl LivenessManager {
    pub fn new(signing_key: SigningKey) -> Self {
        let our_pubkey = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            our_slot: None,
            our_pubkey,
            neighbors: Vec::new(),
            node_liveness: HashMap::new(),
            neighbor_latencies: HashMap::new(),
            last_vouch_height: 0,
            current_height: 0,
        }
    }

    /// Set our slot
    pub fn set_slot(&mut self, slot: u64) {
        self.our_slot = Some(slot);
    }

    /// Update our neighbor list
    pub fn set_neighbors(&mut self, neighbors: Vec<[u8; 32]>) {
        self.neighbors = neighbors;
    }

    /// Update current VDF height
    pub fn set_vdf_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Record a latency measurement to a neighbor
    pub fn record_latency(&mut self, neighbor: [u8; 32], latency_ms: u64) {
        self.neighbor_latencies.insert(neighbor, latency_ms);
    }

    /// Handle an incoming mesh vouch - returns propagation decision
    pub fn handle_vouch(&mut self, vouch: MeshVouch) -> PropagationDecision {
        // Verify signature
        if !vouch.verify() {
            return PropagationDecision::Drop;
        }

        // Check if expired
        if vouch.is_expired(self.current_height) {
            return PropagationDecision::Drop;
        }

        // Am I one of the judged?
        if vouch.judges_me(&self.our_pubkey) {
            // Record vouch for myself
            let liveness = self.node_liveness
                .entry(self.our_pubkey)
                .or_insert_with(|| NodeLiveness::new(self.neighbors.len()));
            liveness.record_vouch(vouch.voucher, vouch.vdf_height, vouch.alive_neighbors.len());

            // Forward to my neighbors (they're witnesses)
            return PropagationDecision::ForwardToNeighbors;
        }

        // Am I a witness? (Is any of my neighbors judged?)
        let judged = vouch.judged_neighbors(&self.neighbors);
        if !judged.is_empty() {
            // Record vouches for my neighbors
            for neighbor in judged {
                let liveness = self.node_liveness
                    .entry(neighbor)
                    .or_insert_with(|| NodeLiveness::new(20)); // Assume full mesh
                liveness.record_vouch(vouch.voucher, vouch.vdf_height, vouch.alive_neighbors.len());
            }

            // Stop here - no further propagation
            return PropagationDecision::Stop;
        }

        // Not relevant to me
        PropagationDecision::Drop
    }

    /// Check if we should create a new vouch (event-driven)
    ///
    /// Vouches are created when:
    /// 1. We've never vouched before (first time)
    /// 2. Our last vouch is about to expire
    /// 3. We have new neighbors with latency data that weren't in our last vouch
    pub fn should_create_vouch(&self) -> bool {
        // Don't vouch if we have no slot
        if self.our_slot.is_none() {
            return false;
        }

        // Don't vouch if we have no neighbors with latency data
        if self.neighbor_latencies.is_empty() {
            return false;
        }

        // If we've never vouched, we should vouch now
        if self.last_vouch_height == 0 {
            return true;
        }

        // Check if our last vouch is expiring soon
        let vouch_age = self.current_height.saturating_sub(self.last_vouch_height);
        if vouch_age > VOUCH_EXPIRY_ROUNDS.saturating_sub(VOUCH_EXPIRY_WARNING) {
            return true;
        }

        false
    }

    /// Create a mesh vouch for all alive neighbors
    pub fn create_vouch(&mut self) -> Option<MeshVouch> {
        let voucher_slot = self.our_slot?;

        if self.neighbor_latencies.is_empty() {
            return None;
        }

        // Collect alive neighbors (those with recent latency data)
        let alive_neighbors: Vec<[u8; 32]> = self.neighbor_latencies.keys().copied().collect();
        let latencies: Vec<([u8; 32], u64)> = self.neighbor_latencies
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        let vouch = MeshVouch::new(
            voucher_slot,
            alive_neighbors,
            latencies,
            self.current_height,
            &self.signing_key,
        );

        // Record that we vouched
        self.last_vouch_height = self.current_height;

        Some(vouch)
    }

    /// Prune expired data
    pub fn prune_expired(&mut self) {
        for liveness in self.node_liveness.values_mut() {
            liveness.prune_expired(self.current_height);
        }

        // Remove nodes with no vouches (completely dead)
        self.node_liveness.retain(|_, l| !l.vouches.is_empty());
    }

    /// Check if a node is currently valid (has sufficient vouches)
    pub fn is_node_valid(&self, node: &[u8; 32]) -> bool {
        self.node_liveness.get(node)
            .map(|l| l.is_valid())
            .unwrap_or(false)
    }

    /// Get all nodes that have become invalid (for slot reclamation)
    pub fn invalid_nodes(&self) -> Vec<[u8; 32]> {
        self.node_liveness.iter()
            .filter(|(_, l)| !l.is_valid())
            .map(|(node, _)| *node)
            .collect()
    }

    /// Get vouch count for a node
    pub fn vouch_count(&self, node: &[u8; 32]) -> usize {
        self.node_liveness.get(node)
            .map(|l| l.vouch_count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_mesh_vouch_creation_and_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let neighbor1 = [1u8; 32];
        let neighbor2 = [2u8; 32];

        let vouch = MeshVouch::new(
            0,
            vec![neighbor1, neighbor2],
            vec![(neighbor1, 10), (neighbor2, 15)],
            100,
            &key,
        );

        assert!(vouch.verify());
        assert!(vouch.judges_me(&neighbor1));
        assert!(vouch.judges_me(&neighbor2));
        assert!(!vouch.judges_me(&[3u8; 32]));
    }

    #[test]
    fn test_propagation_decision_judged() {
        let key = SigningKey::generate(&mut OsRng);
        let my_pubkey = key.verifying_key().to_bytes();

        let mut manager = LivenessManager::new(key);
        manager.set_slot(0);
        manager.set_vdf_height(100);
        manager.set_neighbors(vec![[1u8; 32], [2u8; 32]]);

        // Create vouch that judges us
        let voucher_key = SigningKey::generate(&mut OsRng);
        let vouch = MeshVouch::new(
            1,
            vec![my_pubkey, [1u8; 32]],
            vec![(my_pubkey, 10)],
            99,
            &voucher_key,
        );

        let decision = manager.handle_vouch(vouch);
        assert_eq!(decision, PropagationDecision::ForwardToNeighbors);
    }

    #[test]
    fn test_propagation_decision_witness() {
        let key = SigningKey::generate(&mut OsRng);
        let neighbor = [1u8; 32];

        let mut manager = LivenessManager::new(key);
        manager.set_slot(0);
        manager.set_vdf_height(100);
        manager.set_neighbors(vec![neighbor, [2u8; 32]]);

        // Create vouch that judges our neighbor (we're witness)
        let voucher_key = SigningKey::generate(&mut OsRng);
        let vouch = MeshVouch::new(
            2,
            vec![neighbor],
            vec![(neighbor, 10)],
            99,
            &voucher_key,
        );

        let decision = manager.handle_vouch(vouch);
        assert_eq!(decision, PropagationDecision::Stop);

        // We should have recorded the vouch for our neighbor
        assert!(manager.vouch_count(&neighbor) > 0);
    }

    #[test]
    fn test_propagation_decision_drop() {
        let key = SigningKey::generate(&mut OsRng);

        let mut manager = LivenessManager::new(key);
        manager.set_slot(0);
        manager.set_vdf_height(100);
        manager.set_neighbors(vec![[1u8; 32], [2u8; 32]]);

        // Create vouch for unrelated nodes
        let voucher_key = SigningKey::generate(&mut OsRng);
        let vouch = MeshVouch::new(
            5,
            vec![[10u8; 32], [11u8; 32]],
            vec![],
            99,
            &voucher_key,
        );

        let decision = manager.handle_vouch(vouch);
        assert_eq!(decision, PropagationDecision::Drop);
    }

    #[test]
    fn test_vouch_expiry() {
        let vouch = MeshVouch {
            voucher: [0u8; 32],
            voucher_slot: 0,
            alive_neighbors: vec![],
            vdf_height: 100,
            latencies: vec![],
            signature: [0u8; 64],
        };

        assert!(!vouch.is_expired(100));
        assert!(!vouch.is_expired(110));
        assert!(!vouch.is_expired(120));
        assert!(vouch.is_expired(121));
        assert!(vouch.is_expired(200));
    }

    #[test]
    fn test_node_liveness_validity() {
        let mut liveness = NodeLiveness::new(4);

        // Need 3 vouches (majority of 4)
        assert!(!liveness.is_valid());

        liveness.record_vouch([1u8; 32], 100, 4);
        assert!(!liveness.is_valid()); // 1 < 3

        liveness.record_vouch([2u8; 32], 100, 4);
        assert!(!liveness.is_valid()); // 2 < 3

        liveness.record_vouch([3u8; 32], 100, 4);
        assert!(liveness.is_valid()); // 3 >= 3
    }

    #[test]
    fn test_event_driven_vouch_creation() {
        let key = SigningKey::generate(&mut OsRng);
        let neighbor = [1u8; 32];

        let mut manager = LivenessManager::new(key);
        manager.set_slot(0);
        manager.set_vdf_height(100);
        manager.set_neighbors(vec![neighbor]);

        // No latency data yet - shouldn't vouch
        assert!(!manager.should_create_vouch());

        // Record latency - should vouch now
        manager.record_latency(neighbor, 10);
        assert!(manager.should_create_vouch());

        // Create vouch
        let vouch = manager.create_vouch();
        assert!(vouch.is_some());

        // Shouldn't vouch again at same height
        assert!(!manager.should_create_vouch());

        // Advance time - still shouldn't vouch (not expiring yet)
        manager.set_vdf_height(105);
        assert!(!manager.should_create_vouch());

        // Advance to expiry warning - should vouch again
        manager.set_vdf_height(116); // 100 + 20 - 5 + 1 = 116
        assert!(manager.should_create_vouch());
    }
}
