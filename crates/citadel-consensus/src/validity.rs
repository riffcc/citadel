//! Slot validity through connection topology.
//!
//! A node doesn't "claim" a slot - it BECOMES a slot by having the right
//! connections. The slot identity emerges from the connection pattern.
//!
//! # Deterministic Contender Selection
//!
//! When multiple nodes contend for the same slot, neighbors select the winner
//! using a deterministic hash function - NO TIMESTAMPS, NO "FIRST WINS":
//!
//! ```text
//! winner = argmax_{c ∈ contenders} H(neighbor_id ‖ port ‖ contender_id ‖ epoch)
//! ```
//!
//! This is coordination-free but removes arrival order as an input.
//!
//! # Port Exclusivity
//!
//! For slot N with neighbor M, the port `toward(M, N)` binds to AT MOST ONE node.
//! Binding requires bidirectional mutual signatures (both endpoints sign).

use crate::threshold::validation_threshold;
use citadel_topology::{HexCoord, Neighbors, SpiralIndex};

/// A cryptographic node identifier (e.g., public key hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

/// An epoch for deterministic tie-breaking.
/// Derived from mesh state, not global time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Epoch(pub u64);

/// A port binding: one neighbor direction bound to one node.
/// Both sides must sign for validity (mutual acknowledgment).
#[derive(Debug, Clone)]
pub struct PortBinding {
    /// The neighbor node hosting this port
    pub neighbor: NodeId,
    /// The direction/port on that neighbor
    pub direction: u8, // 0-19
    /// The node bound to this port
    pub bound_to: NodeId,
    /// Signature from the neighbor (proves neighbor agrees)
    pub neighbor_sig: [u8; 64],
    /// Signature from the bound node (proves bound node agrees)
    pub bound_sig: [u8; 64],
}

impl PortBinding {
    /// Verify both signatures are valid.
    /// Byzantine neighbors can sign anything, but can't forge the bound node's signature.
    pub fn is_valid(&self) -> bool {
        // In real impl: verify neighbor_sig over (neighbor, direction, bound_to)
        // and verify bound_sig over same data
        // For now: assume valid
        true
    }
}

/// The validity status of a node at a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotValidity {
    /// Node has sufficient valid port bindings to occupy this slot
    Valid { bindings: usize, threshold: usize },
    /// Node doesn't have enough bindings
    Insufficient { bindings: usize, needed: usize },
    /// Node is being challenged by another with better hash
    Challenged { challenger: NodeId },
}

/// Select winner among contenders using deterministic hash.
///
/// winner = argmax_{c ∈ contenders} H(neighbor_id ‖ port ‖ contender_id ‖ epoch)
///
/// NO TIMESTAMPS. NO "FIRST WINS". Pure function of identities.
pub fn select_winner(
    neighbor_id: &NodeId,
    port: u8,
    contenders: &[NodeId],
    epoch: Epoch,
) -> Option<NodeId> {
    if contenders.is_empty() {
        return None;
    }

    contenders
        .iter()
        .max_by_key(|c| contender_score(neighbor_id, port, c, epoch))
        .copied()
}

/// Compute deterministic score for tie-breaking.
fn contender_score(neighbor: &NodeId, port: u8, contender: &NodeId, epoch: Epoch) -> [u8; 32] {
    // H(neighbor_id ‖ port ‖ contender_id ‖ epoch)
    // In real impl: use blake3 or similar
    let mut hasher = SimpleHasher::new();
    hasher.update(&neighbor.0);
    hasher.update(&[port]);
    hasher.update(&contender.0);
    hasher.update(&epoch.0.to_le_bytes());
    hasher.finalize()
}

/// Simple hasher for demonstration (replace with blake3 in production).
struct SimpleHasher {
    state: [u8; 32],
}

impl SimpleHasher {
    fn new() -> Self {
        Self { state: [0; 32] }
    }

    fn update(&mut self, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            self.state[i % 32] ^= byte;
            self.state[(i + 1) % 32] = self.state[(i + 1) % 32].wrapping_add(*byte);
        }
    }

    fn finalize(self) -> [u8; 32] {
        self.state
    }
}

/// A node's validity state for occupying a slot.
#[derive(Debug)]
pub struct NodeValidity {
    /// The node in question
    pub node: NodeId,
    /// The slot being evaluated
    pub slot: SpiralIndex,
    /// Valid port bindings this node has
    pub bindings: Vec<PortBinding>,
    /// Current epoch
    pub epoch: Epoch,
}

impl NodeValidity {
    /// Check if this node validly occupies the slot.
    pub fn check(&self, existing_neighbors: usize) -> SlotValidity {
        let valid_bindings = self.bindings.iter().filter(|b| b.is_valid()).count();
        let threshold = validation_threshold(existing_neighbors);

        if valid_bindings >= threshold {
            SlotValidity::Valid {
                bindings: valid_bindings,
                threshold,
            }
        } else {
            SlotValidity::Insufficient {
                bindings: valid_bindings,
                needed: threshold - valid_bindings,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(seed: u8) -> NodeId {
        let mut id = [0u8; 32];
        id[0] = seed;
        NodeId(id)
    }

    #[test]
    fn winner_selection_is_deterministic() {
        let neighbor = make_node(1);
        let port = 5;
        let contenders = vec![make_node(10), make_node(20), make_node(30)];
        let epoch = Epoch(100);

        // Same inputs → same winner
        let winner1 = select_winner(&neighbor, port, &contenders, epoch);
        let winner2 = select_winner(&neighbor, port, &contenders, epoch);
        assert_eq!(winner1, winner2);
    }

    #[test]
    fn winner_selection_no_time_dependency() {
        let neighbor = make_node(1);
        let port = 5;
        let epoch = Epoch(100);

        // Order of contenders doesn't matter
        let contenders1 = vec![make_node(10), make_node(20), make_node(30)];
        let contenders2 = vec![make_node(30), make_node(10), make_node(20)];
        let contenders3 = vec![make_node(20), make_node(30), make_node(10)];

        let winner1 = select_winner(&neighbor, port, &contenders1, epoch);
        let winner2 = select_winner(&neighbor, port, &contenders2, epoch);
        let winner3 = select_winner(&neighbor, port, &contenders3, epoch);

        assert_eq!(winner1, winner2);
        assert_eq!(winner2, winner3);
    }

    #[test]
    fn different_epochs_can_change_winner() {
        let neighbor = make_node(1);
        let port = 5;
        let contenders = vec![make_node(10), make_node(20)];

        // Different epochs might select different winners
        // (Not guaranteed, but possible - the function is deterministic per epoch)
        let _winner1 = select_winner(&neighbor, port, &contenders, Epoch(1));
        let _winner2 = select_winner(&neighbor, port, &contenders, Epoch(2));
        // Just checking it doesn't panic - winners may or may not differ
    }

    #[test]
    fn empty_contenders_returns_none() {
        let neighbor = make_node(1);
        let contenders: Vec<NodeId> = vec![];
        assert!(select_winner(&neighbor, 0, &contenders, Epoch(0)).is_none());
    }

    #[test]
    fn single_contender_wins() {
        let neighbor = make_node(1);
        let contender = make_node(42);
        let contenders = vec![contender];
        assert_eq!(
            select_winner(&neighbor, 0, &contenders, Epoch(0)),
            Some(contender)
        );
    }
}
