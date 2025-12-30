//! Convergent self-assembly: the mesh relaxes to SPIRAL topology.
//!
//! # Port Exclusivity Lemma
//!
//! For slot N with neighbor M, the port `toward(M, N)` can be bound to
//! AT MOST ONE node, and binding requires bidirectional mutual signatures.
//!
//! # Exclusivity Proof
//!
//! 1. Slot N has exactly 20 theoretical neighbors → 20 "toward-N" ports total
//! 2. If X occupies N, X binds ≥11 of those ports (with mutual signatures)
//! 3. Remaining unbound toward-N ports ≤ 9
//! 4. Any Y ≠ X can bind ≤ 9 toward-N ports ⇒ cannot reach threshold 11
//!
//! # Byzantine Tolerance
//!
//! A Byzantine neighbor can sign anything, but:
//! - Each binding requires BOTH signatures (neighbor + bound node)
//! - Byzantine can only contribute its own port signatures
//! - Cannot forge honest neighbors' acknowledgments
//! - With 6 Byzantine out of 20, honest node still has 14 > 11 potential bindings

use crate::validity::{NodeId, Epoch, PortBinding, select_winner};
use crate::threshold::{validation_threshold, MAX_NEIGHBORS, FULL_THRESHOLD};
use citadel_topology::SpiralIndex;

/// Tension in the mesh - a node that doesn't fit the topology.
#[derive(Debug, Clone)]
pub struct Tension {
    /// The node experiencing tension
    pub node: NodeId,
    /// Current (possibly wrong) slot
    pub current_slot: SpiralIndex,
    /// Number of valid bindings at current slot
    pub current_bindings: usize,
    /// Suggested correct slot (if determinable)
    pub suggested_slot: Option<SpiralIndex>,
    /// Reason for tension
    pub reason: TensionReason,
}

/// Why a node is under tension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TensionReason {
    /// Not enough bindings to occupy claimed slot
    InsufficientBindings { have: usize, need: usize },
    /// Lost deterministic selection to another node
    LostSelection { winner: NodeId },
    /// Bindings point to wrong theoretical neighbors
    WrongNeighbors,
}

/// A correction action to resolve tension.
#[derive(Debug, Clone)]
pub struct Correction {
    /// Node to be corrected
    pub node: NodeId,
    /// Action to take
    pub action: CorrectionAction,
}

/// Types of correction actions.
#[derive(Debug, Clone)]
pub enum CorrectionAction {
    /// Move to a different slot
    MoveToSlot(SpiralIndex),
    /// Rebind to correct neighbors
    RebindNeighbors,
    /// Leave the network (cannot find valid slot)
    Leave,
}

/// The convergence state of a portion of the mesh.
#[derive(Debug, Default)]
pub struct ConvergenceState {
    /// Current tensions detected
    pub tensions: Vec<Tension>,
    /// Pending corrections
    pub corrections: Vec<Correction>,
    /// Whether the observed region is stable
    pub is_stable: bool,
}

impl ConvergenceState {
    /// Check if convergence is complete (no tensions).
    pub fn is_converged(&self) -> bool {
        self.tensions.is_empty() && self.is_stable
    }

    /// Calculate total "wrongness" - Lyapunov function for convergence proof.
    pub fn total_tension(&self) -> usize {
        self.tensions.len()
    }
}

/// PORT EXCLUSIVITY LEMMA (Rust encoding):
///
/// For a slot N, each of its 20 theoretical neighbors M has exactly one
/// "toward N" port. This port can be bound to at most one node.
///
/// Returns: Maximum nodes that can bind to toward-N ports
pub const fn max_toward_n_bindings() -> usize {
    MAX_NEIGHBORS // 20 ports, each holds at most 1 binding
}

/// EXCLUSIVITY THEOREM (Rust encoding):
///
/// If node X has ≥11 bindings to slot N's ports, then any other node Y
/// can have at most 9 bindings to N's ports.
///
/// Proof:
/// - Total toward-N ports = 20
/// - X binds ≥11
/// - Remaining ≤ 20 - 11 = 9
/// - Y can only bind to remaining
/// - 9 < 11 (threshold)
/// - Therefore Y cannot occupy N
pub const fn max_remaining_bindings_after(occupied_bindings: usize) -> usize {
    MAX_NEIGHBORS.saturating_sub(occupied_bindings)
}

/// Check if exclusivity is violated (impossible if protocol followed).
pub fn check_exclusivity_invariant(
    slot: SpiralIndex,
    bindings_by_node: &[(NodeId, usize)],
) -> Result<(), ExclusivityViolation> {
    // Sum of all bindings to this slot's ports
    let total: usize = bindings_by_node.iter().map(|(_, b)| *b).sum();

    if total > MAX_NEIGHBORS {
        return Err(ExclusivityViolation::TooManyBindings {
            slot,
            total,
            max: MAX_NEIGHBORS,
        });
    }

    // Checks exclusivity without allocation
    let thresh_filter = |(_, b): &&(_, usize)| *b >= FULL_THRESHOLD;
    let second_thresh = bindings_by_node
        .iter()
        .filter(thresh_filter)
        .nth(1);

    if second_thresh.is_some() {
        return Err(ExclusivityViolation::MultipleOccupants {
            slot,
            occupants: bindings_by_node.iter().filter(thresh_filter).map(|(n, _)| *n).collect(),
        });
    }

    Ok(())
}

/// Exclusivity invariant violation (should be impossible).
#[derive(Debug, Clone)]
pub enum ExclusivityViolation {
    /// More bindings than ports exist
    TooManyBindings {
        slot: SpiralIndex,
        total: usize,
        max: usize,
    },
    /// Multiple nodes somehow have ≥11 bindings (impossible by pigeonhole)
    MultipleOccupants {
        slot: SpiralIndex,
        occupants: Vec<NodeId>,
    },
}

/// BYZANTINE TOLERANCE:
///
/// A Byzantine neighbor can:
/// - Sign bindings for any node (contribute its own port)
/// - Refuse to sign for honest nodes
/// - Lie about other nodes
///
/// A Byzantine neighbor CANNOT:
/// - Forge another neighbor's signature
/// - Create bindings on ports it doesn't own
///
/// With B Byzantine neighbors out of 20:
/// - Honest neighbors = 20 - B
/// - Honest node can get ≥ (20 - B) bindings from honest neighbors
/// - Need: 20 - B ≥ 11 → B ≤ 9
///
/// Conservative threshold: B ≤ 6 (leaving margin)
pub const fn byzantine_tolerance_check(byzantine_count: usize) -> bool {
    let honest = MAX_NEIGHBORS.saturating_sub(byzantine_count);
    honest >= FULL_THRESHOLD
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
    fn exclusivity_math() {
        // If X has 11 bindings, Y can have at most 9
        assert_eq!(max_remaining_bindings_after(11), 9);
        const { assert!(9 < FULL_THRESHOLD); }

        // If X has 15 bindings, Y can have at most 5
        assert_eq!(max_remaining_bindings_after(15), 5);

        // Edge case: X has all 20
        assert_eq!(max_remaining_bindings_after(20), 0);
    }

    #[test]
    fn exclusivity_invariant_valid() {
        let slot = SpiralIndex::new(42);

        // Single occupant with 11 bindings - valid
        let bindings = vec![(make_node(1), 11)];
        assert!(check_exclusivity_invariant(slot, &bindings).is_ok());

        // One occupant (11) and one non-occupant (5) - valid
        let bindings = vec![(make_node(1), 11), (make_node(2), 5)];
        assert!(check_exclusivity_invariant(slot, &bindings).is_ok());
    }

    #[test]
    fn exclusivity_invariant_catches_violations() {
        let slot = SpiralIndex::new(42);

        // Too many total bindings (impossible in practice)
        let bindings = vec![(make_node(1), 15), (make_node(2), 10)];
        assert!(matches!(
            check_exclusivity_invariant(slot, &bindings),
            Err(ExclusivityViolation::TooManyBindings { .. })
        ));

        // Two occupants (impossible by pigeonhole, but check detection)
        let bindings = vec![(make_node(1), 11), (make_node(2), 11)];
        let result = check_exclusivity_invariant(slot, &bindings);
        // This would also be TooManyBindings (22 > 20), caught first
        assert!(result.is_err());
    }

    #[test]
    fn byzantine_tolerance() {
        // 0-6 Byzantine: honest can still validate
        for b in 0..=6 {
            assert!(
                byzantine_tolerance_check(b),
                "{} Byzantine should be tolerated",
                b
            );
        }

        // 10+ Byzantine: cannot guarantee honest validation
        assert!(!byzantine_tolerance_check(10));
    }

    #[test]
    fn convergence_state_default_unstable() {
        let state = ConvergenceState::default();
        assert!(!state.is_converged()); // Not stable by default
    }

    #[test]
    fn convergence_with_no_tensions() {
        let state = ConvergenceState {
            tensions: vec![],
            corrections: vec![],
            is_stable: true,
        };
        assert!(state.is_converged());
        assert_eq!(state.total_tension(), 0);
    }
}
