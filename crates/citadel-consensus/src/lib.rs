//! Convergent Self-Assembly Consensus
//!
//! The Citadel mesh doesn't use "first-writer-wins" or any central authority.
//! Instead, nodes **converge** to the correct SPIRAL topology through local
//! neighbor interactions.
//!
//! # Core Insight
//!
//! A slot is not a resource to claim - it's a **position** defined by connections.
//! You don't "get" slot 42, you **become** slot 42 by having the right neighbors.
//!
//! # Convergent Assembly
//!
//! 1. Nodes join with approximate positions
//! 2. Neighbors detect "tension" (topological incorrectness)
//! 3. Local corrections propagate
//! 4. Mesh relaxes to SPIRAL topology
//!
//! Like a crystal lattice forming - nodes settle into correct positions through
//! local forces, not global coordination.
//!
//! # Scaled Threshold
//!
//! Validation requires a threshold of existing neighbors:
//! - 0 neighbors → 0 required (origin node)
//! - n neighbors → ceil(n × 11/20) required
//!
//! Security scales with network size. Bootstrap is trusted, mature network is BFT.

mod convergence;
mod threshold;
mod validity;

pub use convergence::{ConvergenceState, Correction, Tension};
pub use threshold::validation_threshold;
pub use validity::{NodeValidity, SlotValidity};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_scales_correctly() {
        assert_eq!(validation_threshold(0), 0); // Origin
        assert_eq!(validation_threshold(1), 1); // Need the one neighbor
        assert_eq!(validation_threshold(2), 2); // Need both
        assert_eq!(validation_threshold(3), 2); // 2/3
        assert_eq!(validation_threshold(6), 4); // 4/6
        assert_eq!(validation_threshold(10), 6); // 6/10
        assert_eq!(validation_threshold(15), 9); // 9/15
        assert_eq!(validation_threshold(20), 11); // 11/20 - full BFT
    }
}
