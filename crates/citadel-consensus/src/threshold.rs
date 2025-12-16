//! Scaled validation threshold for convergent self-assembly.
//!
//! The threshold scales with network size:
//! - 0 neighbors → 0 required (origin node, void accepts you)
//! - n neighbors → ceil(n × 11/20) required
//!
//! Security grows with the network. Bootstrap is trusted, mature is BFT.

/// Full validation threshold when all 20 neighbors exist.
pub const FULL_THRESHOLD: usize = 11;

/// Total possible neighbors per node.
pub const MAX_NEIGHBORS: usize = 20;

/// Maximum Byzantine nodes we can tolerate.
/// With 11/20 threshold, we tolerate 20 - 11 = 9 missing + some Byzantine.
/// Conservative: 6 Byzantine (need 14 honest, have 14 > 11).
pub const MAX_BYZANTINE: usize = 6;

/// Calculate the validation threshold for a given number of existing neighbors.
///
/// Formula: ceil(n × 11/20)
///
/// This is the minimum number of connections needed to "be" at a slot
/// when only `existing_neighbors` of the theoretical 20 neighbors exist.
///
/// # Examples
///
/// ```
/// use citadel_consensus::validation_threshold;
///
/// assert_eq!(validation_threshold(0), 0);   // Origin - void accepts
/// assert_eq!(validation_threshold(1), 1);   // Need the one neighbor
/// assert_eq!(validation_threshold(20), 11); // Full BFT threshold
/// ```
pub const fn validation_threshold(existing_neighbors: usize) -> usize {
    if existing_neighbors == 0 {
        return 0;
    }
    // ceil(n * 11 / 20) = (n * 11 + 19) / 20
    (existing_neighbors * FULL_THRESHOLD).div_ceil(MAX_NEIGHBORS)
}

/// Check if a connection count meets the threshold.
pub const fn meets_threshold(connections: usize, existing_neighbors: usize) -> bool {
    connections >= validation_threshold(existing_neighbors)
}

/// Calculate how many more connections are needed to meet threshold.
pub const fn connections_needed(current: usize, existing_neighbors: usize) -> usize {
    validation_threshold(existing_neighbors).saturating_sub(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_origin() {
        // Origin node has no neighbors - void accepts
        assert_eq!(validation_threshold(0), 0);
    }

    #[test]
    fn threshold_scales_proportionally() {
        // Should be roughly 55% (11/20)
        let test_cases = [
            (1, 1),   // 1 × 0.55 = 0.55 → ceil = 1
            (2, 2),   // 2 × 0.55 = 1.1  → ceil = 2
            (3, 2),   // 3 × 0.55 = 1.65 → ceil = 2
            (4, 3),   // 4 × 0.55 = 2.2  → ceil = 3
            (5, 3),   // 5 × 0.55 = 2.75 → ceil = 3
            (6, 4),   // 6 × 0.55 = 3.3  → ceil = 4
            (10, 6),  // 10 × 0.55 = 5.5 → ceil = 6
            (15, 9),  // 15 × 0.55 = 8.25 → ceil = 9
            (20, 11), // 20 × 0.55 = 11  → ceil = 11
        ];

        for (neighbors, expected) in test_cases {
            assert_eq!(
                validation_threshold(neighbors),
                expected,
                "threshold({}) should be {}",
                neighbors,
                expected
            );
        }
    }

    #[test]
    fn threshold_never_exceeds_neighbors() {
        for n in 0..=20 {
            assert!(
                validation_threshold(n) <= n,
                "threshold({}) = {} exceeds n",
                n,
                validation_threshold(n)
            );
        }
    }

    #[test]
    fn threshold_monotonic() {
        // More neighbors should never decrease threshold
        let mut prev = 0;
        for n in 0..=20 {
            let t = validation_threshold(n);
            assert!(t >= prev, "threshold should be monotonic");
            prev = t;
        }
    }

    #[test]
    fn meets_threshold_checks() {
        assert!(meets_threshold(0, 0));
        assert!(meets_threshold(1, 1));
        assert!(!meets_threshold(0, 1));
        assert!(meets_threshold(11, 20));
        assert!(!meets_threshold(10, 20));
    }

    #[test]
    fn connections_needed_calculation() {
        assert_eq!(connections_needed(0, 0), 0);
        assert_eq!(connections_needed(0, 1), 1);
        assert_eq!(connections_needed(5, 20), 6); // Need 11, have 5
        assert_eq!(connections_needed(11, 20), 0); // Already met
        assert_eq!(connections_needed(15, 20), 0); // Exceeded
    }

    #[test]
    fn byzantine_tolerance() {
        // With 6 Byzantine nodes out of 20:
        // - 14 honest neighbors
        // - Need 11 to validate
        // - 14 > 11, so honest nodes can still validate
        let honest = MAX_NEIGHBORS - MAX_BYZANTINE;
        let threshold = validation_threshold(MAX_NEIGHBORS);
        assert!(
            honest >= threshold,
            "honest neighbors {} should meet threshold {}",
            honest,
            threshold
        );

        // Byzantine can only get 6 fake validations
        // 6 < 11, so they can't fake occupancy
        assert!(MAX_BYZANTINE < threshold);
    }
}
