//! 20-Connection Neighbor Computation
//!
//! Every node in the Citadel mesh has exactly 20 neighbors:
//! - 6 planar neighbors (hexagonal grid)
//! - 2 vertical neighbors (layers above/below)
//! - 12 extended neighbors (diagonal connections across layers)
//!
//! This invariant is proven in Lean: `CitadelProofs.Topology.connection_count`

use crate::{
    HexCoord, CONNECTIONS_PER_NODE, EXTENDED_CONNECTIONS, PLANAR_CONNECTIONS, VERTICAL_CONNECTIONS,
};

/// All 20 neighbor directions for a node.
#[derive(Debug, Clone, Copy)]
pub struct Neighbors {
    /// The 6 planar neighbor directions
    pub planar: [HexCoord; PLANAR_CONNECTIONS],
    /// The 2 vertical neighbor directions
    pub vertical: [HexCoord; VERTICAL_CONNECTIONS],
    /// The 12 extended diagonal directions
    pub extended: [HexCoord; EXTENDED_CONNECTIONS],
}

impl Neighbors {
    /// Get the standard neighbor directions.
    ///
    /// These are the same for every node - the topology is translation-invariant.
    pub const fn directions() -> Self {
        Self {
            planar: HexCoord::PLANAR_DIRECTIONS,
            vertical: HexCoord::VERTICAL_DIRECTIONS,
            extended: Self::EXTENDED_DIRECTIONS,
        }
    }

    /// The 12 extended neighbor directions.
    ///
    /// These connect to nodes one layer up/down and one hex step away.
    /// 6 directions × 2 layers = 12 connections.
    pub const EXTENDED_DIRECTIONS: [HexCoord; 12] = [
        // Layer above (+z) with each planar direction
        HexCoord { q: 1, r: 0, z: 1 },
        HexCoord { q: 1, r: -1, z: 1 },
        HexCoord { q: 0, r: -1, z: 1 },
        HexCoord { q: -1, r: 0, z: 1 },
        HexCoord { q: -1, r: 1, z: 1 },
        HexCoord { q: 0, r: 1, z: 1 },
        // Layer below (-z) with each planar direction
        HexCoord { q: 1, r: 0, z: -1 },
        HexCoord { q: 1, r: -1, z: -1 },
        HexCoord { q: 0, r: -1, z: -1 },
        HexCoord { q: -1, r: 0, z: -1 },
        HexCoord { q: -1, r: 1, z: -1 },
        HexCoord { q: 0, r: 1, z: -1 },
    ];

    /// Get all 20 neighbor directions as a single array.
    pub fn all_directions() -> [HexCoord; CONNECTIONS_PER_NODE] {
        let dirs = Self::directions();
        let mut result = [HexCoord::ORIGIN; CONNECTIONS_PER_NODE];

        // Copy planar (0-5)
        result[..6].copy_from_slice(&dirs.planar);
        // Copy vertical (6-7)
        result[6..8].copy_from_slice(&dirs.vertical);
        // Copy extended (8-19)
        result[8..20].copy_from_slice(&dirs.extended);

        result
    }

    /// Get all 20 neighbors of a given coordinate.
    pub fn of(coord: HexCoord) -> [HexCoord; CONNECTIONS_PER_NODE] {
        Self::all_directions().map(|dir| coord + dir)
    }

    /// Get the 6 planar neighbors of a coordinate.
    pub fn planar_of(coord: HexCoord) -> [HexCoord; PLANAR_CONNECTIONS] {
        coord.planar_neighbors()
    }

    /// Get the 2 vertical neighbors of a coordinate.
    pub fn vertical_of(coord: HexCoord) -> [HexCoord; VERTICAL_CONNECTIONS] {
        coord.vertical_neighbors()
    }

    /// Get the 12 extended neighbors of a coordinate.
    pub fn extended_of(coord: HexCoord) -> [HexCoord; EXTENDED_CONNECTIONS] {
        Self::EXTENDED_DIRECTIONS.map(|dir| coord + dir)
    }
}

/// Check if two coordinates are neighbors (within 20-connection set).
pub fn are_neighbors(a: HexCoord, b: HexCoord) -> bool {
    let diff = b - a;
    Neighbors::all_directions().contains(&diff)
}

/// Count how many of a node's 20 neighbors are present in a set.
///
/// Used for peer validation: a claim needs 11/20 validators.
pub fn count_present_neighbors<F>(coord: HexCoord, is_present: F) -> usize
where
    F: Fn(HexCoord) -> bool,
{
    Neighbors::of(coord)
        .iter()
        .filter(|&&n| is_present(n))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_20_directions() {
        assert_eq!(Neighbors::all_directions().len(), 20);
    }

    #[test]
    fn directions_are_unique() {
        let dirs = Neighbors::all_directions();
        for i in 0..dirs.len() {
            for j in (i + 1)..dirs.len() {
                assert_ne!(dirs[i], dirs[j], "Duplicate direction at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn extended_directions_correct_count() {
        assert_eq!(Neighbors::EXTENDED_DIRECTIONS.len(), 12);
    }

    #[test]
    fn extended_directions_are_diagonal() {
        for dir in Neighbors::EXTENDED_DIRECTIONS {
            // Each extended direction should have |z| = 1
            assert!(dir.z == 1 || dir.z == -1);
            // And a non-zero planar component
            assert!(dir.q != 0 || dir.r != 0);
        }
    }

    #[test]
    fn neighbors_of_origin() {
        let neighbors = Neighbors::of(HexCoord::ORIGIN);
        assert_eq!(neighbors.len(), 20);

        // All should be at distance 1 or 2 from origin
        for n in neighbors {
            let dist = n.distance(&HexCoord::ORIGIN);
            assert!(dist <= 2, "Neighbor {:?} too far: {}", n, dist);
        }
    }

    #[test]
    fn neighbor_relation_symmetric() {
        let a = HexCoord::new(3, -2, 1);
        let b = HexCoord::new(4, -2, 1); // Planar neighbor

        assert!(are_neighbors(a, b));
        assert!(are_neighbors(b, a));
    }

    #[test]
    fn not_neighbors_if_too_far() {
        let a = HexCoord::ORIGIN;
        let b = HexCoord::new(5, 0, 0);

        assert!(!are_neighbors(a, b));
    }

    #[test]
    fn count_neighbors_empty() {
        let count = count_present_neighbors(HexCoord::ORIGIN, |_| false);
        assert_eq!(count, 0);
    }

    #[test]
    fn count_neighbors_all_present() {
        let count = count_present_neighbors(HexCoord::ORIGIN, |_| true);
        assert_eq!(count, 20);
    }

    #[test]
    fn count_neighbors_partial() {
        // Only planar neighbors present (z = 0)
        let count = count_present_neighbors(HexCoord::ORIGIN, |c| c.z == 0);
        assert_eq!(count, 6); // Only planar neighbors have z = 0
    }
}
