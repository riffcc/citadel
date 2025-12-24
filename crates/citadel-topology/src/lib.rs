//! Citadel Mesh Topology
//!
//! Hexagonal mesh topology with 20-connection invariant and SPIRAL self-assembly.
//!
//! # Mathematical Foundation
//!
//! The Citadel mesh uses axial hexagonal coordinates on a 3D layered grid.
//! Each node has exactly 20 connections:
//! - 6 planar neighbors (hexagonal grid)
//! - 2 vertical neighbors (layers above/below)
//! - 12 extended neighbors (diagonal connections across layers)
//!
//! # SPIRAL Self-Assembly
//!
//! Nodes join the network by claiming slots in a deterministic spiral pattern
//! starting from origin (0,0,0). First-writer-wins with 11-of-20 peer validation
//! ensures consistency without global coordination.
//!
//! # Formal Proofs
//!
//! All invariants are proven in Lean4. See `proofs/CitadelProofs/Topology.lean`
//! and `proofs/CitadelProofs/Spiral.lean`.

mod hex;
mod spiral;
mod spiral3d;
mod neighbors;
mod gap_and_wrap;

pub use hex::HexCoord;
pub use spiral::{SpiralIndex, Spiral, slots_in_ring, total_slots_through, spiral_to_coord, coord_to_spiral};
pub use spiral3d::{Spiral3DIndex, Spiral3D, slots_in_shell, total_slots_through_shell, spiral3d_to_coord, coord_to_spiral3d};
pub use neighbors::{Neighbors, are_neighbors, count_present_neighbors};
pub use gap_and_wrap::{Direction, Connection, theoretical_neighbor, ghost_target, compute_all_connections, is_bidirectional};

/// Total number of connections per node (invariant: always 20)
pub const CONNECTIONS_PER_NODE: usize = 20;

/// Planar connections in hexagonal grid
pub const PLANAR_CONNECTIONS: usize = 6;

/// Vertical connections (up/down layers)
pub const VERTICAL_CONNECTIONS: usize = 2;

/// Extended diagonal connections across layers
pub const EXTENDED_CONNECTIONS: usize = 12;

// Compile-time assertion of the 20-connection invariant
const _: () = assert!(
    PLANAR_CONNECTIONS + VERTICAL_CONNECTIONS + EXTENDED_CONNECTIONS == CONNECTIONS_PER_NODE
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_invariant() {
        assert_eq!(
            PLANAR_CONNECTIONS + VERTICAL_CONNECTIONS + EXTENDED_CONNECTIONS,
            CONNECTIONS_PER_NODE
        );
    }
}
