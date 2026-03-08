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

mod gap_and_wrap;
mod hex;
mod neighbors;
mod spiral;
mod spiral3d;

pub use gap_and_wrap::{
    compute_all_connections, ghost_target, is_bidirectional, theoretical_neighbor, Connection,
    Direction,
};
pub use hex::HexCoord;
pub use neighbors::{are_neighbors, count_present_neighbors, Neighbors};
pub use spiral::{
    coord_to_spiral, slots_in_ring, spiral_to_coord, total_slots_through, Spiral, SpiralIndex,
};
pub use spiral3d::{
    coord_to_spiral3d, slots_in_shell, spiral3d_to_coord, total_slots_through_shell, Spiral3D,
    Spiral3DIndex,
};

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
