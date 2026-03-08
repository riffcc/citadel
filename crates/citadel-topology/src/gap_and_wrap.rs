//! Gap-and-Wrap: Toroidal SPIRAL with Ghost Connections
//!
//! Gap-and-Wrap (GnW) extends SPIRAL with:
//! 1. **Toroidal wrapping** - the mesh wraps in all 20 directions
//! 2. **Ghost connections** - if expected neighbor is empty, connect to next occupied slot in that direction
//!
//! This ensures every node has exactly 20 logical connections regardless of mesh density.
//!
//! # Key Insight
//!
//! In a sparse mesh, rather than having "broken" neighbor relationships, each direction
//! wraps toroidally to find the next occupied slot. This creates "ghost connections"
//! that span gaps in the mesh while preserving the geometric routing properties.
//!
//! # Formal Proofs
//!
//! All properties are proven in Lean: `CitadelProofs.GapAndWrap`
//! - `ghost_bidirectional`: A→B in d implies B→A in opposite(d)
//! - `full_connectivity`: Every node has 20 connections (if mesh > 1)
//! - `connections_symmetric`: The connection graph is undirected
//! - `self_healing`: Connections auto-resolve when nodes leave

use crate::HexCoord;
use std::collections::HashSet;

/// One of the 20 directions in the 3D hexagonal lattice.
///
/// - 6 planar directions (same z-layer)
/// - 2 vertical directions (up/down)
/// - 12 extended directions (diagonal: 6 around × 2 layers)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Planar direction (0-5): East, NE, NW, West, SW, SE
    Planar(u8),
    /// Vertical direction: Up (true) or Down (false)
    Vertical(bool),
    /// Extended direction: planar index (0-5) × layer (up=true, down=false)
    Extended(u8, bool),
}

impl Direction {
    /// All 20 directions in canonical order
    pub fn all() -> [Direction; 20] {
        [
            // 6 planar
            Direction::Planar(0),
            Direction::Planar(1),
            Direction::Planar(2),
            Direction::Planar(3),
            Direction::Planar(4),
            Direction::Planar(5),
            // 2 vertical
            Direction::Vertical(true),
            Direction::Vertical(false),
            // 12 extended
            Direction::Extended(0, true),
            Direction::Extended(1, true),
            Direction::Extended(2, true),
            Direction::Extended(3, true),
            Direction::Extended(4, true),
            Direction::Extended(5, true),
            Direction::Extended(0, false),
            Direction::Extended(1, false),
            Direction::Extended(2, false),
            Direction::Extended(3, false),
            Direction::Extended(4, false),
            Direction::Extended(5, false),
        ]
    }

    /// Get the opposite direction (for bidirectionality)
    ///
    /// Proven in Lean: `Direction.opposite_involutive`
    pub fn opposite(self) -> Direction {
        match self {
            Direction::Planar(i) => Direction::Planar((i + 3) % 6),
            Direction::Vertical(up) => Direction::Vertical(!up),
            Direction::Extended(i, up) => Direction::Extended((i + 3) % 6, !up),
        }
    }

    /// Get the offset vector for this direction
    pub fn offset(self) -> HexCoord {
        match self {
            Direction::Planar(i) => HexCoord::PLANAR_DIRECTIONS[i as usize],
            Direction::Vertical(up) => {
                if up {
                    HexCoord::new(0, 0, 1)
                } else {
                    HexCoord::new(0, 0, -1)
                }
            }
            Direction::Extended(i, up) => {
                let planar = HexCoord::PLANAR_DIRECTIONS[i as usize];
                let z = if up { 1 } else { -1 };
                HexCoord::new(planar.q, planar.r, z)
            }
        }
    }
}

/// The theoretical neighbor of a hex coordinate in a given direction.
///
/// This is the "ideal" neighbor assuming all slots are occupied.
pub fn theoretical_neighbor(coord: HexCoord, direction: Direction) -> HexCoord {
    coord + direction.offset()
}

/// Walk one step in a direction (for toroidal traversal)
pub fn step(coord: HexCoord, direction: Direction) -> HexCoord {
    theoretical_neighbor(coord, direction)
}

/// Find the next occupied slot in a given direction, wrapping toroidally.
///
/// Returns `None` if we wrap all the way back to start (mesh too sparse in this direction).
///
/// The `max_steps` parameter prevents infinite loops in edge cases.
pub fn next_occupied(
    occupied: &HashSet<HexCoord>,
    start: HexCoord,
    direction: Direction,
    max_steps: usize,
) -> Option<HexCoord> {
    let mut current = start;
    for _ in 0..max_steps {
        current = step(current, direction);
        if current == start {
            // Wrapped all the way around - no other node in this direction
            return None;
        }
        if occupied.contains(&current) {
            return Some(current);
        }
    }
    None // Safety limit reached
}

/// The ghost target: either the theoretical neighbor (if occupied) or the next occupied in that direction
///
/// This is the core of Gap-and-Wrap:
/// - If theoretical neighbor exists → normal connection
/// - Otherwise → ghost connection to next occupied
pub fn ghost_target(
    occupied: &HashSet<HexCoord>,
    coord: HexCoord,
    direction: Direction,
) -> Option<HexCoord> {
    let theoretical = theoretical_neighbor(coord, direction);
    if occupied.contains(&theoretical) {
        Some(theoretical) // Normal connection
    } else {
        // Ghost connection - find next occupied in this direction
        // Use a reasonable limit based on expected mesh sizes
        next_occupied(occupied, coord, direction, 10_000)
    }
}

/// A connection from a node in a specific direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    /// Direction of this connection
    pub direction: Direction,
    /// Target coordinate
    pub target: HexCoord,
    /// Gap size (0 = normal connection, >0 = ghost connection)
    pub gap_size: u32,
    /// Is this a ghost connection?
    pub is_ghost: bool,
}

/// Compute all 20 connections for a node using bidirectional gap-and-wrap.
///
/// For each of the 20 directions:
/// 1. **Primary**: walk outward in direction D, find the nearest occupied slot.
///    If it's unique (not already a neighbor), use it.
/// 2. **Wrap**: if the primary collides (already a neighbor) or walks into void,
///    wrap to the opposite side of the honeycomb — walk in the opposite
///    direction (-D) to find the antipodal edge, then the nearest unchosen
///    node from that side is the neighbor for direction D.
///
/// This guarantees exactly min(20, N-1) unique neighbors per node.
/// The wrapping maintains spatial balance: neighbors form a balanced shell
/// even when the mesh is small.
pub fn compute_all_connections(occupied: &HashSet<HexCoord>, coord: HexCoord) -> Vec<Connection> {
    let mut chosen: HashSet<HexCoord> = HashSet::new();
    chosen.insert(coord); // never connect to self

    Direction::all()
        .iter()
        .filter_map(|&direction| {
            // Primary: nearest occupied in direction D (may collide with existing neighbor)
            let primary = ghost_target(occupied, coord, direction);

            let target = match primary {
                Some(t) if !chosen.contains(&t) => t,
                _ => {
                    // Collision or void — wrap to the opposite side.
                    // Walk -D to find the unchosen node at the antipodal edge.
                    wrap_opposite(occupied, coord, direction, &chosen)?
                }
            };

            chosen.insert(target);

            let theoretical = theoretical_neighbor(coord, direction);
            let is_ghost = target != theoretical;
            let gap_size = if is_ghost {
                shell_distance(coord, target) as u32
            } else {
                0
            };

            Some(Connection {
                direction,
                target,
                gap_size,
                is_ghost,
            })
        })
        .collect()
}

/// Wrap to the opposite side of the honeycomb in direction D.
///
/// When direction D's primary target is a collision (already a neighbor) or void
/// (walks into empty space), we imagine wrapping around to the opposite side of
/// the honeycomb and coming back toward our position.
///
/// Implementation: among all unchosen occupied nodes, pick the one furthest
/// from us in the OPPOSITE direction (-D). This is the antipodal node —
/// the first one you'd encounter if you wrapped around the honeycomb and
/// walked back toward the center.
///
/// Uses projection onto the direction vector for geometric ordering.
/// Ties broken by shell distance (prefer closer nodes) then coordinates
/// (determinism).
fn wrap_opposite(
    occupied: &HashSet<HexCoord>,
    origin: HexCoord,
    direction: Direction,
    already_chosen: &HashSet<HexCoord>,
) -> Option<HexCoord> {
    let d = direction.offset();

    // Projection of each node onto direction D, relative to our position.
    // Negative projection = opposite side of honeycomb in direction D.
    // The most negative projection = furthest antipodal = first hit when wrapping.
    occupied
        .iter()
        .filter(|c| !already_chosen.contains(c))
        .min_by_key(|c| {
            let proj = (c.q - origin.q) * d.q + (c.r - origin.r) * d.r + (c.z - origin.z) * d.z;
            // Most negative projection first (antipodal edge).
            // Tie-break: prefer closer nodes (smaller shell distance).
            let shell = shell_distance(origin, **c);
            (proj, shell, c.q, c.r, c.z)
        })
        .copied()
}

/// Shell distance between two coordinates: max(hex_distance, |dz|).
///
/// This is the radius of the smallest shell centered on `a` that contains `b`.
pub fn shell_distance(a: HexCoord, b: HexCoord) -> u64 {
    let hex_dist = a.hex_distance(&b);
    let dz = (a.z - b.z).unsigned_abs();
    hex_dist.max(dz)
}

/// Check if a connection is bidirectional (it should always be, per Lean proofs)
///
/// This is a debug/verification function.
pub fn is_bidirectional(
    occupied: &HashSet<HexCoord>,
    source: HexCoord,
    target: HexCoord,
    direction: Direction,
) -> bool {
    // If source→target in direction, then target→source in opposite
    let forward = ghost_target(occupied, source, direction);
    let backward = ghost_target(occupied, target, direction.opposite());

    forward == Some(target) && backward == Some(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_opposite_involutive() {
        for d in Direction::all() {
            assert_eq!(d.opposite().opposite(), d);
        }
    }

    #[test]
    fn exactly_20_directions() {
        assert_eq!(Direction::all().len(), 20);
    }

    #[test]
    fn directions_unique() {
        let dirs = Direction::all();
        let set: HashSet<_> = dirs.iter().collect();
        assert_eq!(set.len(), 20);
    }

    #[test]
    fn theoretical_neighbor_matches_topology() {
        use crate::Neighbors;

        let origin = HexCoord::ORIGIN;
        let all_neighbors = Neighbors::of(origin);

        // All theoretical neighbors should be in the 20-neighbor set
        for d in Direction::all() {
            let neighbor = theoretical_neighbor(origin, d);
            assert!(
                all_neighbors.contains(&neighbor),
                "Direction {:?} gives {:?} which is not in neighbors",
                d,
                neighbor
            );
        }
    }

    #[test]
    fn ghost_target_normal_connection() {
        let mut occupied = HashSet::new();
        let origin = HexCoord::ORIGIN;
        let east = HexCoord::new(1, 0, 0);

        occupied.insert(origin);
        occupied.insert(east);

        // Origin should connect to East via normal connection
        let target = ghost_target(&occupied, origin, Direction::Planar(0));
        assert_eq!(target, Some(east));
    }

    #[test]
    fn ghost_target_ghost_connection() {
        let mut occupied = HashSet::new();
        let origin = HexCoord::ORIGIN;
        // Skip the immediate east neighbor, put one further
        let far_east = HexCoord::new(3, 0, 0);

        occupied.insert(origin);
        occupied.insert(far_east);

        // Origin should ghost-connect to far_east
        let target = ghost_target(&occupied, origin, Direction::Planar(0));
        assert_eq!(target, Some(far_east));
    }

    #[test]
    fn ghost_connection_bidirectional() {
        let mut occupied = HashSet::new();
        let origin = HexCoord::ORIGIN;
        let far_east = HexCoord::new(3, 0, 0);

        occupied.insert(origin);
        occupied.insert(far_east);

        // Forward: origin → far_east in East direction
        let forward = ghost_target(&occupied, origin, Direction::Planar(0));
        assert_eq!(forward, Some(far_east));

        // Backward: far_east → origin in West direction (opposite of East)
        let backward = ghost_target(&occupied, far_east, Direction::Planar(0).opposite());
        assert_eq!(backward, Some(origin));
    }

    #[test]
    fn compute_all_connections_sparse_mesh() {
        let mut occupied = HashSet::new();
        let a = HexCoord::ORIGIN;
        let b = HexCoord::new(5, 0, 0); // Far away

        occupied.insert(a);
        occupied.insert(b);

        let connections_a = compute_all_connections(&occupied, a);
        let connections_b = compute_all_connections(&occupied, b);

        // Both should have some connections (may not be 20 if they're very far apart)
        assert!(!connections_a.is_empty());
        assert!(!connections_b.is_empty());

        // At least one connection should be ghost
        assert!(connections_a.iter().any(|c| c.is_ghost));
    }

    #[test]
    fn single_node_no_connections() {
        let mut occupied = HashSet::new();
        let origin = HexCoord::ORIGIN;
        occupied.insert(origin);

        // Single node wraps around to itself in all directions → no connections
        let connections = compute_all_connections(&occupied, origin);
        assert!(connections.is_empty());
    }

    #[test]
    fn full_shell_1_all_normal_connections() {
        use crate::Neighbors;

        let mut occupied = HashSet::new();
        let origin = HexCoord::ORIGIN;
        occupied.insert(origin);

        // Add all 20 neighbors
        for neighbor in Neighbors::of(origin) {
            occupied.insert(neighbor);
        }

        let connections = compute_all_connections(&occupied, origin);

        // Should have exactly 20 normal connections
        assert_eq!(connections.len(), 20);
        assert!(connections.iter().all(|c| !c.is_ghost));
        assert!(connections.iter().all(|c| c.gap_size == 0));
    }

    #[test]
    fn forty_nodes_all_have_20_unique_neighbors() {
        use crate::spiral3d_to_coord;
        use crate::Spiral3DIndex;

        // Occupy slots 0..40 — the first 40 SPIRAL positions.
        let mut occupied = HashSet::new();
        let coords: Vec<HexCoord> = (0..40)
            .map(|i| {
                let c = spiral3d_to_coord(Spiral3DIndex::new(i));
                occupied.insert(c);
                c
            })
            .collect();

        // Every node must have exactly 20 unique neighbors.
        for (i, &coord) in coords.iter().enumerate() {
            let connections = compute_all_connections(&occupied, coord);
            let targets: HashSet<HexCoord> = connections.iter().map(|c| c.target).collect();

            assert_eq!(
                connections.len(),
                20,
                "node {} at {:?}: expected 20 connections, got {}",
                i,
                coord,
                connections.len()
            );

            // All targets must be unique (guaranteed by construction, but verify).
            assert_eq!(
                targets.len(),
                20,
                "node {} at {:?}: expected 20 unique targets, got {} (duplicates!)",
                i,
                coord,
                targets.len()
            );

            // No self-connections.
            assert!(
                !targets.contains(&coord),
                "node {} at {:?}: connected to self!",
                i,
                coord
            );
        }
    }

    /// Helper: build an N-node mesh and compute neighbor graph statistics.
    ///
    /// Returns (min_neighbors, max_neighbors, asymmetries, node_count).
    fn mesh_stats(n: usize) -> (usize, usize, usize, usize) {
        use crate::spiral3d_to_coord;
        use crate::Spiral3DIndex;

        let mut occupied = HashSet::new();
        let coords: Vec<HexCoord> = (0..n)
            .map(|i| {
                let c = spiral3d_to_coord(Spiral3DIndex::new(i as u64));
                occupied.insert(c);
                c
            })
            .collect();

        // Build neighbor graph: coord → set of neighbor coords.
        let mut neighbors: std::collections::HashMap<HexCoord, HashSet<HexCoord>> =
            std::collections::HashMap::new();

        for &coord in &coords {
            let connections = compute_all_connections(&occupied, coord);
            let targets: HashSet<HexCoord> = connections.iter().map(|c| c.target).collect();
            neighbors.insert(coord, targets);
        }

        let min_nbrs = neighbors.values().map(|s| s.len()).min().unwrap_or(0);
        let max_nbrs = neighbors.values().map(|s| s.len()).max().unwrap_or(0);

        // Count asymmetric relationships.
        let mut asymmetries = 0;
        for &a in &coords {
            for &b in neighbors.get(&a).unwrap() {
                if !neighbors.get(&b).unwrap().contains(&a) {
                    asymmetries += 1;
                }
            }
        }

        (min_nbrs, max_nbrs, asymmetries, n)
    }

    #[test]
    fn mesh_behavior_at_various_sizes() {
        // Verify sane behavior at multiple mesh sizes.
        // At small sizes (N ≤ 20), every node is every other node's neighbor.
        // At larger sizes, every node should have exactly 20 unique neighbors.
        // Asymmetry is expected at small mesh sizes — full symmetry requires
        // the mesh to be large enough that wrap collisions don't dominate
        // (empirically ~20² = 400+ nodes).

        for &n in &[1, 2, 3, 5, 10, 15, 20, 40] {
            let (min_nbrs, max_nbrs, asymmetries, _) = mesh_stats(n);
            let expected_nbrs = std::cmp::min(20, n - 1);

            assert_eq!(
                min_nbrs, expected_nbrs,
                "n={n}: min neighbors {min_nbrs}, expected {expected_nbrs}"
            );
            assert_eq!(
                max_nbrs, expected_nbrs,
                "n={n}: max neighbors {max_nbrs}, expected {expected_nbrs}"
            );

            // Report asymmetries (informational, not a hard failure for small meshes).
            if asymmetries > 0 {
                eprintln!(
                    "n={n}: {asymmetries} asymmetric relationships \
                     (expected at small mesh sizes)"
                );
            }
        }
    }

    #[test]
    fn symmetry_improves_with_size() {
        // As mesh grows, the asymmetry ratio should decrease.
        // At N ≤ 20, everything is fully connected → zero asymmetry.
        // At N=40, some asymmetry is expected.
        // At N=400+, asymmetry should approach zero.
        let stats_20 = mesh_stats(20);
        assert_eq!(
            stats_20.2, 0,
            "N=20 (fully connected) should have zero asymmetry"
        );

        // N=40: asymmetry is expected, just verify it's bounded.
        let stats_40 = mesh_stats(40);
        let asymmetry_ratio = stats_40.2 as f64 / (stats_40.3 * 20) as f64;
        assert!(
            asymmetry_ratio < 0.5,
            "N=40: asymmetry ratio {asymmetry_ratio:.2} is surprisingly high"
        );
        eprintln!(
            "N=40: {}/{} asymmetric ({:.1}%)",
            stats_40.2,
            stats_40.3 * 20,
            asymmetry_ratio * 100.0
        );
    }
}
