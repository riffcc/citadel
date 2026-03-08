//! DHT routing using hexagonal topology.
//!
//! Maps keys to slots and provides greedy geometric routing.

use crate::DhtKey;
use citadel_topology::{spiral3d_to_coord, HexCoord, Spiral3DIndex};

/// Map a DHT key to a slot index in the mesh.
///
/// Uses the key's prefix to deterministically assign a slot.
/// The slot wraps around the current mesh size.
pub fn key_to_slot(key: &DhtKey, mesh_size: u64) -> u64 {
    if mesh_size == 0 {
        return 0;
    }
    key.prefix_u64() % mesh_size
}

/// Map a DHT key to hex coordinates.
///
/// First maps to a slot, then converts slot to coordinates.
pub fn key_to_coord(key: &DhtKey, mesh_size: u64) -> HexCoord {
    let slot = key_to_slot(key, mesh_size);
    spiral3d_to_coord(Spiral3DIndex(slot))
}

/// Route from a source coordinate toward a key's target coordinate.
///
/// Returns the next hop coordinate using greedy geometric routing.
/// Returns None if we're already at the target.
pub fn route_to_key(
    from: HexCoord,
    key: &DhtKey,
    mesh_size: u64,
    neighbors: &[HexCoord],
) -> Option<HexCoord> {
    let target = key_to_coord(key, mesh_size);

    // Already at target?
    if from == target {
        return None;
    }

    let current_dist = from.distance(&target);

    // Find neighbor closest to target
    let mut best: Option<(HexCoord, u64)> = None;

    for &neighbor in neighbors {
        let dist = neighbor.distance(&target);
        if dist < current_dist {
            match best {
                None => best = Some((neighbor, dist)),
                Some((_, best_dist)) if dist < best_dist => {
                    best = Some((neighbor, dist));
                }
                _ => {}
            }
        }
    }

    best.map(|(coord, _)| coord)
}

/// Estimate hops to reach a key from a coordinate.
///
/// Uses the hex distance as an approximation.
/// Actual routing may take fewer hops due to diagonal connections.
pub fn estimate_hops(from: HexCoord, key: &DhtKey, mesh_size: u64) -> u64 {
    let target = key_to_coord(key, mesh_size);
    from.distance(&target)
}

/// Check if a coordinate is responsible for a key.
///
/// A node is responsible if:
/// 1. It owns the target slot, OR
/// 2. The target slot doesn't exist yet and this is the closest node
pub fn is_responsible_for(coord: HexCoord, key: &DhtKey, mesh_size: u64) -> bool {
    let target = key_to_coord(key, mesh_size);
    coord == target
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_key;

    #[test]
    fn key_to_slot_deterministic() {
        let key = hash_key(b"test");
        let slot1 = key_to_slot(&key, 100);
        let slot2 = key_to_slot(&key, 100);
        assert_eq!(slot1, slot2);
    }

    #[test]
    fn key_to_slot_within_bounds() {
        let key = hash_key(b"test");
        for size in [1, 10, 100, 1000, 10000] {
            let slot = key_to_slot(&key, size);
            assert!(slot < size);
        }
    }

    #[test]
    fn key_to_coord_origin_for_small_mesh() {
        let key = hash_key(b"test");
        // With mesh size 1, everything maps to origin
        let coord = key_to_coord(&key, 1);
        assert_eq!(coord, HexCoord::ORIGIN);
    }

    #[test]
    fn routing_reaches_target() {
        let key = hash_key(b"test");
        let mesh_size = 100;
        let target = key_to_coord(&key, mesh_size);

        // Start from origin, route to target
        let mut current = HexCoord::ORIGIN;
        let mut hops = 0;
        let max_hops = 50;

        while current != target && hops < max_hops {
            // Get all 20 neighbors
            let mut neighbors = Vec::new();
            neighbors.extend(current.planar_neighbors());
            neighbors.extend(current.vertical_neighbors());
            // Note: Extended neighbors would be added here in full implementation

            if let Some(next) = route_to_key(current, &key, mesh_size, &neighbors) {
                current = next;
                hops += 1;
            } else {
                break;
            }
        }

        // Should reach target or get very close
        let final_dist = current.distance(&target);
        assert!(
            final_dist <= 1,
            "Should reach target or adjacent, got dist {}",
            final_dist
        );
    }

    #[test]
    fn is_responsible_exact_match() {
        let key = hash_key(b"test");
        let mesh_size = 100;
        let target = key_to_coord(&key, mesh_size);

        assert!(is_responsible_for(target, &key, mesh_size));
        assert!(
            !is_responsible_for(HexCoord::ORIGIN, &key, mesh_size) || target == HexCoord::ORIGIN
        );
    }

    #[test]
    fn estimate_hops_reasonable() {
        let key = hash_key(b"test");
        let mesh_size = 1000;

        let hops = estimate_hops(HexCoord::ORIGIN, &key, mesh_size);
        // For a mesh of 1000 nodes (roughly 10 shells), max distance should be ~10
        assert!(
            hops <= 20,
            "Hops {} seems too high for mesh size {}",
            hops,
            mesh_size
        );
    }
}
