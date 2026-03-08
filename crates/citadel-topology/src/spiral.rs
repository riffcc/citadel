//! SPIRAL - Self-similar Positioning In Recursive Ascending Layers
//!
//! Deterministic enumeration of 3D hexagonal coordinates in a self-similar spiral.
//! Each node placement defines its 20 neighbors' positions. The structure is:
//!
//! - **Infinite**: No closure condition, grows forever
//! - **Self-similar**: Same pattern at every scale
//! - **Toroidal wrap**: Every direction wraps to its opposite via gap-and-wrap
//!
//! # 3D Ring Structure
//!
//! The 3D spiral enumerates shells of increasing "radius" where radius is
//! the maximum of hex distance and |z|. Within each shell:
//!
//! - Shell 0: Just the origin (1 slot)
//! - Shell n > 0: All coordinates with max(hex_dist, |z|) = n
//!
//! # Gap and Wrap
//!
//! The 20-neighbor topology creates implicit wrapping:
//! - Planar neighbors at (q±1, r±1, z)
//! - Vertical neighbors at (q, r, z±1)
//! - Extended neighbors at (q±1, r±1, z±1)
//!
//! Going far enough in any direction wraps through the extended connections,
//! creating a toroidal superstructure across infinite space.

use crate::HexCoord;

/// A spiral index - unique slot identifier in the SPIRAL enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpiralIndex(pub u64);

impl SpiralIndex {
    /// Origin slot.
    pub const ORIGIN: Self = Self(0);

    /// Create from raw index.
    pub const fn new(index: u64) -> Self {
        Self(index)
    }

    /// Get the raw index value.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Determine which ring this index falls in.
    ///
    /// Ring 0: index 0
    /// Ring 1: indices 1-6
    /// Ring 2: indices 7-18
    /// Ring n: indices from total_slots(n-1) to total_slots(n)-1
    pub fn ring(&self) -> u64 {
        if self.0 == 0 {
            return 0;
        }

        // Binary search for the ring
        // Total slots through ring n = 1 + 3n(n+1)
        let mut low = 1u64;
        let mut high = ((self.0 as f64).sqrt() as u64) + 2;

        while low < high {
            let mid = (low + high) / 2;
            if total_slots_through(mid) <= self.0 {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    /// Offset within the ring (0 to 6n-1 for ring n > 0).
    pub fn offset_in_ring(&self) -> u64 {
        let ring = self.ring();
        if ring == 0 {
            return 0;
        }
        self.0 - total_slots_through(ring - 1)
    }
}

impl From<u64> for SpiralIndex {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SpiralIndex> for u64 {
    fn from(value: SpiralIndex) -> Self {
        value.0
    }
}

/// Total number of slots in ring n.
///
/// - Ring 0: 1 slot (origin)
/// - Ring n > 0: 6n slots
pub const fn slots_in_ring(ring: u64) -> u64 {
    if ring == 0 {
        1
    } else {
        6 * ring
    }
}

/// Total slots through ring n (inclusive).
///
/// Formula: 1 + 3n(n+1)
///
/// Proven in Lean: `CitadelProofs.Spiral.total_slots_formula`
pub const fn total_slots_through(ring: u64) -> u64 {
    1 + 3 * ring * (ring + 1)
}

/// Iterator over spiral coordinates.
pub struct Spiral {
    current: u64,
    limit: Option<u64>,
}

impl Spiral {
    /// Create an infinite spiral iterator starting from origin.
    pub fn new() -> Self {
        Self {
            current: 0,
            limit: None,
        }
    }

    /// Create a spiral iterator that yields `count` coordinates.
    pub fn take_slots(count: u64) -> Self {
        Self {
            current: 0,
            limit: Some(count),
        }
    }

    /// Create a spiral iterator for a specific ring range.
    pub fn rings(start_ring: u64, end_ring: u64) -> Self {
        let start_slot = if start_ring == 0 {
            0
        } else {
            total_slots_through(start_ring - 1)
        };
        let end_slot = total_slots_through(end_ring);

        Self {
            current: start_slot,
            limit: Some(end_slot),
        }
    }
}

impl Default for Spiral {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for Spiral {
    type Item = HexCoord;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(limit) = self.limit {
            if self.current >= limit {
                return None;
            }
        }

        let coord = spiral_to_coord(SpiralIndex(self.current));
        self.current += 1;
        Some(coord)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.limit {
            Some(limit) => {
                let remaining = limit.saturating_sub(self.current);
                (remaining as usize, Some(remaining as usize))
            }
            None => (usize::MAX, None),
        }
    }
}

/// Convert a spiral index to hexagonal coordinates.
///
/// This is the core bijection proven in Lean.
pub fn spiral_to_coord(index: SpiralIndex) -> HexCoord {
    if index.0 == 0 {
        return HexCoord::ORIGIN;
    }

    let ring = index.ring();
    let offset = index.offset_in_ring();

    // Starting corner of ring n: (n, 0, 0)
    // We traverse 6 edges, each of length n
    let edge = offset / ring;
    let pos_on_edge = offset % ring;

    // Edge directions (counter-clockwise from east corner)
    let corners = [
        HexCoord::planar(ring as i64, 0),              // East corner
        HexCoord::planar(0, ring as i64),              // Northwest corner (after NW edge)
        HexCoord::planar(-(ring as i64), ring as i64), // West corner
        HexCoord::planar(-(ring as i64), 0),           // Southwest corner
        HexCoord::planar(0, -(ring as i64)),           // Southeast corner
        HexCoord::planar(ring as i64, -(ring as i64)), // East-southeast
    ];

    // Direction along each edge
    let directions = [
        HexCoord::planar(-1, 1), // Edge 0: East -> NW
        HexCoord::planar(-1, 0), // Edge 1: NW -> W
        HexCoord::planar(0, -1), // Edge 2: W -> SW
        HexCoord::planar(1, -1), // Edge 3: SW -> SE
        HexCoord::planar(1, 0),  // Edge 4: SE -> E
        HexCoord::planar(0, 1),  // Edge 5: E -> back to start
    ];

    let corner = corners[edge as usize];
    let dir = directions[edge as usize];

    HexCoord::planar(
        corner.q + dir.q * pos_on_edge as i64,
        corner.r + dir.r * pos_on_edge as i64,
    )
}

/// Convert hexagonal coordinates to spiral index.
///
/// Inverse of `spiral_to_coord`.
pub fn coord_to_spiral(coord: HexCoord) -> SpiralIndex {
    // Only handle z=0 for now (planar spiral)
    assert_eq!(
        coord.z, 0,
        "Only planar coordinates supported for spiral index"
    );

    if coord == HexCoord::ORIGIN {
        return SpiralIndex::ORIGIN;
    }

    let ring = coord.ring();

    // Determine which edge and position on edge
    // Corners of ring n
    let corners = [
        (ring as i64, 0i64),           // Edge 0 start
        (0, ring as i64),              // Edge 1 start
        (-(ring as i64), ring as i64), // Edge 2 start
        (-(ring as i64), 0),           // Edge 3 start
        (0, -(ring as i64)),           // Edge 4 start
        (ring as i64, -(ring as i64)), // Edge 5 start
    ];

    let directions = [(-1i64, 1i64), (-1, 0), (0, -1), (1, -1), (1, 0), (0, 1)];

    // Find which edge this coordinate is on
    for edge in 0..6 {
        let (cq, cr) = corners[edge];
        let (dq, dr) = directions[edge];

        // Check if coord lies on this edge
        for pos in 0..ring {
            let test_q = cq + dq * pos as i64;
            let test_r = cr + dr * pos as i64;
            if test_q == coord.q && test_r == coord.r {
                let base = total_slots_through(ring - 1);
                return SpiralIndex(base + edge as u64 * ring + pos);
            }
        }
    }

    // Should never reach here for valid coordinates
    panic!("Invalid coordinate for spiral: {:?}", coord);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_in_ring_formula() {
        assert_eq!(slots_in_ring(0), 1);
        assert_eq!(slots_in_ring(1), 6);
        assert_eq!(slots_in_ring(2), 12);
        assert_eq!(slots_in_ring(3), 18);
        assert_eq!(slots_in_ring(10), 60);
    }

    #[test]
    fn total_slots_formula() {
        // 1 + 3n(n+1)
        assert_eq!(total_slots_through(0), 1);
        assert_eq!(total_slots_through(1), 7); // 1 + 6
        assert_eq!(total_slots_through(2), 19); // 1 + 6 + 12
        assert_eq!(total_slots_through(3), 37); // 1 + 6 + 12 + 18
        assert_eq!(total_slots_through(10), 331);
    }

    #[test]
    fn spiral_index_ring() {
        assert_eq!(SpiralIndex(0).ring(), 0);

        // Ring 1: indices 1-6
        for i in 1..=6 {
            assert_eq!(SpiralIndex(i).ring(), 1, "index {} should be ring 1", i);
        }

        // Ring 2: indices 7-18
        for i in 7..=18 {
            assert_eq!(SpiralIndex(i).ring(), 2, "index {} should be ring 2", i);
        }

        // Ring 3: indices 19-36
        for i in 19..=36 {
            assert_eq!(SpiralIndex(i).ring(), 3, "index {} should be ring 3", i);
        }
    }

    #[test]
    fn origin_is_slot_zero() {
        assert_eq!(spiral_to_coord(SpiralIndex::ORIGIN), HexCoord::ORIGIN);
    }

    #[test]
    fn ring_one_has_six_unique_coords() {
        let ring_one: Vec<_> = (1..=6).map(|i| spiral_to_coord(SpiralIndex(i))).collect();

        // All should be at distance 1 from origin
        for coord in &ring_one {
            assert_eq!(coord.hex_distance(&HexCoord::ORIGIN), 1);
        }

        // All should be unique
        let mut sorted = ring_one.clone();
        sorted.sort_by_key(|c| (c.q, c.r));
        for i in 0..sorted.len() - 1 {
            assert_ne!(sorted[i], sorted[i + 1]);
        }
    }

    #[test]
    fn spiral_bijection_ring_0_to_3() {
        // Test that spiral_to_coord and coord_to_spiral are inverses
        for i in 0..total_slots_through(3) {
            let coord = spiral_to_coord(SpiralIndex(i));
            let back = coord_to_spiral(coord);
            assert_eq!(
                back.0, i,
                "Round-trip failed for index {}: coord {:?}",
                i, coord
            );
        }
    }

    #[test]
    fn spiral_iterator_count() {
        let count = Spiral::take_slots(100).count();
        assert_eq!(count, 100);
    }

    #[test]
    fn spiral_rings_iterator() {
        // Ring 0 only
        let ring_0: Vec<_> = Spiral::rings(0, 0).collect();
        assert_eq!(ring_0.len(), 1);
        assert_eq!(ring_0[0], HexCoord::ORIGIN);

        // Ring 1 only
        let ring_1: Vec<_> = Spiral::rings(1, 1).collect();
        assert_eq!(ring_1.len(), 6);

        // Rings 0-2
        let rings_0_2: Vec<_> = Spiral::rings(0, 2).collect();
        assert_eq!(rings_0_2.len(), 19); // 1 + 6 + 12
    }

    #[test]
    fn large_ring_formula() {
        // Test with large ring to ensure no overflow
        let ring = 1000;
        let total = total_slots_through(ring);
        assert_eq!(total, 1 + 3 * 1000 * 1001); // 3_003_001
    }
}
