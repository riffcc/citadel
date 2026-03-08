//! Hexagonal coordinate system using axial coordinates.
//!
//! Axial coordinates use two axes (q, r) at 60 degrees, with an implicit
//! third axis s = -q - r. This gives us efficient storage (2 values instead
//! of 3) while maintaining the hexagonal symmetry.
//!
//! We extend to 3D with a layer coordinate for the mesh topology.

use std::ops::{Add, Neg, Sub};

/// A position in 3D hexagonal space.
///
/// Uses axial coordinates (q, r) for the hexagonal plane and z for layers.
/// The implicit third axis is s = -q - r.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HexCoord {
    /// First axial coordinate
    pub q: i64,
    /// Second axial coordinate
    pub r: i64,
    /// Layer (vertical position)
    pub z: i64,
}

impl HexCoord {
    /// Origin of the coordinate system.
    pub const ORIGIN: Self = Self { q: 0, r: 0, z: 0 };

    /// Create a new coordinate.
    pub const fn new(q: i64, r: i64, z: i64) -> Self {
        Self { q, r, z }
    }

    /// Create a planar coordinate (z = 0).
    pub const fn planar(q: i64, r: i64) -> Self {
        Self { q, r, z: 0 }
    }

    /// Compute the implicit third axis: s = -q - r.
    pub const fn s(&self) -> i64 {
        -self.q - self.r
    }

    /// Hexagonal distance between two coordinates (same layer).
    ///
    /// For hexagonal coordinates, the distance is:
    /// max(|dq|, |dr|, |ds|) where ds = -dq - dr
    pub fn hex_distance(&self, other: &Self) -> u64 {
        let dq = (self.q - other.q).unsigned_abs();
        let dr = (self.r - other.r).unsigned_abs();
        let ds = ((self.q - other.q) + (self.r - other.r)).unsigned_abs();
        dq.max(dr).max(ds)
    }

    /// Manhattan-style distance including vertical component.
    pub fn distance(&self, other: &Self) -> u64 {
        let hex_dist = self.hex_distance(other);
        let z_dist = (self.z - other.z).unsigned_abs();
        hex_dist + z_dist
    }

    /// Ring number in the spiral (0 = origin, 1 = first ring, etc.)
    pub fn ring(&self) -> u64 {
        self.hex_distance(&Self::ORIGIN)
    }

    /// The six planar neighbor directions.
    pub const PLANAR_DIRECTIONS: [Self; 6] = [
        Self { q: 1, r: 0, z: 0 },  // East
        Self { q: 1, r: -1, z: 0 }, // Northeast
        Self { q: 0, r: -1, z: 0 }, // Northwest
        Self { q: -1, r: 0, z: 0 }, // West
        Self { q: -1, r: 1, z: 0 }, // Southwest
        Self { q: 0, r: 1, z: 0 },  // Southeast
    ];

    /// The two vertical directions.
    pub const VERTICAL_DIRECTIONS: [Self; 2] = [
        Self { q: 0, r: 0, z: 1 },  // Up
        Self { q: 0, r: 0, z: -1 }, // Down
    ];

    /// Get all six planar neighbors.
    pub fn planar_neighbors(&self) -> [Self; 6] {
        Self::PLANAR_DIRECTIONS.map(|d| *self + d)
    }

    /// Get both vertical neighbors.
    pub fn vertical_neighbors(&self) -> [Self; 2] {
        Self::VERTICAL_DIRECTIONS.map(|d| *self + d)
    }
}

impl Add for HexCoord {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        Self {
            q: self.q + other.q,
            r: self.r + other.r,
            z: self.z + other.z,
        }
    }
}

impl Sub for HexCoord {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        Self {
            q: self.q - other.q,
            r: self.r - other.r,
            z: self.z - other.z,
        }
    }
}

impl Neg for HexCoord {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self {
            q: -self.q,
            r: -self.r,
            z: -self.z,
        }
    }
}

impl std::fmt::Display for HexCoord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.q, self.r, self.z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_is_zero() {
        let origin = HexCoord::ORIGIN;
        assert_eq!(origin.q, 0);
        assert_eq!(origin.r, 0);
        assert_eq!(origin.z, 0);
    }

    #[test]
    fn s_axis_constraint() {
        // For any hex coord, q + r + s = 0
        let coords = [
            HexCoord::new(0, 0, 0),
            HexCoord::new(1, 0, 0),
            HexCoord::new(1, -1, 0),
            HexCoord::new(-3, 5, 2),
        ];
        for c in coords {
            assert_eq!(c.q + c.r + c.s(), 0);
        }
    }

    #[test]
    fn hex_distance_from_origin() {
        // Ring 0
        assert_eq!(HexCoord::ORIGIN.ring(), 0);

        // Ring 1 - all 6 neighbors
        for dir in HexCoord::PLANAR_DIRECTIONS {
            assert_eq!(dir.ring(), 1);
        }

        // Ring 2
        assert_eq!(HexCoord::planar(2, 0).ring(), 2);
        assert_eq!(HexCoord::planar(1, 1).ring(), 2);
    }

    #[test]
    fn six_planar_neighbors() {
        let neighbors = HexCoord::ORIGIN.planar_neighbors();
        assert_eq!(neighbors.len(), 6);

        // All neighbors should be at distance 1
        for n in neighbors {
            assert_eq!(n.hex_distance(&HexCoord::ORIGIN), 1);
        }

        // All neighbors should be unique
        let mut sorted: Vec<_> = neighbors.iter().collect();
        sorted.sort_by_key(|c| (c.q, c.r, c.z));
        for i in 0..sorted.len() - 1 {
            assert_ne!(sorted[i], sorted[i + 1]);
        }
    }

    #[test]
    fn vertical_neighbors() {
        let origin = HexCoord::ORIGIN;
        let [up, down] = origin.vertical_neighbors();

        assert_eq!(up, HexCoord::new(0, 0, 1));
        assert_eq!(down, HexCoord::new(0, 0, -1));
    }

    #[test]
    fn addition_subtraction() {
        let a = HexCoord::new(1, 2, 3);
        let b = HexCoord::new(4, -1, 2);

        assert_eq!(a + b, HexCoord::new(5, 1, 5));
        assert_eq!(a - b, HexCoord::new(-3, 3, 1));
        assert_eq!(a + (-b), a - b);
    }
}
