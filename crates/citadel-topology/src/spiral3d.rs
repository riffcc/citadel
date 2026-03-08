//! SPIRAL-3D: Self-similar 3D Hexagonal Spiral Enumeration
//!
//! # The Core Insight
//!
//! The 20-neighbor topology creates a 3D structure where:
//! - Each node has exactly 20 neighbors (6 planar + 2 vertical + 12 extended)
//! - The structure is infinite and self-similar
//! - Opposite directions wrap through gap-and-wrap
//!
//! # Shell Structure
//!
//! We enumerate in "shells" of increasing radius where:
//!   shell_radius(q, r, z) = max(hex_distance(q, r), |z|)
//!
//! Shell sizes:
//! - Shell 0: 1 (origin only)
//! - Shell n > 0: 18n² + 2
//!
//! Total through shell n: 6n³ + 9n² + 5n + 1
//!
//! # Enumeration Order Within Shells
//!
//! Within each shell, we enumerate to maximize locality (neighbors are close in index):
//! 1. Start at z=0, traverse hex ring n counter-clockwise
//! 2. Alternate z=+1, z=-1, z=+2, z=-2, ...
//! 3. At each z-level, enumerate from outer ring inward
//! 4. Within each ring, traverse counter-clockwise
//!
//! # Self-Similarity
//!
//! The enumeration is self-similar because:
//! - Every node sees the same 20 directions
//! - The local structure (20 neighbors) mirrors the global structure
//! - Zooming in or out shows the same pattern
//!
//! # Gap and Wrap
//!
//! The toroidal wrapping emerges from the topology:
//! - Extended connections (planar + vertical) create diagonal paths
//! - Going far enough in any direction eventually connects back
//! - The "gap" is infinite space; the "wrap" is through neighbor connections

use crate::HexCoord;

/// A 3D spiral index for the 20-neighbor mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Spiral3DIndex(pub u64);

impl Spiral3DIndex {
    pub const ORIGIN: Self = Self(0);

    pub const fn new(index: u64) -> Self {
        Self(index)
    }

    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Determine which shell this index falls in.
    pub fn shell(&self) -> u64 {
        if self.0 == 0 {
            return 0;
        }
        // Binary search: find n where total_through(n-1) < index <= total_through(n)
        let mut low = 1u64;
        let mut high = ((self.0 as f64).cbrt() as u64) + 2;

        while low < high {
            let mid = (low + high) / 2;
            if total_slots_through_shell(mid) <= self.0 {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    /// Offset within the shell.
    pub fn offset_in_shell(&self) -> u64 {
        let shell = self.shell();
        if shell == 0 {
            return 0;
        }
        self.0 - total_slots_through_shell(shell - 1)
    }
}

/// Number of slots in shell n.
///
/// - Shell 0: 1
/// - Shell n > 0: 18n² + 2
pub const fn slots_in_shell(n: u64) -> u64 {
    if n == 0 {
        1
    } else {
        18 * n * n + 2
    }
}

/// Total slots through shell n (inclusive).
///
/// Formula: 6n³ + 9n² + 5n + 1
pub const fn total_slots_through_shell(n: u64) -> u64 {
    6 * n * n * n + 9 * n * n + 5 * n + 1
}

/// Convert a 3D spiral index to coordinates.
pub fn spiral3d_to_coord(index: Spiral3DIndex) -> HexCoord {
    if index.0 == 0 {
        return HexCoord::ORIGIN;
    }

    let shell = index.shell();
    let offset = index.offset_in_shell();

    // Within shell n, we enumerate:
    // 1. z=0 hex ring n (6n slots)
    // 2. z=1: hex rings n down to 0 (6n + 6(n-1) + ... + 1 = 3n² + 3n + 1 slots)
    // 3. z=-1: same
    // 4. z=2: hex rings n down to 0
    // ... and so on

    // Count slots at each z-level in shell n:
    // - z=0: only ring n → 6n
    // - |z| = k for 1 ≤ k < n: rings n, n-1, ..., (n-k+1) → sum = 6n + 6(n-1) + ... + 6(n-k+1) = 6k(2n-k+1)/2 = 3k(2n-k+1)
    //   Wait no. For |z| = k < n, we need hex_dist ≥ n-k+1 to have max = n.
    //   Actually for |z| = k < n, we have max(hex_dist, k) = n, so hex_dist = n. Just ring n. → 6n slots
    // - |z| = n: hex_dist can be 0 to n → 1 + 3n(n+1) slots

    // Let me recalculate. For shell n:
    // Position (q,r,z) is in shell n iff max(hex_dist(q,r), |z|) = n
    //
    // Case 1: |z| < n and hex_dist = n
    //   z can be -(n-1), ..., -1, 0, 1, ..., (n-1) → 2n-1 values
    //   Each has 6n positions (ring n)
    //   Total: (2n-1) × 6n = 12n² - 6n
    //
    // Case 2: |z| = n and hex_dist ≤ n
    //   z = +n or z = -n → 2 values
    //   hex_dist can be 0, 1, ..., n → total positions = 1 + 3n(n+1)
    //   Total: 2 × (1 + 3n² + 3n) = 2 + 6n² + 6n
    //
    // Grand total: 12n² - 6n + 2 + 6n² + 6n = 18n² + 2 ✓

    // Enumeration order within shell n:
    // 1. z = 0, ring n: 6n slots
    // 2. z = 1, ring n: 6n slots
    // 3. z = -1, ring n: 6n slots
    // ...
    // 2n-1. z = n-1, ring n: 6n slots
    // 2n. z = -(n-1), ring n: 6n slots
    // After that: (2n-1) × 6n = 12n² - 6n slots enumerated
    //
    // Then z = +n, all rings 0 to n: 1 + 3n(n+1) slots
    // Then z = -n, all rings 0 to n: 1 + 3n(n+1) slots

    let ring_n_size = 6 * shell;
    let z_levels_with_ring_n = 2 * shell - 1; // z = -(n-1) to (n-1)
    let slots_at_ring_n = z_levels_with_ring_n * ring_n_size; // (2n-1) × 6n

    if offset < slots_at_ring_n {
        // We're in the ring-n portion at some z with |z| < n
        let z_index = offset / ring_n_size;
        let ring_offset = offset % ring_n_size;

        // z_index 0 → z=0, 1 → z=1, 2 → z=-1, 3 → z=2, 4 → z=-2, ...
        let z = if z_index == 0 {
            0
        } else {
            let half = (z_index + 1) / 2;
            if z_index % 2 == 1 {
                half as i64
            } else {
                -(half as i64)
            }
        };

        let planar = ring_coord(shell, ring_offset);
        HexCoord::new(planar.q, planar.r, z)
    } else {
        // We're in the z = ±n portion
        let remaining = offset - slots_at_ring_n;
        let disk_size = total_slots_through_shell_2d(shell); // 1 + 3n(n+1)

        if remaining < disk_size {
            // z = +n
            let planar = disk_coord(shell, remaining);
            HexCoord::new(planar.q, planar.r, shell as i64)
        } else {
            // z = -n
            let disk_offset = remaining - disk_size;
            let planar = disk_coord(shell, disk_offset);
            HexCoord::new(planar.q, planar.r, -(shell as i64))
        }
    }
}

/// Convert coordinates to 3D spiral index.
pub fn coord_to_spiral3d(coord: HexCoord) -> Spiral3DIndex {
    if coord == HexCoord::ORIGIN {
        return Spiral3DIndex::ORIGIN;
    }

    let hex_dist = coord.hex_distance(&HexCoord::new(0, 0, coord.z)) as u64;
    let abs_z = coord.z.unsigned_abs();
    let shell = hex_dist.max(abs_z);

    let base = if shell > 0 {
        total_slots_through_shell(shell - 1)
    } else {
        0
    };

    let ring_n_size = 6 * shell;
    let z_levels_with_ring_n = 2 * shell - 1;
    let slots_at_ring_n = z_levels_with_ring_n * ring_n_size;

    if abs_z < shell {
        // This coord has hex_dist = shell and |z| < shell
        // It's in the ring-n portion

        // Find z_index from z value
        let z_index = if coord.z == 0 {
            0
        } else if coord.z > 0 {
            (2 * coord.z - 1) as u64
        } else {
            (2 * (-coord.z)) as u64
        };

        let ring_offset = coord_to_ring_offset(shell, HexCoord::planar(coord.q, coord.r));
        Spiral3DIndex(base + z_index * ring_n_size + ring_offset)
    } else {
        // abs_z = shell, so we're in the disk portion
        let disk_offset = coord_to_disk_offset(shell, HexCoord::planar(coord.q, coord.r));

        if coord.z > 0 {
            Spiral3DIndex(base + slots_at_ring_n + disk_offset)
        } else {
            let disk_size = total_slots_through_shell_2d(shell);
            Spiral3DIndex(base + slots_at_ring_n + disk_size + disk_offset)
        }
    }
}

// ============ Helper functions for 2D enumeration within shells ============

/// Total slots through ring n in 2D: 1 + 3n(n+1)
const fn total_slots_through_shell_2d(n: u64) -> u64 {
    1 + 3 * n * (n + 1)
}

/// Slots in 2D ring n: 6n (or 1 for n=0)
const fn slots_in_ring_2d(n: u64) -> u64 {
    if n == 0 {
        1
    } else {
        6 * n
    }
}

/// Get the coordinate at a given offset within ring n (2D).
fn ring_coord(ring: u64, offset: u64) -> HexCoord {
    if ring == 0 {
        return HexCoord::ORIGIN;
    }

    let edge = offset / ring;
    let pos = offset % ring;

    let corners = [
        (ring as i64, 0i64),
        (0, ring as i64),
        (-(ring as i64), ring as i64),
        (-(ring as i64), 0),
        (0, -(ring as i64)),
        (ring as i64, -(ring as i64)),
    ];

    let directions = [(-1i64, 1i64), (-1, 0), (0, -1), (1, -1), (1, 0), (0, 1)];

    let (cq, cr) = corners[edge as usize];
    let (dq, dr) = directions[edge as usize];

    HexCoord::planar(cq + dq * pos as i64, cr + dr * pos as i64)
}

/// Get the offset of a coordinate within ring n (2D).
fn coord_to_ring_offset(ring: u64, coord: HexCoord) -> u64 {
    if ring == 0 {
        return 0;
    }

    let corners = [
        (ring as i64, 0i64),
        (0, ring as i64),
        (-(ring as i64), ring as i64),
        (-(ring as i64), 0),
        (0, -(ring as i64)),
        (ring as i64, -(ring as i64)),
    ];

    let directions = [(-1i64, 1i64), (-1, 0), (0, -1), (1, -1), (1, 0), (0, 1)];

    for edge in 0..6 {
        let (cq, cr) = corners[edge];
        let (dq, dr) = directions[edge];

        for pos in 0..ring {
            if coord.q == cq + dq * pos as i64 && coord.r == cr + dr * pos as i64 {
                return edge as u64 * ring + pos;
            }
        }
    }

    panic!("Coordinate {:?} not on ring {}", coord, ring);
}

/// Get the coordinate at a given offset within disk (rings 0 to n).
fn disk_coord(max_ring: u64, offset: u64) -> HexCoord {
    if offset == 0 {
        return HexCoord::ORIGIN;
    }

    // Find which ring this offset is in
    let mut remaining = offset;
    for ring in 0..=max_ring {
        let ring_size = slots_in_ring_2d(ring);
        if remaining < ring_size {
            return ring_coord(ring, remaining);
        }
        remaining -= ring_size;
    }

    panic!(
        "Offset {} exceeds disk size for max_ring {}",
        offset, max_ring
    );
}

/// Get the offset of a coordinate within disk (rings 0 to n).
fn coord_to_disk_offset(max_ring: u64, coord: HexCoord) -> u64 {
    if coord == HexCoord::ORIGIN {
        return 0;
    }

    let ring = coord.hex_distance(&HexCoord::ORIGIN) as u64;
    assert!(
        ring <= max_ring,
        "Coordinate ring {} exceeds max {}",
        ring,
        max_ring
    );

    let base = if ring > 0 {
        total_slots_through_shell_2d(ring - 1)
    } else {
        0
    };

    base + coord_to_ring_offset(ring, coord)
}

/// Iterator over 3D spiral coordinates.
pub struct Spiral3D {
    current: u64,
    limit: Option<u64>,
}

impl Spiral3D {
    pub fn new() -> Self {
        Self {
            current: 0,
            limit: None,
        }
    }

    pub fn take_slots(count: u64) -> Self {
        Self {
            current: 0,
            limit: Some(count),
        }
    }

    pub fn shells(start: u64, end: u64) -> Self {
        let start_slot = if start == 0 {
            0
        } else {
            total_slots_through_shell(start - 1)
        };
        let end_slot = total_slots_through_shell(end);
        Self {
            current: start_slot,
            limit: Some(end_slot),
        }
    }
}

impl Default for Spiral3D {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for Spiral3D {
    type Item = HexCoord;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(limit) = self.limit {
            if self.current >= limit {
                return None;
            }
        }

        let coord = spiral3d_to_coord(Spiral3DIndex(self.current));
        self.current += 1;
        Some(coord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_size_formula() {
        assert_eq!(slots_in_shell(0), 1);
        assert_eq!(slots_in_shell(1), 20); // 18 + 2
        assert_eq!(slots_in_shell(2), 74); // 72 + 2
        assert_eq!(slots_in_shell(3), 164); // 162 + 2
    }

    #[test]
    fn total_through_shell_formula() {
        assert_eq!(total_slots_through_shell(0), 1);
        assert_eq!(total_slots_through_shell(1), 21); // 1 + 20
        assert_eq!(total_slots_through_shell(2), 95); // 21 + 74
        assert_eq!(total_slots_through_shell(3), 259); // 95 + 164
    }

    #[test]
    fn origin_is_index_zero() {
        assert_eq!(spiral3d_to_coord(Spiral3DIndex(0)), HexCoord::ORIGIN);
        assert_eq!(coord_to_spiral3d(HexCoord::ORIGIN), Spiral3DIndex(0));
    }

    #[test]
    fn shell_1_has_20_unique_coords() {
        let shell_1: Vec<_> = (1..=20)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        // All should have shell_radius = 1
        for coord in &shell_1 {
            let radius = (coord.hex_distance(&HexCoord::new(0, 0, coord.z)) as u64)
                .max(coord.z.unsigned_abs());
            assert_eq!(radius, 1, "Coord {:?} has wrong radius", coord);
        }

        // All should be unique
        for i in 0..shell_1.len() {
            for j in (i + 1)..shell_1.len() {
                assert_ne!(
                    shell_1[i],
                    shell_1[j],
                    "Duplicate at {} and {}",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    #[test]
    fn shell_1_are_neighbors_of_origin() {
        use crate::Neighbors;

        let neighbors = Neighbors::of(HexCoord::ORIGIN);
        let shell_1: Vec<_> = (1..=20)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        for coord in &shell_1 {
            assert!(
                neighbors.contains(coord),
                "Shell-1 coord {:?} is not a neighbor of origin",
                coord
            );
        }
    }

    #[test]
    fn bijection_through_shell_2() {
        let total = total_slots_through_shell(2);

        for i in 0..total {
            let coord = spiral3d_to_coord(Spiral3DIndex(i));
            let back = coord_to_spiral3d(coord);
            assert_eq!(
                back.0, i,
                "Round-trip failed for index {}: coord {:?} -> {}",
                i, coord, back.0
            );
        }
    }

    #[test]
    fn bijection_through_shell_3() {
        let total = total_slots_through_shell(3);

        for i in 0..total {
            let coord = spiral3d_to_coord(Spiral3DIndex(i));
            let back = coord_to_spiral3d(coord);
            assert_eq!(
                back.0, i,
                "Round-trip failed for index {}: coord {:?} -> {}",
                i, coord, back.0
            );
        }
    }

    #[test]
    fn all_shell_1_coords_are_20_neighbor_directions() {
        use crate::Neighbors;

        let directions = Neighbors::all_directions();
        let shell_1: Vec<_> = (1..=20)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        // Every shell-1 coord should be one of the 20 directions
        for coord in &shell_1 {
            assert!(
                directions.contains(coord),
                "Shell-1 coord {:?} is not a neighbor direction",
                coord
            );
        }

        // Every direction should appear in shell-1
        for dir in &directions {
            assert!(
                shell_1.contains(dir),
                "Direction {:?} not found in shell-1",
                dir
            );
        }
    }

    #[test]
    fn iterator_yields_correct_count() {
        let count = Spiral3D::take_slots(100).count();
        assert_eq!(count, 100);
    }

    #[test]
    fn iterator_shells_range() {
        // Shell 1 only
        let shell_1: Vec<_> = Spiral3D::shells(1, 1).collect();
        assert_eq!(shell_1.len(), 20);

        // Shells 0-2
        let shells_0_2: Vec<_> = Spiral3D::shells(0, 2).collect();
        assert_eq!(shells_0_2.len(), 95); // 1 + 20 + 74
    }

    #[test]
    fn shell_index_detection() {
        assert_eq!(Spiral3DIndex(0).shell(), 0);

        // Shell 1: indices 1-20
        for i in 1..=20 {
            assert_eq!(Spiral3DIndex(i).shell(), 1, "Index {} should be shell 1", i);
        }

        // Shell 2: indices 21-94
        for i in 21..=94 {
            assert_eq!(Spiral3DIndex(i).shell(), 2, "Index {} should be shell 2", i);
        }

        // Shell 3: indices 95-258
        for i in 95..=258 {
            assert_eq!(Spiral3DIndex(i).shell(), 3, "Index {} should be shell 3", i);
        }
    }

    #[test]
    fn self_similar_neighbor_structure() {
        // Every node should have the same local structure:
        // Its 20 neighbors are at the 20 canonical directions from it

        use crate::Neighbors;

        // Test a few nodes from different shells
        let test_indices = [0, 1, 5, 21, 50, 100];

        for idx in test_indices {
            let coord = spiral3d_to_coord(Spiral3DIndex(idx));
            let neighbors = Neighbors::of(coord);

            // All 20 neighbors should be valid coords (exist in the infinite mesh)
            // The key property is that the directions are always the same
            let dirs_from_here: Vec<_> = neighbors.iter().map(|&n| n - coord).collect();
            let canonical = Neighbors::all_directions();

            for dir in &dirs_from_here {
                assert!(
                    canonical.contains(dir),
                    "Node {} at {:?} has non-canonical neighbor direction {:?}",
                    idx,
                    coord,
                    dir
                );
            }
        }
    }

    #[test]
    fn growth_is_balanced_in_3d() {
        // Verify that the 3D spiral grows in all three dimensions
        // The key insight: shell n should have z values from -n to +n

        use std::collections::HashSet;

        for shell in 1..=4 {
            let start = if shell == 1 {
                1
            } else {
                total_slots_through_shell(shell - 1)
            };
            let end = total_slots_through_shell(shell);

            let coords: Vec<_> = (start..end)
                .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
                .collect();

            let z_values: HashSet<_> = coords.iter().map(|c| c.z).collect();
            let q_values: HashSet<_> = coords.iter().map(|c| c.q).collect();

            // Shell n should have z values from -n to +n (2n+1 distinct values)
            let shell_i = shell as i64;
            let expected_z_range: HashSet<_> = (-shell_i..=shell_i).collect();

            assert_eq!(
                z_values, expected_z_range,
                "Shell {} should have z from {} to {}, got {:?}",
                shell, -shell_i, shell_i, z_values
            );

            // Q should also range from -n to +n
            let expected_q_range: HashSet<_> = (-shell_i..=shell_i).collect();
            assert_eq!(
                q_values, expected_q_range,
                "Shell {} should have q from {} to {}, got {:?}",
                shell, -shell_i, shell_i, q_values
            );

            println!(
                "Shell {}: {} coords, z range {:?}, q range {:?}",
                shell,
                coords.len(),
                z_values,
                q_values
            );
        }
    }

    #[test]
    fn cumulative_growth_expands_all_axes() {
        // Test cumulative growth through all slots up to N
        // This simulates how the mesh grows during assembly

        let test_counts = [21, 95, 259]; // End of shells 1, 2, 3

        for count in test_counts {
            let coords: Vec<_> = (0..count)
                .map(|i| spiral3d_to_coord(Spiral3DIndex(i as u64)))
                .collect();

            let min_z = coords.iter().map(|c| c.z).min().unwrap();
            let max_z = coords.iter().map(|c| c.z).max().unwrap();
            let min_q = coords.iter().map(|c| c.q).min().unwrap();
            let max_q = coords.iter().map(|c| c.q).max().unwrap();
            let min_r = coords.iter().map(|c| c.r).min().unwrap();
            let max_r = coords.iter().map(|c| c.r).max().unwrap();

            let z_span = max_z - min_z;
            let q_span = max_q - min_q;
            let r_span = max_r - min_r;

            println!(
                "After {} nodes: Q [{}, {}] (span {}), R [{}, {}] (span {}), Z [{}, {}] (span {})",
                count, min_q, max_q, q_span, min_r, max_r, r_span, min_z, max_z, z_span
            );

            // All axes should grow symmetrically for complete shells
            // (q_span should equal z_span at shell boundaries)
            assert_eq!(
                q_span, z_span,
                "At {} nodes (shell boundary), Q span {} should equal Z span {}",
                count, q_span, z_span
            );
        }
    }

    #[test]
    fn mid_shell_growth_analysis() {
        // Analyze growth at various points, including mid-shell
        // This shows how the mesh looks during assembly (not just at shell boundaries)

        let test_points = [10, 21, 50, 75, 95, 100, 150, 200, 259];

        println!("\nMesh growth analysis:");
        println!(
            "{:>6} | {:>12} | {:>12} | {:>12} | {:>6}",
            "Nodes", "Q range", "R range", "Z range", "Shell"
        );
        println!(
            "{:-<6}-+-{:-<12}-+-{:-<12}-+-{:-<12}-+-{:-<6}",
            "", "", "", "", ""
        );

        for count in test_points {
            let coords: Vec<_> = (0..count as u64)
                .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
                .collect();

            let min_z = coords.iter().map(|c| c.z).min().unwrap();
            let max_z = coords.iter().map(|c| c.z).max().unwrap();
            let min_q = coords.iter().map(|c| c.q).min().unwrap();
            let max_q = coords.iter().map(|c| c.q).max().unwrap();
            let min_r = coords.iter().map(|c| c.r).min().unwrap();
            let max_r = coords.iter().map(|c| c.r).max().unwrap();

            let shell = Spiral3DIndex(count as u64 - 1).shell();

            println!(
                "{:>6} | [{:>4}, {:>4}] | [{:>4}, {:>4}] | [{:>4}, {:>4}] | {:>6}",
                count, min_q, max_q, min_r, max_r, min_z, max_z, shell
            );
        }

        // Key insight: mid-shell growth will show Q/R advancing faster than Z
        // because we enumerate ring-n at z=0 first, then z=±1, etc.
        // Only at shell end do all axes catch up

        // At 100 nodes (mid shell 3), we expect Q/R to be at ±3 but Z might lag
        let coords_100: Vec<_> = (0..100)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        let z_at_100: i64 = coords_100.iter().map(|c| c.z.abs()).max().unwrap();
        let q_at_100: i64 = coords_100.iter().map(|c| c.q.abs()).max().unwrap();

        println!("\nAt 100 nodes: max|Q|={}, max|Z|={}", q_at_100, z_at_100);
        println!("This is expected - within a shell, Q/R fill first, then Z catches up");
    }

    #[test]
    fn diagnose_column_growth() {
        // Diagnose whether the mesh forms a column at high shell counts
        use std::collections::HashMap;

        println!("\n=== Coordinate distribution by z-level ===\n");

        // Check distribution at shell boundaries
        for shell in [3, 5, 7] {
            let total = total_slots_through_shell(shell);
            let coords: Vec<_> = (0..total)
                .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
                .collect();

            // Count coords at each z level
            let mut z_counts: HashMap<i64, usize> = HashMap::new();
            for c in &coords {
                *z_counts.entry(c.z).or_insert(0) += 1;
            }

            // Count coords at each hex distance from vertical axis
            let mut hex_dist_counts: HashMap<u64, usize> = HashMap::new();
            for c in &coords {
                let dist = c.hex_distance(&HexCoord::new(0, 0, c.z));
                *hex_dist_counts.entry(dist).or_insert(0) += 1;
            }

            println!("Shell {}: {} total coords", shell, total);
            println!("  Z distribution (z -> count):");
            let mut z_sorted: Vec<_> = z_counts.iter().collect();
            z_sorted.sort_by_key(|(z, _)| **z);
            for (z, count) in z_sorted {
                let bar = "#".repeat(*count / 5);
                println!("    z={:+3}: {:4} {}", z, count, bar);
            }

            println!("  Hex-distance distribution (dist -> count):");
            let mut dist_sorted: Vec<_> = hex_dist_counts.iter().collect();
            dist_sorted.sort_by_key(|(d, _)| **d);
            for (d, count) in dist_sorted {
                let bar = "#".repeat(*count / 5);
                println!("    d={:3}: {:4} {}", d, count, bar);
            }
            println!();
        }
    }
}
