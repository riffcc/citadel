//! # SPORE: Succinct Proof of Range Exclusions
//!
//! An information-theoretically optimal distributed sync protocol for 256-bit hash spaces.
//!
//! ## Key Insight
//!
//! Synchronization fundamentally requires communicating only one thing:
//! the **boundaries** between "have" and "don't have" regions. In a 256-bit hash space,
//! these boundaries can be represented as ranges. The number of ranges—not the amount
//! of data—determines sync complexity.
//!
//! ## Core Properties (Proven in proofs/CitadelProofs/Spore.lean)
//!
//! 1. **Symmetric Optimality**: Both empty nodes (0% coverage) and full nodes (100% coverage)
//!    require only 64 bytes of state representation.
//!
//! 2. **Self-Optimization**: Each successful sync operation reduces future sync overhead.
//!
//! 3. **Convergence to Zero**: At steady state, protocol overhead approaches zero as
//!    all nodes converge to full coverage.
//!
//! 4. **Information-Theoretic Optimality**: O(k) representation for k boundaries,
//!    matching the lower bound.
//!
//! ## Implicit Exclusion
//!
//! The gaps between ranges are **implicitly excluded**. Values not in HaveList and not
//! in WantList are permanently excluded from sync—they require zero encoding.
//!
//! ```text
//! Universe = [0, 2^256)
//!
//! HaveList: Ranges of values I possess
//! WantList: Ranges of values I desire
//! GAPS:     Everything else - IMPLICITLY EXCLUDED (never syncs, zero cost)
//! ```

use serde::{Deserialize, Serialize};
use std::cmp::{max, min, Ordering};

/// A 256-bit unsigned integer.
///
/// Represented as 4 u64 limbs in little-endian order.
/// Limb 0 is least significant, limb 3 is most significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct U256 {
    /// Four 64-bit limbs, little-endian (limb[0] is least significant)
    pub limbs: [u64; 4],
}

impl U256 {
    /// Zero value
    pub const ZERO: U256 = U256 {
        limbs: [0, 0, 0, 0],
    };

    /// Maximum value (2^256 - 1)
    pub const MAX: U256 = U256 {
        limbs: [u64::MAX, u64::MAX, u64::MAX, u64::MAX],
    };

    /// Create from a u64 (placed in lowest limb)
    pub const fn from_u64(n: u64) -> Self {
        U256 {
            limbs: [n, 0, 0, 0],
        }
    }

    /// Create from a u128 (placed in lowest two limbs)
    pub const fn from_u128(n: u128) -> Self {
        U256 {
            limbs: [n as u64, (n >> 64) as u64, 0, 0],
        }
    }

    /// Create from 32 bytes (big-endian)
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        // Big endian: bytes[0..8] is most significant
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (3 - i) * 8;
            *limb = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        U256 { limbs }
    }

    /// Convert to 32 bytes (big-endian)
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            let limb_bytes = self.limbs[i].to_be_bytes();
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.limbs == [0, 0, 0, 0]
    }

    /// Checked addition
    pub fn checked_add(&self, other: &U256) -> Option<U256> {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for (i, res) in result.iter_mut().enumerate() {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry;
            *res = sum as u64;
            carry = sum >> 64;
        }

        if carry == 0 {
            Some(U256 { limbs: result })
        } else {
            None // Overflow
        }
    }

    /// Checked subtraction
    pub fn checked_sub(&self, other: &U256) -> Option<U256> {
        if self < other {
            return None;
        }

        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for (i, res) in result.iter_mut().enumerate() {
            let diff = self.limbs[i] as i128 - other.limbs[i] as i128 - borrow;
            if diff < 0 {
                *res = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                *res = diff as u64;
                borrow = 0;
            }
        }

        Some(U256 { limbs: result })
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare from most significant limb
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for U256 {
    fn from(n: u64) -> Self {
        U256::from_u64(n)
    }
}

impl From<u128> for U256 {
    fn from(n: u128) -> Self {
        U256::from_u128(n)
    }
}

/// A range [start, stop) in 256-bit hash space.
///
/// Represents ALL values v where start ≤ v < stop.
/// Encoding cost: 64 bytes (two 256-bit values), regardless of how many values are covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range256 {
    /// Start of range (inclusive)
    pub start: U256,
    /// End of range (exclusive)
    pub stop: U256,
}

impl Range256 {
    /// Create a new range. Panics if start > stop.
    pub fn new(start: U256, stop: U256) -> Self {
        assert!(start <= stop, "Invalid range: start > stop");
        Range256 { start, stop }
    }

    /// Create range covering entire 256-bit space
    pub fn full() -> Self {
        Range256 {
            start: U256::ZERO,
            stop: U256::MAX,
        }
    }

    /// Check if range is empty
    pub fn is_empty(&self) -> bool {
        self.start == self.stop
    }

    /// Check if a value is in this range
    pub fn contains(&self, v: &U256) -> bool {
        self.start <= *v && *v < self.stop
    }

    /// Check if two ranges are disjoint
    pub fn is_disjoint(&self, other: &Range256) -> bool {
        self.stop <= other.start || other.stop <= self.start
    }

    /// Check if two ranges are adjacent (can be merged)
    pub fn is_adjacent(&self, other: &Range256) -> bool {
        self.stop == other.start || other.stop == self.start
    }

    /// Compute intersection of two ranges
    pub fn intersect(&self, other: &Range256) -> Option<Range256> {
        let start = max(self.start, other.start);
        let stop = min(self.stop, other.stop);

        if start < stop {
            Some(Range256 { start, stop })
        } else {
            None
        }
    }

    /// Merge two adjacent or overlapping ranges
    pub fn merge(&self, other: &Range256) -> Option<Range256> {
        // Can merge if they overlap or are adjacent
        if self.stop < other.start || other.stop < self.start {
            return None; // Gap between them
        }

        Some(Range256 {
            start: min(self.start, other.start),
            stop: max(self.stop, other.stop),
        })
    }
}

/// SPORE: A sorted list of non-overlapping ranges.
///
/// Represents either a HaveList (what I possess) or WantList (what I desire).
/// The gaps between ranges are **implicitly excluded** from sync.
///
/// ## Encoding Size
///
/// 64 bytes per range. A single range covering 2^255 values costs the same as
/// a single range covering 1 value. The cost is O(boundaries), not O(values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Spore {
    /// Sorted, non-overlapping ranges
    ranges: Vec<Range256>,
}

impl Spore {
    /// Create an empty SPORE (nothing covered, everything excluded)
    pub fn empty() -> Self {
        Spore { ranges: vec![] }
    }

    /// Create a SPORE covering the entire 256-bit space
    pub fn full() -> Self {
        Spore {
            ranges: vec![Range256::full()],
        }
    }

    /// Create from a single range
    pub fn from_range(range: Range256) -> Self {
        if range.is_empty() {
            Spore::empty()
        } else {
            Spore {
                ranges: vec![range],
            }
        }
    }

    /// Create from multiple ranges (will be sorted and merged)
    pub fn from_ranges(mut ranges: Vec<Range256>) -> Self {
        // Sort by start
        ranges.sort_by(|a, b| a.start.cmp(&b.start));

        // Merge overlapping/adjacent ranges
        let mut merged: Vec<Range256> = vec![];
        for range in ranges {
            if range.is_empty() {
                continue;
            }

            if let Some(last) = merged.last_mut() {
                if let Some(merged_range) = last.merge(&range) {
                    *last = merged_range;
                    continue;
                }
            }
            merged.push(range);
        }

        Spore { ranges: merged }
    }

    /// Get the ranges
    pub fn ranges(&self) -> &[Range256] {
        &self.ranges
    }

    /// Number of ranges
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Number of boundary transitions (2 per range)
    pub fn boundary_count(&self) -> usize {
        2 * self.ranges.len()
    }

    /// Encoding size in bytes (64 bytes per range)
    pub fn encoding_size(&self) -> usize {
        64 * self.ranges.len()
    }

    /// Check if a value is covered by this SPORE
    pub fn covers(&self, v: &U256) -> bool {
        // Binary search for efficiency
        self.ranges.iter().any(|r| r.contains(v))
    }

    /// Check if a value is excluded (not covered) by this SPORE
    pub fn excludes(&self, v: &U256) -> bool {
        !self.covers(v)
    }

    /// Check if empty (no ranges)
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Check if this SPORE is disjoint with another
    pub fn is_disjoint(&self, other: &Spore) -> bool {
        // For sorted ranges, use merge-style comparison
        let mut i = 0;
        let mut j = 0;

        while i < self.ranges.len() && j < other.ranges.len() {
            if !self.ranges[i].is_disjoint(&other.ranges[j]) {
                return false;
            }

            // Advance the one that ends first
            if self.ranges[i].stop <= other.ranges[j].stop {
                i += 1;
            } else {
                j += 1;
            }
        }

        true
    }

    /// Compute intersection: values in both SPOREs
    ///
    /// This is the core sync operation: `to_send = my_have.intersect(their_want)`
    pub fn intersect(&self, other: &Spore) -> Spore {
        let mut result = vec![];
        let mut i = 0;
        let mut j = 0;

        while i < self.ranges.len() && j < other.ranges.len() {
            if let Some(intersection) = self.ranges[i].intersect(&other.ranges[j]) {
                result.push(intersection);
            }

            // Advance the one that ends first
            if self.ranges[i].stop <= other.ranges[j].stop {
                i += 1;
            } else {
                j += 1;
            }
        }

        Spore { ranges: result }
    }

    /// Compute union: values in either SPORE
    pub fn union(&self, other: &Spore) -> Spore {
        let mut all_ranges = self.ranges.clone();
        all_ranges.extend(other.ranges.iter().cloned());
        Spore::from_ranges(all_ranges)
    }

    /// Compute XOR (symmetric difference): values in exactly one SPORE
    ///
    /// Useful for discovering what each side is missing:
    /// `my_have XOR their_have` = things only one of us has
    pub fn xor(&self, other: &Spore) -> Spore {
        // XOR = (A ∪ B) \ (A ∩ B) = (A \ B) ∪ (B \ A)
        let a_minus_b = self.subtract(other);
        let b_minus_a = other.subtract(self);
        a_minus_b.union(&b_minus_a)
    }

    /// Compute set difference: values in self but not in other
    pub fn subtract(&self, other: &Spore) -> Spore {
        let mut result = vec![];

        for range in &self.ranges {
            let mut current_start = range.start;

            for other_range in &other.ranges {
                // Skip other ranges that end before our current position
                if other_range.stop <= current_start {
                    continue;
                }
                // Stop if other ranges start after our range ends
                if other_range.start >= range.stop {
                    break;
                }

                // If there's a gap before this other_range, add it
                if current_start < other_range.start {
                    let gap_end = min(other_range.start, range.stop);
                    if current_start < gap_end {
                        result.push(Range256::new(current_start, gap_end));
                    }
                }

                // Advance past this other_range
                current_start = max(current_start, other_range.stop);
            }

            // Add remaining portion after all other_ranges
            if current_start < range.stop {
                result.push(Range256::new(current_start, range.stop));
            }
        }

        Spore { ranges: result }
    }

    /// Compute complement: everything NOT in this SPORE
    ///
    /// The complement of HaveList gives the potential WantList.
    pub fn complement(&self) -> Spore {
        if self.ranges.is_empty() {
            return Spore::full();
        }

        let mut result = vec![];
        let mut prev_end = U256::ZERO;

        for range in &self.ranges {
            if prev_end < range.start {
                result.push(Range256::new(prev_end, range.start));
            }
            prev_end = range.stop;
        }

        // Add final range to MAX if needed
        if prev_end < U256::MAX {
            result.push(Range256::new(prev_end, U256::MAX));
        }

        Spore { ranges: result }
    }
}

/// Sync state between two nodes using SPORE.
///
/// Each node maintains HaveList (what they possess) and WantList (what they desire).
#[derive(Debug, Clone)]
pub struct SyncState {
    /// My HaveList: ranges of block IDs I possess
    pub my_have: Spore,
    /// My WantList: ranges of block IDs I want
    pub my_want: Spore,
    /// Their HaveList (received via flood)
    pub their_have: Spore,
    /// Their WantList (received via flood)
    pub their_want: Spore,
}

impl SyncState {
    /// Create new sync state
    pub fn new() -> Self {
        SyncState {
            my_have: Spore::empty(),
            my_want: Spore::full(), // Want everything by default
            their_have: Spore::empty(),
            their_want: Spore::empty(),
        }
    }

    /// Compute what I should send them: my_have ∩ their_want
    pub fn to_send(&self) -> Spore {
        self.my_have.intersect(&self.their_want)
    }

    /// Compute what they should send me: their_have ∩ my_want
    pub fn to_receive(&self) -> Spore {
        self.their_have.intersect(&self.my_want)
    }

    /// Check if sync is complete (both want lists empty or satisfied)
    pub fn is_complete(&self) -> bool {
        self.to_send().is_empty() && self.to_receive().is_empty()
    }
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire format for SPORE messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SporeMessage {
    /// Node identifier (256-bit)
    pub node_id: U256,
    /// HaveList: what this node possesses
    pub have_list: Spore,
    /// WantList: what this node wants
    pub want_list: Spore,
    /// Ed25519 signature (64 bytes)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SporeMessage {
    /// Create an unsigned message (for testing)
    pub fn unsigned(node_id: U256, have_list: Spore, want_list: Spore) -> Self {
        SporeMessage {
            node_id,
            have_list,
            want_list,
            signature: vec![],
        }
    }

    /// Total encoding size in bytes
    pub fn encoding_size(&self) -> usize {
        // node_id (32) + have_count (2) + want_count (2) + ranges + signature (64)
        32 + 4 + self.have_list.encoding_size() + self.want_list.encoding_size() + 64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_ordering() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert!(a < b);
        assert!(b > a);
        assert!(a == a);
    }

    #[test]
    fn test_u256_arithmetic() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(50);

        let sum = a.checked_add(&b).unwrap();
        assert_eq!(sum, U256::from_u64(150));

        let diff = a.checked_sub(&b).unwrap();
        assert_eq!(diff, U256::from_u64(50));

        // Underflow check
        assert!(b.checked_sub(&a).is_none());
    }

    #[test]
    fn test_range_contains() {
        let r = Range256::new(U256::from_u64(10), U256::from_u64(20));
        assert!(r.contains(&U256::from_u64(10)));
        assert!(r.contains(&U256::from_u64(15)));
        assert!(!r.contains(&U256::from_u64(20))); // Exclusive
        assert!(!r.contains(&U256::from_u64(5)));
    }

    #[test]
    fn test_range_intersect() {
        let a = Range256::new(U256::from_u64(0), U256::from_u64(10));
        let b = Range256::new(U256::from_u64(5), U256::from_u64(15));

        let intersection = a.intersect(&b).unwrap();
        assert_eq!(intersection.start, U256::from_u64(5));
        assert_eq!(intersection.stop, U256::from_u64(10));
    }

    #[test]
    fn test_empty_spore() {
        let s = Spore::empty();
        assert!(s.is_empty());
        assert_eq!(s.range_count(), 0);
        assert_eq!(s.encoding_size(), 0);
        assert!(s.excludes(&U256::from_u64(42)));
    }

    #[test]
    fn test_full_spore() {
        let s = Spore::full();
        assert!(!s.is_empty());
        assert_eq!(s.range_count(), 1);
        assert_eq!(s.encoding_size(), 64);
        assert!(s.covers(&U256::from_u64(0)));
        assert!(s.covers(&U256::from_u64(u64::MAX)));
    }

    #[test]
    fn test_spore_intersect() {
        let a = Spore::from_range(Range256::new(U256::from_u64(0), U256::from_u64(100)));
        let b = Spore::from_range(Range256::new(U256::from_u64(50), U256::from_u64(150)));

        let intersection = a.intersect(&b);
        assert_eq!(intersection.range_count(), 1);
        assert!(intersection.covers(&U256::from_u64(75)));
        assert!(!intersection.covers(&U256::from_u64(25)));
        assert!(!intersection.covers(&U256::from_u64(125)));
    }

    #[test]
    fn test_spore_union() {
        let a = Spore::from_range(Range256::new(U256::from_u64(0), U256::from_u64(50)));
        let b = Spore::from_range(Range256::new(U256::from_u64(50), U256::from_u64(100)));

        let union = a.union(&b);
        assert_eq!(union.range_count(), 1); // Should merge
        assert!(union.covers(&U256::from_u64(0)));
        assert!(union.covers(&U256::from_u64(75)));
    }

    #[test]
    fn test_spore_complement() {
        let s = Spore::from_range(Range256::new(U256::from_u64(10), U256::from_u64(20)));
        let complement = s.complement();

        assert!(complement.covers(&U256::from_u64(5)));
        assert!(!complement.covers(&U256::from_u64(15)));
        assert!(complement.covers(&U256::from_u64(25)));
    }

    #[test]
    fn test_symmetry_empty_and_full() {
        // Both empty and full have O(1) representation
        let empty = Spore::empty();
        let full = Spore::full();

        // Empty: 0 bytes (0 ranges)
        assert_eq!(empty.encoding_size(), 0);

        // Full: 64 bytes (1 range covering everything)
        assert_eq!(full.encoding_size(), 64);

        // Both are extremely compact!
    }

    #[test]
    fn test_sync_computation() {
        // Node A has blocks in range [0, 100)
        // Node B wants blocks in range [50, 150)
        let mut state = SyncState::new();
        state.my_have = Spore::from_range(Range256::new(U256::from_u64(0), U256::from_u64(100)));
        state.their_want =
            Spore::from_range(Range256::new(U256::from_u64(50), U256::from_u64(150)));

        // A should send B blocks in [50, 100)
        let to_send = state.to_send();
        assert!(to_send.covers(&U256::from_u64(75)));
        assert!(!to_send.covers(&U256::from_u64(25)));
        assert!(!to_send.covers(&U256::from_u64(125)));
    }

    #[test]
    fn test_implicit_exclusion() {
        // HaveList: [10, 20)
        // WantList: [30, 40)
        // Gaps: [0, 10), [20, 30), [40, ∞) - all implicitly excluded

        let have = Spore::from_range(Range256::new(U256::from_u64(10), U256::from_u64(20)));
        let want = Spore::from_range(Range256::new(U256::from_u64(30), U256::from_u64(40)));

        // Value 5 is in a gap - excluded
        assert!(have.excludes(&U256::from_u64(5)));
        assert!(want.excludes(&U256::from_u64(5)));

        // Value 25 is in a gap - excluded
        assert!(have.excludes(&U256::from_u64(25)));
        assert!(want.excludes(&U256::from_u64(25)));
    }

    #[test]
    fn test_range_merge() {
        // Multiple ranges that can be merged
        let ranges = vec![
            Range256::new(U256::from_u64(0), U256::from_u64(10)),
            Range256::new(U256::from_u64(10), U256::from_u64(20)), // Adjacent
            Range256::new(U256::from_u64(30), U256::from_u64(40)),
        ];

        let spore = Spore::from_ranges(ranges);
        // First two should merge, third is separate
        assert_eq!(spore.range_count(), 2);
    }
}
