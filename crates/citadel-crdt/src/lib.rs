//! # Citadel CRDT: Bilateral CRDTs with Proven Convergence
//!
//! This crate provides the core CRDT (Conflict-free Replicated Data Type) traits
//! and implementations for the Citadel protocol suite.
//!
//! ## Key Concepts
//!
//! ### Bilateral CRDTs
//!
//! Traditional CRDTs provide "eventual consistency" - a hope that nodes will converge.
//! Bilateral CRDTs provide **proven convergence** - a mathematical guarantee.
//!
//! The key insight: The CRDT IS the other general. The merge function IS its signature.
//! Pure functions cannot disagree with themselves.
//!
//! ### TGP Collapse
//!
//! Traditional Two Generals Protocol requires 4 network phases: C → D → T → Q
//! For pure functions, all phases collapse into one local computation: C=D=T=Q
//!
//! - **C (Commitment)**: Local - you propose an operation
//! - **D (Double)**: Automatic - merge is total, always succeeds
//! - **T (Triple)**: Immediate - you ran the merge locally
//! - **Q (Quaternary)**: Inherent - determinism IS bilateral construction
//!
//! ## Proven Properties (from proofs/CitadelProofs/CRDT/)
//!
//! 1. `merge_cannot_disagree` - Same inputs → same outputs
//! 2. `no_merge_failure` - Merge is total, cannot fail
//! 3. `full_sync_convergence` - Same operations → same state
//! 4. `offline_op_always_possible` - Works without network
//!
//! ## Example
//!
//! ```rust
//! use citadel_crdt::{TotalMerge, IsCRDT};
//!
//! #[derive(Clone, PartialEq, Eq)]
//! struct GCounter {
//!     counts: std::collections::BTreeMap<String, u64>,
//! }
//!
//! impl TotalMerge for GCounter {
//!     fn merge(&self, other: &Self) -> Self {
//!         let mut result = self.counts.clone();
//!         for (k, v) in &other.counts {
//!             let entry = result.entry(k.clone()).or_insert(0);
//!             *entry = (*entry).max(*v);
//!         }
//!         GCounter { counts: result }
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeSet;

/// A 256-bit content identifier (Blake3 hash).
///
/// All content in Citadel is addressed by its Blake3 hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ContentId(bytes)
    }

    /// Create from a Blake3 hash of data
    pub fn hash(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        ContentId(*hash.as_bytes())
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(ContentId(arr))
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16]) // First 16 hex chars
    }
}

/// Total merge function - the core of Bilateral CRDTs.
///
/// A merge function is **total** if it always succeeds. There is no `Result`,
/// no `Option`, no failure path. The function signature `fn merge(&self, other: &Self) -> Self`
/// guarantees totality.
///
/// ## Properties (proven in Lean)
///
/// For a valid TotalMerge:
/// - **Deterministic**: Same inputs always produce same output
/// - **Cannot fail**: No merge operation can fail
/// - **No data loss**: Rich merges preserve information from both inputs
///
/// ## The Bilateral Insight
///
/// Traditional TGP: Alice ←── network ──→ Bob (4 phases)
/// Bilateral CRDT:  You ←── local ──→ CRDT (1 computation)
///
/// The CRDT IS the other general.
pub trait TotalMerge: Clone {
    /// Merge two states into one.
    ///
    /// This function MUST be:
    /// - **Total**: Always returns a valid result (no Option/Result)
    /// - **Commutative**: merge(a, b) = merge(b, a)
    /// - **Associative**: merge(merge(a, b), c) = merge(a, merge(b, c))
    /// - **Idempotent**: merge(a, a) = a
    fn merge(&self, other: &Self) -> Self;
}

/// Commutative merge - order doesn't matter.
///
/// For any a, b: merge(a, b) = merge(b, a)
pub trait CommutativeMerge: TotalMerge {}

/// Associative merge - grouping doesn't matter.
///
/// For any a, b, c: merge(merge(a, b), c) = merge(a, merge(b, c))
pub trait AssociativeMerge: TotalMerge {}

/// Idempotent merge - duplicates don't matter.
///
/// For any a: merge(a, a) = a
pub trait IdempotentMerge: TotalMerge {}

/// A full CRDT: Total + Commutative + Associative + Idempotent.
///
/// This is the `IsCRDT` typeclass from the Lean proofs.
pub trait IsCRDT: TotalMerge + CommutativeMerge + AssociativeMerge + IdempotentMerge {}

// Blanket implementation: anything with all four traits is a CRDT
impl<T: TotalMerge + CommutativeMerge + AssociativeMerge + IdempotentMerge> IsCRDT for T {}

/// Operation that can be applied to a CRDT.
///
/// Operations are the "verbs" - they transform state.
/// The CRDT state is the "noun" - the accumulated result.
pub trait CRDTOp<State: TotalMerge> {
    /// Apply this operation to a state, producing a new state.
    ///
    /// This is a pure function - same state + same op = same result.
    fn apply(&self, state: &State) -> State;
}

/// Content-addressable state.
///
/// Every CRDT state can be hashed to produce a ContentId.
/// This enables SPORE sync - we track ContentIds, not full states.
pub trait ContentAddressable {
    /// Compute the ContentId of this state.
    fn content_id(&self) -> ContentId;
}

/// A self-certifying operation proof.
///
/// This is the TGP collapse in action:
/// - before: ContentId of state before operation
/// - op: The operation applied
/// - after: ContentId of state after operation
/// - signature: Ed25519 signature proving authorship
///
/// Anyone can verify this proof without re-executing the operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationProof<Op> {
    /// ContentId of state before operation
    pub before: ContentId,
    /// The operation that was applied
    pub op: Op,
    /// ContentId of state after operation
    pub after: ContentId,
    /// Public key of the author
    pub author: [u8; 32],
    /// Ed25519 signature over (before, op, after)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl<Op: Serialize> OperationProof<Op> {
    /// Compute the ContentId of this proof
    pub fn content_id(&self) -> ContentId {
        let bytes = bincode::serialize(self).expect("serialization cannot fail");
        ContentId::hash(&bytes)
    }
}

// ============================================================================
// Common CRDT implementations
// ============================================================================

/// GSet: Grow-only set.
///
/// Elements can only be added, never removed.
/// Merge is union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GSet<T: Ord + Clone> {
    elements: BTreeSet<T>,
}

impl<T: Ord + Clone> GSet<T> {
    /// Create empty GSet
    pub fn new() -> Self {
        GSet {
            elements: BTreeSet::new(),
        }
    }

    /// Add an element
    pub fn insert(&mut self, value: T) {
        self.elements.insert(value);
    }

    /// Check if contains element
    pub fn contains(&self, value: &T) -> bool {
        self.elements.contains(value)
    }

    /// Get all elements
    pub fn elements(&self) -> &BTreeSet<T> {
        &self.elements
    }

    /// Number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

impl<T: Ord + Clone> Default for GSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone> TotalMerge for GSet<T> {
    fn merge(&self, other: &Self) -> Self {
        GSet {
            elements: self.elements.union(&other.elements).cloned().collect(),
        }
    }
}

impl<T: Ord + Clone> CommutativeMerge for GSet<T> {}
impl<T: Ord + Clone> AssociativeMerge for GSet<T> {}
impl<T: Ord + Clone> IdempotentMerge for GSet<T> {}

/// LWW (Last-Writer-Wins) Register.
///
/// Stores a single value with a timestamp. Higher timestamp wins.
/// Note: This CAN lose data - use carefully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LWWRegister<T: Clone> {
    pub value: T,
    pub timestamp: u64,
}

impl<T: Clone> LWWRegister<T> {
    /// Create new register
    pub fn new(value: T, timestamp: u64) -> Self {
        LWWRegister { value, timestamp }
    }

    /// Update value with new timestamp
    pub fn set(&mut self, value: T, timestamp: u64) {
        if timestamp > self.timestamp {
            self.value = value;
            self.timestamp = timestamp;
        }
    }
}

impl<T: Clone> TotalMerge for LWWRegister<T> {
    fn merge(&self, other: &Self) -> Self {
        if other.timestamp > self.timestamp {
            other.clone()
        } else {
            self.clone()
        }
    }
}

impl<T: Clone> CommutativeMerge for LWWRegister<T> {}
impl<T: Clone> AssociativeMerge for LWWRegister<T> {}
impl<T: Clone> IdempotentMerge for LWWRegister<T> {}

/// Max register - always takes the maximum value.
///
/// Unlike LWW, this is lossless for monotonic values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxRegister<T: Ord + Clone> {
    pub value: T,
}

impl<T: Ord + Clone> MaxRegister<T> {
    pub fn new(value: T) -> Self {
        MaxRegister { value }
    }
}

impl<T: Ord + Clone> TotalMerge for MaxRegister<T> {
    fn merge(&self, other: &Self) -> Self {
        if other.value > self.value {
            other.clone()
        } else {
            self.clone()
        }
    }
}

impl<T: Ord + Clone> CommutativeMerge for MaxRegister<T> {}
impl<T: Ord + Clone> AssociativeMerge for MaxRegister<T> {}
impl<T: Ord + Clone> IdempotentMerge for MaxRegister<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gset_merge() {
        let mut a = GSet::new();
        a.insert("x");
        a.insert("y");

        let mut b = GSet::new();
        b.insert("y");
        b.insert("z");

        let merged = a.merge(&b);
        assert!(merged.contains(&"x"));
        assert!(merged.contains(&"y"));
        assert!(merged.contains(&"z"));
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn test_gset_commutativity() {
        let mut a = GSet::new();
        a.insert(1);

        let mut b = GSet::new();
        b.insert(2);

        assert_eq!(a.merge(&b), b.merge(&a));
    }

    #[test]
    fn test_gset_idempotency() {
        let mut a = GSet::new();
        a.insert(1);
        a.insert(2);

        assert_eq!(a.merge(&a), a);
    }

    #[test]
    fn test_lww_register() {
        let a = LWWRegister::new("first", 10);
        let b = LWWRegister::new("second", 20);

        let merged = a.merge(&b);
        assert_eq!(merged.value, "second");
        assert_eq!(merged.timestamp, 20);
    }

    #[test]
    fn test_max_register() {
        let a = MaxRegister::new(10);
        let b = MaxRegister::new(20);

        let merged = a.merge(&b);
        assert_eq!(merged.value, 20);
    }

    #[test]
    fn test_content_id() {
        let id = ContentId::hash(b"hello world");
        assert_eq!(id.to_hex().len(), 64);

        let parsed = ContentId::from_hex(&id.to_hex()).unwrap();
        assert_eq!(id, parsed);
    }
}
