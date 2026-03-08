//! SPORE sync utilities.
//!
//! SPORE (Set of Priority-Ordered Range Expressions) provides efficient
//! set reconciliation with O(k) complexity where k = differing items.
//!
//! Key properties:
//! - XOR cancellation: sync_cost(A,B) = O(|A ⊕ B|) → 0 at convergence
//! - No polling: continuous flooding, zero traffic at steady state
//! - Bilateral: all data eventually converges without coordination

use citadel_spore::{Range256, Spore, U256};

/// Convert a release ID to U256 for SPORE range operations
/// Uses BLAKE3 hash to map string IDs into 256-bit hash space
pub fn release_id_to_u256(id: &str) -> U256 {
    let hash = blake3::hash(id.as_bytes());
    U256::from_be_bytes(hash.as_bytes())
}

/// Build a Spore HaveList from a list of release IDs
/// Each release ID becomes a point range [hash, hash+1)
/// Ranges automatically merge when adjacent (rare for random UUIDs but happens)
pub fn build_spore_havelist(release_ids: &[String]) -> Spore {
    if release_ids.is_empty() {
        return Spore::empty();
    }

    let ranges: Vec<Range256> = release_ids
        .iter()
        .filter_map(|id| {
            let start = release_id_to_u256(id);
            // Point range: [hash, hash+1)
            start
                .checked_add(&U256::from_u64(1))
                .map(|stop| Range256::new(start, stop))
        })
        .collect();

    Spore::from_ranges(ranges)
}

/// Build WantList from HaveList
/// WantList = complement of HaveList = everything I DON'T have
/// A new node wants everything: Spore::full()
/// A synced node wants: HaveList.complement()
pub fn build_spore_wantlist(have_list: &Spore) -> Spore {
    have_list.complement()
}
