//! Citadel Distributed Hash Table
//!
//! A DHT implementation built on the hexagonal mesh topology.
//! Uses Blake3 for key hashing and supports last-write-wins conflict resolution.
//!
//! # Design
//!
//! Keys are 32-byte Blake3 hashes. Each key maps deterministically to a
//! slot in the hexagonal mesh via modular hashing. Queries route through
//! the mesh using greedy geometric routing (O(log n) hops).
//!
//! # Conflict Resolution
//!
//! Uses timestamps for last-write-wins semantics. When merging state from
//! multiple peers, the entry with the highest timestamp wins.

mod entry;
pub mod peer;
mod routing;
mod state;

pub use entry::{DhtEntry, DhtKey, DhtValue};
pub use peer::{KnowledgeMode, NeighborType, PeerId, PeerInfo, PeerKnowledge, PeerSpore};
pub use routing::{key_to_slot, route_to_key};
pub use state::DhtState;

/// Hash a string key to a DHT key using Blake3.
pub fn hash_key(data: &[u8]) -> DhtKey {
    let hash = blake3::hash(data);
    DhtKey(*hash.as_bytes())
}

/// Hash a prefixed key (e.g., "release:{id}") to a DHT key.
pub fn hash_prefixed_key(prefix: &str, id: &str) -> DhtKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(id.as_bytes());
    DhtKey(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_key_deterministic() {
        let key1 = hash_key(b"hello");
        let key2 = hash_key(b"hello");
        assert_eq!(key1, key2);
    }

    #[test]
    fn hash_key_different_inputs() {
        let key1 = hash_key(b"hello");
        let key2 = hash_key(b"world");
        assert_ne!(key1, key2);
    }

    #[test]
    fn prefixed_key_format() {
        let key1 = hash_prefixed_key("release", "abc123");
        let key2 = hash_prefixed_key("release", "abc123");
        assert_eq!(key1, key2);

        let key3 = hash_prefixed_key("release", "different");
        assert_ne!(key1, key3);
    }
}
