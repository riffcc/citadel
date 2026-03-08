//! Peer discovery and knowledge using SPORE sync.
//!
//! # The Two-Hop Knowledge Theorem
//!
//! Each node only needs to track nodes within 2 hops (~400 nodes).
//! Yet through SPORE sync, ALL nodes achieve COMPLETE KNOWLEDGE.
//!
//! ## How it works
//!
//! 1. **SPIRAL Layer**: Each node has exactly 20 neighbors
//! 2. **Routing Layer**: 2-hop knowledge suffices for forwarding
//! 3. **Knowledge Layer**: SPORE syncs PeerInfo like any other data
//!
//! ## The Beautiful Equation
//!
//! ```text
//! No node knows everything initially
//! Every node wants everything (WantList = [(0, 2^256)])
//! SPORE syncs what exists
//! Convergence theorem applies
//! ∴ Every node knows everything eventually
//! ```
//!
//! The key insight: PeerInfo is just data in hash space.
//! SPORE's convergence theorem applies automatically.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use citadel_topology::HexCoord;
use serde::{Deserialize, Serialize};

use crate::DhtKey;

/// Custom serde for Option<[u8; 64]> signatures.
mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes[..]),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) if vec.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&vec);
                Ok(Some(arr))
            }
            Some(_) => Ok(None), // Wrong length, treat as None
            None => Ok(None),
        }
    }
}

/// Unique peer identifier (256-bit hash of public key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Create from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hash a public key to create a PeerId.
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let hash = blake3::hash(pubkey);
        Self(*hash.as_bytes())
    }

    /// Get as DHT key (for SPORE sync).
    pub fn to_dht_key(&self) -> DhtKey {
        DhtKey(self.0)
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// XOR distance (for hash-space routing).
    pub fn xor_distance(&self, other: &PeerId) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, res) in result.iter_mut().enumerate() {
            *res = self.0[i] ^ other.0[i];
        }
        result
    }

    /// Leading zeros in XOR distance (for bucket assignment).
    pub fn xor_leading_zeros(&self, other: &PeerId) -> u32 {
        let dist = self.xor_distance(other);
        let mut zeros = 0u32;
        for byte in dist {
            if byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}...", &self.to_hex()[..8])
    }
}

/// Information about a peer in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's unique identifier.
    pub id: PeerId,

    /// SPIRAL slot coordinates (q, r, layer).
    pub slot: (i64, i64, i64),

    /// Network addresses (can have multiple).
    pub addresses: Vec<SocketAddr>,

    /// Capabilities this peer supports.
    pub capabilities: HashSet<String>,

    /// Timestamp when this info was last updated (unix millis).
    pub timestamp: u64,

    /// Signature over the above fields (for authenticity).
    #[serde(with = "signature_bytes")]
    pub signature: Option<[u8; 64]>,
}

impl PeerInfo {
    /// Create new peer info.
    pub fn new(id: PeerId, slot: (i64, i64, i64), addresses: Vec<SocketAddr>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            id,
            slot,
            addresses,
            capabilities: HashSet::new(),
            timestamp,
            signature: None,
        }
    }

    /// Get the HexCoord for this peer's slot.
    pub fn coord(&self) -> HexCoord {
        HexCoord::new(self.slot.0, self.slot.1, self.slot.2)
    }

    /// Check if this info is newer than another.
    pub fn is_newer_than(&self, other: &PeerInfo) -> bool {
        self.timestamp > other.timestamp
    }

    /// Merge with another PeerInfo, keeping the newer one.
    pub fn merge(&mut self, other: PeerInfo) -> bool {
        if other.is_newer_than(self) && other.id == self.id {
            *self = other;
            true
        } else {
            false
        }
    }

    /// Serialize to bytes for network transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use bincode for compact serialization
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// The 20 neighbor types in SPIRAL topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeighborType {
    /// 6 planar neighbors (same layer).
    Planar(u8), // 0-5
    /// 2 vertical neighbors (directly above/below).
    Vertical(bool), // true = above, false = below
    /// 12 extended neighbors (6 above + 6 below diagonally).
    Extended(bool, u8), // (above?, direction 0-5)
}

/// The three knowledge modes for routing.
///
/// These are **distinct operating modes**, not a hierarchy or fallback:
/// - Each mode is a complete, self-sufficient way to operate
/// - The network can choose ONE mode based on requirements
/// - Nodes in different modes cannot interoperate directly
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KnowledgeMode {
    /// Mix Mode: NOBODY knows more than necessary.
    ///
    /// Pure local operation:
    /// - Each node knows only their 20 direct neighbors
    /// - Greedy routing: forward to closest neighbor
    /// - SPIRAL geometry guarantees progress toward any target
    /// - Storage: O(k) = 20 peers exactly
    ///
    /// Use when: Minimal state is paramount, privacy is critical
    #[default]
    Mix,

    /// Smart Mode: Know only what you NEED.
    ///
    /// Local + on-demand operation:
    /// - Each node knows their 2-hop neighborhood (~400 peers)
    /// - Can route directly within 2-hop radius
    /// - Beyond 2-hop: greedy forward + on-demand query
    /// - Storage: O(k²) = 400 peers
    ///
    /// Use when: Balance of efficiency and minimal state
    Smart,

    /// Full Mode: EVERYONE wants to know everything.
    ///
    /// Complete knowledge operation:
    /// - SPORE sync actively seeks complete mesh knowledge
    /// - WantList = [(0, 2^256)] - we want ALL peer info
    /// - Convergence theorem: all nodes eventually know all peers
    /// - Storage: O(n) eventually
    ///
    /// Use when: Maximum routing efficiency, global mesh awareness
    Full,
}

impl NeighborType {
    /// Get all 20 neighbor types.
    pub fn all() -> [NeighborType; 20] {
        [
            // 6 planar
            NeighborType::Planar(0),
            NeighborType::Planar(1),
            NeighborType::Planar(2),
            NeighborType::Planar(3),
            NeighborType::Planar(4),
            NeighborType::Planar(5),
            // 2 vertical
            NeighborType::Vertical(true),
            NeighborType::Vertical(false),
            // 12 extended (6 above + 6 below)
            NeighborType::Extended(true, 0),
            NeighborType::Extended(true, 1),
            NeighborType::Extended(true, 2),
            NeighborType::Extended(true, 3),
            NeighborType::Extended(true, 4),
            NeighborType::Extended(true, 5),
            NeighborType::Extended(false, 0),
            NeighborType::Extended(false, 1),
            NeighborType::Extended(false, 2),
            NeighborType::Extended(false, 3),
            NeighborType::Extended(false, 4),
            NeighborType::Extended(false, 5),
        ]
    }
}

/// Two-hop peer knowledge.
///
/// This is the core data structure that enables global knowledge from local sync.
/// Each node maintains:
/// - Direct neighbors (20 nodes, 1-hop)
/// - Neighbors of neighbors (~400 nodes, 2-hop)
///
/// But through SPORE sync, ALL peer info eventually propagates.
#[derive(Debug, Default)]
pub struct PeerKnowledge {
    /// Our own peer ID.
    local_id: Option<PeerId>,

    /// All known peers (indexed by PeerId).
    peers: HashMap<PeerId, PeerInfo>,

    /// Direct neighbors (1-hop).
    neighbors: HashSet<PeerId>,

    /// Two-hop neighbors (neighbors of neighbors).
    two_hop: HashSet<PeerId>,

    /// When each peer was last seen alive.
    last_seen: HashMap<PeerId, Instant>,
}

impl PeerKnowledge {
    /// Create new peer knowledge tracker.
    pub fn new(local_id: PeerId) -> Self {
        Self {
            local_id: Some(local_id),
            peers: HashMap::new(),
            neighbors: HashSet::new(),
            two_hop: HashSet::new(),
            last_seen: HashMap::new(),
        }
    }

    /// Get our local peer ID.
    pub fn local_id(&self) -> Option<PeerId> {
        self.local_id
    }

    /// Add or update a peer.
    /// Returns true if this is new or updated info.
    pub fn update_peer(&mut self, info: PeerInfo) -> bool {
        let id = info.id;
        self.last_seen.insert(id, Instant::now());

        match self.peers.get_mut(&id) {
            Some(existing) => existing.merge(info),
            None => {
                self.peers.insert(id, info);
                true
            }
        }
    }

    /// Mark a peer as a direct neighbor.
    pub fn add_neighbor(&mut self, id: PeerId) {
        self.neighbors.insert(id);
    }

    /// Remove a neighbor.
    pub fn remove_neighbor(&mut self, id: &PeerId) {
        self.neighbors.remove(id);
    }

    /// Mark a peer as 2-hop reachable.
    pub fn add_two_hop(&mut self, id: PeerId) {
        if !self.neighbors.contains(&id) {
            self.two_hop.insert(id);
        }
    }

    /// Get info for a peer.
    pub fn get_peer(&self, id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }

    /// Get all direct neighbors.
    pub fn neighbors(&self) -> impl Iterator<Item = &PeerId> {
        self.neighbors.iter()
    }

    /// Get all two-hop reachable peers.
    pub fn two_hop_reachable(&self) -> impl Iterator<Item = &PeerId> {
        self.neighbors.iter().chain(self.two_hop.iter())
    }

    /// Get all known peers.
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Count of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Count of direct neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }

    /// Check if we have the expected 20 neighbors.
    pub fn has_full_neighbors(&self) -> bool {
        self.neighbors.len() >= 20
    }

    /// Find the neighbor closest to a target in hash space.
    pub fn closest_neighbor_to(&self, target: &PeerId) -> Option<&PeerId> {
        self.neighbors.iter().min_by_key(|n| n.xor_distance(target))
    }

    /// Find k closest peers to a target (for DHT queries).
    pub fn k_closest(&self, target: &PeerId, k: usize) -> Vec<&PeerId> {
        let mut peers: Vec<_> = self.peers.keys().collect();
        peers.sort_by_key(|p| p.xor_distance(target));
        peers.truncate(k);
        peers
    }

    /// Merge peer knowledge from a neighbor's perspective.
    /// This is how 2-hop knowledge expands.
    pub fn merge_from_neighbor(&mut self, neighbor_id: PeerId, their_peers: &[PeerInfo]) -> usize {
        let mut updated = 0;

        for info in their_peers {
            // Mark as 2-hop reachable (through this neighbor)
            if info.id != self.local_id.unwrap_or(PeerId([0; 32])) {
                self.add_two_hop(info.id);
            }

            if self.update_peer(info.clone()) {
                updated += 1;
            }
        }

        updated
    }

    /// Get peers that have been updated since a timestamp.
    pub fn peers_since(&self, timestamp: u64) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.timestamp > timestamp)
            .collect()
    }

    /// Expire peers not seen within a duration.
    pub fn expire_stale(&mut self, max_age: Duration) -> Vec<PeerId> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .last_seen
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) > max_age)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            self.peers.remove(id);
            self.neighbors.remove(id);
            self.two_hop.remove(id);
            self.last_seen.remove(id);
        }

        expired
    }

    /// Get peers suitable for SPORE sync (all peers as HaveList ranges).
    ///
    /// In the SPORE model:
    /// - Each PeerId hashes to a position in [0, 2^256)
    /// - Our HaveList contains ranges for peers we know
    /// - WantList = [(0, 2^256)] (we want to know everyone)
    /// - XOR cancellation: matching knowledge cancels
    /// - Convergence: all nodes eventually know all peers
    pub fn to_spore_have_list(&self) -> Vec<([u8; 32], [u8; 32])> {
        // For now, represent each peer as a point range [id, id+1)
        // In production, adjacent IDs would be merged into ranges
        self.peers
            .keys()
            .map(|id| {
                let mut end = id.0;
                // Increment by 1 (with overflow handling)
                for i in (0..32).rev() {
                    if end[i] == 255 {
                        end[i] = 0;
                    } else {
                        end[i] += 1;
                        break;
                    }
                }
                (id.0, end)
            })
            .collect()
    }

    /// Get statistics about peer knowledge.
    pub fn stats(&self) -> PeerKnowledgeStats {
        PeerKnowledgeStats {
            total_peers: self.peers.len(),
            direct_neighbors: self.neighbors.len(),
            two_hop_reachable: self.two_hop.len(),
            has_full_neighbors: self.has_full_neighbors(),
        }
    }
}

/// Statistics about peer knowledge.
#[derive(Debug, Clone)]
pub struct PeerKnowledgeStats {
    pub total_peers: usize,
    pub direct_neighbors: usize,
    pub two_hop_reachable: usize,
    pub has_full_neighbors: bool,
}

impl std::fmt::Display for PeerKnowledgeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PeerKnowledge: {} total, {} neighbors ({}), {} 2-hop",
            self.total_peers,
            self.direct_neighbors,
            if self.has_full_neighbors {
                "full"
            } else {
                "partial"
            },
            self.two_hop_reachable
        )
    }
}

/// SPORE-based peer list for efficient sync.
///
/// This represents our peer knowledge as SPORE ranges, enabling:
/// - O(boundaries) sync instead of O(peers)
/// - XOR cancellation for identical knowledge
/// - Convergence to complete knowledge
#[derive(Debug, Clone, Default)]
pub struct PeerSpore {
    /// Ranges of PeerIds we have info for.
    /// Sorted and non-overlapping.
    have_ranges: Vec<([u8; 32], [u8; 32])>,

    /// Ranges we want (default: entire space = want everyone).
    want_ranges: Vec<([u8; 32], [u8; 32])>,
}

impl PeerSpore {
    /// Create a new PeerSpore wanting everyone.
    pub fn new() -> Self {
        Self {
            have_ranges: Vec::new(),
            want_ranges: vec![([0u8; 32], [0xff; 32])], // Want entire space
        }
    }

    /// Create from PeerKnowledge.
    pub fn from_knowledge(knowledge: &PeerKnowledge) -> Self {
        let have_ranges = knowledge.to_spore_have_list();
        // Merge adjacent ranges for efficiency
        let have_ranges = Self::merge_adjacent_ranges(have_ranges);

        Self {
            have_ranges,
            want_ranges: vec![([0u8; 32], [0xff; 32])],
        }
    }

    /// Merge adjacent ranges for more compact representation.
    fn merge_adjacent_ranges(mut ranges: Vec<([u8; 32], [u8; 32])>) -> Vec<([u8; 32], [u8; 32])> {
        if ranges.len() <= 1 {
            return ranges;
        }

        // Sort by start
        ranges.sort_by(|a, b| a.0.cmp(&b.0));

        let mut merged = Vec::new();
        let mut current = ranges[0];

        for next in ranges.into_iter().skip(1) {
            if current.1 >= next.0 {
                // Overlapping or adjacent - extend current
                if next.1 > current.1 {
                    current.1 = next.1;
                }
            } else {
                // Gap - push current and start new
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);

        merged
    }

    /// Check if we have info for a PeerId.
    pub fn has(&self, id: &PeerId) -> bool {
        for (start, end) in &self.have_ranges {
            if &id.0 >= start && &id.0 < end {
                return true;
            }
        }
        false
    }

    /// Compute XOR with another PeerSpore (the differences).
    /// Returns ranges that are in exactly one of the two SPOREs.
    pub fn xor(&self, other: &PeerSpore) -> PeerSpore {
        // Simplified XOR - in production this would be a proper interval XOR
        let mut diff = Vec::new();

        // Add ranges we have that they don't
        for range in &self.have_ranges {
            if !other.has_range(range) {
                diff.push(*range);
            }
        }

        // Add ranges they have that we don't
        for range in &other.have_ranges {
            if !self.has_range(range) {
                diff.push(*range);
            }
        }

        PeerSpore {
            have_ranges: diff,
            want_ranges: vec![([0u8; 32], [0xff; 32])],
        }
    }

    /// Check if we have an exact range.
    fn has_range(&self, range: &([u8; 32], [u8; 32])) -> bool {
        self.have_ranges.iter().any(|r| r == range)
    }

    /// Number of ranges (boundaries / 2).
    pub fn range_count(&self) -> usize {
        self.have_ranges.len()
    }

    /// Encoding size in bytes.
    pub fn encoding_size(&self) -> usize {
        // 64 bytes per range (32 + 32)
        64 * self.have_ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
    }

    #[test]
    fn peer_id_xor_distance() {
        let a = PeerId([0u8; 32]);
        let b = PeerId([0xff; 32]);

        let dist = a.xor_distance(&b);
        assert_eq!(dist, [0xff; 32]);

        let self_dist = a.xor_distance(&a);
        assert_eq!(self_dist, [0u8; 32]);
    }

    #[test]
    fn peer_id_leading_zeros() {
        let a = PeerId([0u8; 32]);
        let b = PeerId([0u8; 32]);
        assert_eq!(a.xor_leading_zeros(&b), 256);

        let c = PeerId([0x80; 32].map(|x| if x == 0x80 { 0 } else { x }));
        let mut c_bytes = [0u8; 32];
        c_bytes[0] = 0x80;
        let c = PeerId(c_bytes);
        assert_eq!(a.xor_leading_zeros(&c), 0);
    }

    #[test]
    fn peer_info_merge() {
        let id = PeerId([1u8; 32]);

        let mut old = PeerInfo {
            id,
            slot: (0, 0, 0),
            addresses: vec![test_addr()],
            capabilities: HashSet::new(),
            timestamp: 100,
            signature: None,
        };

        let new = PeerInfo {
            id,
            slot: (1, 1, 1),
            addresses: vec![test_addr()],
            capabilities: HashSet::new(),
            timestamp: 200,
            signature: None,
        };

        assert!(old.merge(new));
        assert_eq!(old.slot, (1, 1, 1));
        assert_eq!(old.timestamp, 200);
    }

    #[test]
    fn peer_knowledge_neighbors() {
        let local = PeerId([0u8; 32]);
        let mut knowledge = PeerKnowledge::new(local);

        // Add 20 neighbors
        for i in 0..20 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i + 1;
            let id = PeerId(id_bytes);
            knowledge.add_neighbor(id);
        }

        assert!(knowledge.has_full_neighbors());
        assert_eq!(knowledge.neighbor_count(), 20);
    }

    #[test]
    fn peer_knowledge_two_hop_expansion() {
        let local = PeerId([0u8; 32]);
        let mut knowledge = PeerKnowledge::new(local);

        let neighbor = PeerId([1u8; 32]);
        knowledge.add_neighbor(neighbor);

        // Neighbor shares their peers
        let mut their_peers = Vec::new();
        for i in 2..22 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i;
            let id = PeerId(id_bytes);
            their_peers.push(PeerInfo::new(id, (i as i64, 0, 0), vec![test_addr()]));
        }

        let updated = knowledge.merge_from_neighbor(neighbor, &their_peers);
        assert_eq!(updated, 20);
        assert_eq!(knowledge.peer_count(), 20);
    }

    #[test]
    fn peer_spore_xor_identical_empty() {
        let knowledge1 = PeerKnowledge::new(PeerId([0u8; 32]));
        let knowledge2 = PeerKnowledge::new(PeerId([1u8; 32]));

        let spore1 = PeerSpore::from_knowledge(&knowledge1);
        let spore2 = PeerSpore::from_knowledge(&knowledge2);

        // Identical empty knowledge → empty XOR
        let xor = spore1.xor(&spore2);
        assert_eq!(xor.range_count(), 0);
    }

    #[test]
    fn peer_spore_xor_differences() {
        let mut knowledge1 = PeerKnowledge::new(PeerId([0u8; 32]));
        let mut knowledge2 = PeerKnowledge::new(PeerId([1u8; 32]));

        // knowledge1 has peer A
        let peer_a = PeerId([10u8; 32]);
        knowledge1.update_peer(PeerInfo::new(peer_a, (0, 0, 0), vec![test_addr()]));

        // knowledge2 has peer B
        let peer_b = PeerId([20u8; 32]);
        knowledge2.update_peer(PeerInfo::new(peer_b, (1, 1, 1), vec![test_addr()]));

        let spore1 = PeerSpore::from_knowledge(&knowledge1);
        let spore2 = PeerSpore::from_knowledge(&knowledge2);

        // XOR should show 2 differences
        let xor = spore1.xor(&spore2);
        assert_eq!(xor.range_count(), 2);
    }
}
