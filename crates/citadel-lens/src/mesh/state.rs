//! Mesh state management.
//!
//! MeshState holds all node state for the mesh service:
//! - Identity (keys, PeerID)
//! - Peer tracking
//! - Slot management
//! - SPORE sync state
//! - VDF/CVDF coordinators
//! - Liveness tracking

use crate::accountability::AccountabilityTracker;
use crate::cvdf::CvdfCoordinator;
use crate::liveness::LivenessManager;
use crate::vdf_race::{AnchoredSlotClaim, VdfRace};
use citadel_protocols::SporeSyncManager;
use citadel_spore::Spore;
use citadel_topology::{ghost_target, Connection, Direction, HexCoord};
use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use super::peer::MeshPeer;
use super::peer_addr_store::PeerAddrStore;
use super::slot::{LatencyHistory, SlotClaim};

/// Traffic statistics for aggregate logging (instead of per-packet spam)
#[derive(Debug, Default)]
pub struct TrafficStats {
    /// UDP bytes sent
    pub bytes_sent: AtomicU64,
    /// UDP bytes received
    pub bytes_recv: AtomicU64,
    /// UDP packets sent
    pub packets_sent: AtomicU64,
    /// UDP packets received
    pub packets_recv: AtomicU64,
    /// TGP messages processed
    pub tgp_messages: AtomicU64,
    /// TGP completions (QuadProof achieved)
    pub tgp_completions: AtomicU64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_send(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_recv(&self, bytes: u64) {
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tgp_message(&self) {
        self.tgp_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tgp_completion(&self) {
        self.tgp_completions.fetch_add(1, Ordering::Relaxed);
    }

    /// Reset and return previous values for interval logging
    pub fn take_snapshot(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.bytes_sent.swap(0, Ordering::Relaxed),
            self.bytes_recv.swap(0, Ordering::Relaxed),
            self.packets_sent.swap(0, Ordering::Relaxed),
            self.packets_recv.swap(0, Ordering::Relaxed),
            self.tgp_messages.swap(0, Ordering::Relaxed),
            self.tgp_completions.swap(0, Ordering::Relaxed),
        )
    }

    /// Format bytes as human-readable (B/s, KiB/s, MiB/s)
    pub fn format_rate(bytes: u64, interval_secs: u64) -> String {
        let rate = bytes as f64 / interval_secs as f64;
        if rate >= 1024.0 * 1024.0 {
            format!("{:.1} MiB/s", rate / (1024.0 * 1024.0))
        } else if rate >= 1024.0 {
            format!("{:.1} KiB/s", rate / 1024.0)
        } else {
            format!("{:.0} B/s", rate)
        }
    }
}

/// Mesh service state
pub struct MeshState {
    /// Our node ID (PeerID)
    pub self_id: String,
    /// Our signing key for authentication
    pub signing_key: SigningKey,
    /// Our claimed slot in the mesh
    pub self_slot: Option<SlotClaim>,
    /// Known peers in the mesh (by PeerID)
    pub peers: HashMap<String, MeshPeer>,
    /// SPORE-indexed address metadata for peers.
    pub peer_addr_store: PeerAddrStore,
    /// Claimed slots (by SPIRAL index)
    pub claimed_slots: HashMap<u64, SlotClaim>,
    /// Coordinates with claimed slots (for neighbor lookup)
    pub slot_coords: HashSet<HexCoord>,
    /// SPORE sync manager for content replication (Full mesh strategy)
    pub spore_sync: Option<SporeSyncManager>,
    /// VDF race for bootstrap coordination and split-brain merge
    /// Uses collaborative VDF chain - longest chain = largest swarm
    pub vdf_race: Option<VdfRace>,
    /// VDF-anchored slot claims (slot -> best claim we've seen)
    /// These have VDF priority ordering for deterministic conflict resolution
    pub vdf_claims: HashMap<u64, AnchoredSlotClaim>,
    /// Proof of Latency manager for automatic mesh optimization
    /// Enables atomic slot swapping when it improves both parties' latency
    pub pol_manager: Option<crate::proof_of_latency::PoLManager>,
    /// Pending PoL ping nonces (nonce -> target node)
    pub pol_pending_pings: HashMap<u64, [u8; 32]>,
    /// CVDF coordinator for collaborative VDF consensus
    /// Weight-based chain comparison (heavier wins, not taller)
    pub cvdf: Option<CvdfCoordinator>,
    /// Latency history for each neighbor (from_node -> to_node -> history)
    /// Used for map visualization and swap optimization
    pub latency_history: HashMap<String, HashMap<String, LatencyHistory>>,
    /// Our observed public IP (learned from peers who connect to us)
    /// This is what other nodes see us as - used instead of hardcoded announce_addr
    pub observed_public_addr: Option<SocketAddr>,

    // =========================================================================
    // SPORE⁻¹: Deletion Sync (inverse of SPORE)
    // =========================================================================
    //
    // SPORE syncs content: HaveList XOR → everyone ADDS what anyone has
    // SPORE⁻¹ syncs deletions: DoNotWantList XOR → everyone REMOVES what anyone deleted
    //
    // Cost is O(|diff|) → 0 at convergence. Perfect erasure sync.
    //
    // GDPR Article 17 "Right to Erasure" Compliance:
    // -----------------------------------------------
    // - User requests deletion → content removed from all nodes via SPORE⁻¹
    // - Double-hash H(H(id)) prevents content enumeration while allowing sync
    // - erasure_confirmed tracks cryptographic proof of deletion per peer
    // - erasure_synced tracks which peers have confirmed (for audit trail)
    // - GC only after ALL peers confirm → provable mesh-wide erasure
    // - Re-upload allowed (GDPR requires deletion, not blocking future uploads)
    //
    // This provides a complete audit trail demonstrating good-faith compliance
    // with data protection regulations requiring deletion on request.
    /// SPORE⁻¹: DoNotWantList - deletions as ranges in 256-bit hash space (GDPR Art. 17)
    /// Same range-based representation as SPORE HaveList, but inverted semantics
    /// Recipients DELETE content matching these ranges instead of ADD
    /// XOR with peer's list gives diff; at convergence XOR = empty (zero cost)
    pub do_not_want: Spore,
    /// SPORE⁻¹: Confirmed erasures - ranges peers have confirmed deleting
    /// Provides audit trail for GDPR compliance: we can prove deletion occurred
    /// When our do_not_want XOR their erasure_confirmed = empty, they're synced
    pub erasure_confirmed: Spore,
    /// SPORE⁻¹: Peer erasure sync status (peer_id -> their erasure XOR ours == empty)
    /// Tracks which peers have confirmed deletion for compliance audit
    /// When all peers are erasure_synced, we have provable mesh-wide erasure
    pub erasure_synced: HashMap<String, bool>,

    // =========================================================================
    // BadBits: Permanent blocklist (NOT for normal deletes)
    // =========================================================================
    /// BadBits: PERMANENT blocklist of double-hashed CIDs H(H(cid))
    /// Unlike DoNotWantList (GC'd after erasure), BadBits are forever
    /// Used for: copyright violations (DMCA), abuse material, illegal content
    /// Checked on upload - matching CIDs are rejected before storage
    /// Can sync from external sources like https://badbits.dwebops.pub/
    pub bad_bits: HashSet<[u8; 32]>,
    /// Accountability tracker for neighbor monitoring and misbehaviour detection
    /// Tracks latency proofs, vouches, and failure witnesses
    pub accountability: Option<AccountabilityTracker>,
    /// Liveness manager for structure-aware vouch propagation
    /// Handles 2-hop vouches: Origin → Judged → Witness → STOP
    /// Event-driven: zero traffic at steady state
    pub liveness: Option<LivenessManager>,
}

impl MeshState {
    /// Count the currently fillable slot frontier for the live mesh view.
    ///
    /// This is the number of occupied slots plus the empty theoretical neighbor
    /// coordinates immediately adjacent to those occupied slots. It is the live
    /// "surface area" of the mesh that can currently be filled without inventing
    /// an arbitrary global capacity.
    pub fn available_slot_count(&self) -> usize {
        if self.claimed_slots.is_empty() {
            return 0;
        }

        let mut available = self.slot_coords.clone();
        for claim in self.claimed_slots.values() {
            for neighbor_coord in claim.neighbor_coords() {
                available.insert(neighbor_coord);
            }
        }
        available.len()
    }

    /// Fraction of the currently available slot frontier that is occupied.
    pub fn mesh_density(&self) -> f64 {
        let available = self.available_slot_count();
        if available == 0 {
            return 0.0;
        }

        (self.claimed_slots.len() as f64 / available as f64) * 100.0
    }

    /// Record a latency measurement between two nodes
    pub fn record_latency(&mut self, from_node: &str, to_node: &str, latency_ms: u64) {
        let from_map = self
            .latency_history
            .entry(from_node.to_string())
            .or_insert_with(HashMap::new);

        let history = from_map
            .entry(to_node.to_string())
            .or_insert_with(LatencyHistory::new);

        history.record(latency_ms);
    }

    /// Get latency history between two nodes
    pub fn get_latency_history(&self, from_node: &str, to_node: &str) -> Option<&LatencyHistory> {
        self.latency_history.get(from_node)?.get(to_node)
    }

    /// Find the next available SPIRAL slot
    pub fn next_available_slot(&self) -> u64 {
        let mut index = 0u64;
        while self.claimed_slots.contains_key(&index) {
            index += 1;
        }
        index
    }

    /// Check if a coordinate has a claimed slot
    pub fn is_slot_claimed(&self, coord: &HexCoord) -> bool {
        self.slot_coords.contains(coord)
    }

    /// Get neighbors of our slot that are present in the mesh
    pub fn present_neighbors(&self) -> Vec<&SlotClaim> {
        let Some(ref self_slot) = self.self_slot else {
            return Vec::new();
        };

        self_slot
            .neighbor_coords()
            .iter()
            .filter_map(|coord| {
                // Find claimed slot at this coordinate
                self.claimed_slots.values().find(|s| s.coord == *coord)
            })
            .collect()
    }

    /// Count how many of our 20 neighbors are present
    pub fn neighbor_count(&self) -> usize {
        self.present_neighbors().len()
    }

    /// Check if a peer is in our SPIRAL neighborhood (one of 20 possible neighbors)
    pub fn is_spiral_neighbor(&self, peer_id: &str) -> bool {
        let Some(ref self_slot) = self.self_slot else {
            return false;
        };

        // Check if this peer has claimed a slot that is adjacent to ours
        let neighbor_coords: std::collections::HashSet<_> =
            self_slot.neighbor_coords().into_iter().collect();

        self.claimed_slots
            .values()
            .any(|claim| claim.peer_id == peer_id && neighbor_coords.contains(&claim.coord))
    }

    /// Count connected SPIRAL neighbors (not entry peers)
    pub fn connected_neighbor_count(&self) -> usize {
        let Some(ref self_slot) = self.self_slot else {
            return 0;
        };

        let neighbor_coords: std::collections::HashSet<_> =
            self_slot.neighbor_coords().into_iter().collect();

        // Count peers whose slots are in our neighborhood
        self.peers
            .values()
            .filter(|peer| {
                if let Some(ref slot) = peer.slot {
                    neighbor_coords.contains(&slot.coord)
                } else {
                    false
                }
            })
            .count()
    }

    /// SPORE: Check if this node has all content from all peers (WantList = ∅)
    /// Returns true when we have everything that any peer has - our HaveList ⊇ ∪(all peer HaveLists)
    /// This is used by /api/v1/ready to indicate the node is caught up with the mesh
    ///
    /// Note: This is about US having everything, not about peers being synced with each other.
    /// One peer going offline or having extra content doesn't affect our readiness.
    pub fn is_content_ready(&self) -> bool {
        // If no peers, we're trivially ready (genesis node)
        if self.peers.is_empty() {
            return true;
        }

        // Ready when we have all content from ALL peers (our WantList for each is empty)
        self.peers.values().all(|peer| peer.content_synced)
    }

    /// SPORE: Get sync status breakdown for debugging
    pub fn sync_status(&self) -> (usize, usize) {
        let synced = self.peers.values().filter(|p| p.content_synced).count();
        let total = self.peers.len();
        (synced, total)
    }

    /// Get entry peers that should be disconnected (have enough SPIRAL neighbors)
    pub fn entry_peers_to_disconnect(&self) -> Vec<String> {
        // Need at least 3 SPIRAL neighbors before we can safely disconnect from entry peers
        const MIN_NEIGHBORS_FOR_DISCONNECT: usize = 3;

        if self.connected_neighbor_count() < MIN_NEIGHBORS_FOR_DISCONNECT {
            return Vec::new();
        }

        // Return entry peers that are NOT also SPIRAL neighbors
        self.peers
            .iter()
            .filter(|(id, peer)| peer.is_entry_peer && !self.is_spiral_neighbor(id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    // =========================================================================
    // Gap-and-Wrap: Toroidal mesh with ghost connections
    // =========================================================================

    /// Get our ghost connections using Gap-and-Wrap.
    ///
    /// Returns all actual connections for our slot, including ghost connections
    /// that span gaps in the mesh. In a dense mesh, these match theoretical neighbors.
    /// In a sparse mesh, ghost connections may span multiple slots.
    pub fn ghost_connections(&self) -> Vec<Connection> {
        let Some(ref self_slot) = self.self_slot else {
            return Vec::new();
        };
        self_slot.ghost_connections(&self.slot_coords)
    }

    /// Get ghost connection targets as (Direction, HexCoord, is_ghost, gap_size).
    ///
    /// Useful for routing: "forward in direction D" uses the ghost target for D.
    /// Works identically for normal and ghost connections - routing is direction-based.
    pub fn ghost_connection_targets(&self) -> Vec<(Direction, HexCoord, bool, u32)> {
        self.ghost_connections()
            .into_iter()
            .map(|c| (c.direction, c.target, c.is_ghost, c.gap_size))
            .collect()
    }

    /// Get the peer at a ghost connection target in a specific direction.
    ///
    /// This is the GnW-aware version of "who is my neighbor in direction D?"
    /// Unlike theoretical neighbors, this accounts for gaps in the mesh.
    pub fn ghost_neighbor_peer(&self, direction: Direction) -> Option<&MeshPeer> {
        let self_slot = self.self_slot.as_ref()?;
        let target_coord = ghost_target(&self.slot_coords, self_slot.coord, direction)?;

        // Find the slot at target_coord
        let target_slot_index = self
            .claimed_slots
            .values()
            .find(|s| s.coord == target_coord)?
            .index;

        // Find peer with this slot
        self.peers
            .values()
            .find(|p| p.slot.as_ref().map(|s| s.index) == Some(target_slot_index))
    }

    /// Get all ghost neighbor peers.
    ///
    /// Returns peers at each ghost connection target. In a sparse mesh,
    /// these may be far away in slot index but are our logical neighbors.
    pub fn ghost_neighbor_peers(&self) -> Vec<&MeshPeer> {
        Direction::all()
            .iter()
            .filter_map(|&d| self.ghost_neighbor_peer(d))
            .collect()
    }

    /// Count ghost connections (should be 20 in a mesh with > 1 node).
    pub fn ghost_connection_count(&self) -> usize {
        self.ghost_connections().len()
    }

    /// Count ghost connections that are actual ghosts (span gaps).
    pub fn ghost_gap_count(&self) -> usize {
        self.ghost_connections()
            .iter()
            .filter(|c| c.is_ghost)
            .count()
    }

    /// Get total gap size across all ghost connections.
    ///
    /// In a dense mesh, this is 0. In a sparse mesh, this indicates
    /// how many empty slots our connections span.
    pub fn total_gap_size(&self) -> u32 {
        self.ghost_connections().iter().map(|c| c.gap_size).sum()
    }

    /// Convert a HexCoord to its slot index (if claimed).
    pub fn coord_to_slot_index(&self, coord: HexCoord) -> Option<u64> {
        self.claimed_slots
            .values()
            .find(|s| s.coord == coord)
            .map(|s| s.index)
    }

    /// Get the peer_id at a given coordinate (if any).
    pub fn peer_at_coord(&self, coord: HexCoord) -> Option<&str> {
        self.claimed_slots
            .values()
            .find(|s| s.coord == coord)
            .map(|s| s.peer_id.as_str())
    }

    // =========================================================================
    // SPORE⁻¹ Helper Methods: Working with individual hashes as point-ranges
    // =========================================================================
    //
    // SPORE represents ranges in 256-bit hash space. For tombstones/deletions,
    // each hash H becomes a point-range [H, H+1) which covers exactly that hash.
    // These helpers abstract the conversion between [u8; 32] and Spore.

    /// Convert a 32-byte hash to a U256 for Spore operations.
    fn hash_to_u256(hash: &[u8; 32]) -> citadel_spore::U256 {
        citadel_spore::U256::from_be_bytes(hash)
    }

    /// Create a point-range [H, H+1) for a single hash.
    /// This is how individual hashes are represented in Spore.
    ///
    /// Edge case: U256::MAX cannot have +1. The probability of H(H(id)) = MAX
    /// is 1/2^256 - astronomically unlikely. We panic if this ever happens.
    fn hash_to_point_range(hash: &[u8; 32]) -> citadel_spore::Range256 {
        let point = Self::hash_to_u256(hash);
        let next = point
            .checked_add(&citadel_spore::U256::from_u64(1))
            .expect("Hash collision at U256::MAX - probability 1/2^256");
        citadel_spore::Range256::new(point, next)
    }

    /// Add a tombstone (single hash) to the do_not_want set.
    /// Returns true if this is a new addition (set was modified).
    pub fn add_tombstone(&mut self, hash: [u8; 32]) -> bool {
        let point = Self::hash_to_u256(&hash);
        if self.do_not_want.covers(&point) {
            return false; // Already tombstoned
        }
        let point_range = Self::hash_to_point_range(&hash);
        self.do_not_want = self.do_not_want.union(&Spore::from_range(point_range));
        true
    }

    /// Check if a hash is tombstoned (in do_not_want set).
    pub fn is_tombstoned(&self, hash: &[u8; 32]) -> bool {
        let point = Self::hash_to_u256(hash);
        self.do_not_want.covers(&point)
    }

    /// Remove a tombstone from the do_not_want set.
    /// Note: This subtracts the point-range, which may split a larger range.
    pub fn remove_tombstone(&mut self, hash: &[u8; 32]) {
        let point_range = Self::hash_to_point_range(hash);
        self.do_not_want = self.do_not_want.subtract(&Spore::from_range(point_range));
    }

    /// Get the do_not_want Spore for SPORE⁻¹ sync.
    /// This is the range-based representation to send to peers.
    pub fn do_not_want_spore(&self) -> &Spore {
        &self.do_not_want
    }

    /// Merge received do_not_want ranges into our set.
    /// This is the core SPORE⁻¹ sync: union of all deletions.
    pub fn merge_do_not_want(&mut self, other: &Spore) {
        self.do_not_want = self.do_not_want.union(other);
    }

    /// Confirm erasure from a peer (for GDPR audit trail).
    pub fn confirm_erasure(&mut self, peer_id: &str, confirmed: &Spore) {
        self.erasure_confirmed = self.erasure_confirmed.union(confirmed);
        // Peer is synced if their confirmed XOR our do_not_want is empty
        let diff = self.do_not_want.xor(confirmed);
        self.erasure_synced
            .insert(peer_id.to_string(), diff.is_empty());
    }

    /// Check if all peers have confirmed erasure (for GC eligibility).
    pub fn all_erasures_confirmed(&self) -> bool {
        !self.erasure_synced.is_empty() && self.erasure_synced.values().all(|&synced| synced)
    }
}

#[cfg(test)]
mod tests {
    use super::MeshState;
    use crate::mesh::{peer_addr_store::PeerAddrStore, slot::SlotClaim};
    use citadel_protocols::SporeSyncManager;
    use citadel_spore::Spore;
    use citadel_topology::HexCoord;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::collections::HashSet;

    fn test_mesh_state() -> MeshState {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let peer_id_u256 = {
            let hash = blake3::hash(signing_key.verifying_key().as_bytes());
            citadel_spore::U256::from_be_bytes(hash.as_bytes())
        };

        MeshState {
            self_id: "b3b3/self".to_string(),
            signing_key: signing_key.clone(),
            self_slot: None,
            peers: HashMap::new(),
            peer_addr_store: PeerAddrStore::new(120_000),
            claimed_slots: HashMap::new(),
            slot_coords: HashSet::new(),
            spore_sync: Some(SporeSyncManager::new(peer_id_u256)),
            vdf_race: None,
            vdf_claims: HashMap::new(),
            pol_manager: None,
            pol_pending_pings: HashMap::new(),
            cvdf: None,
            latency_history: HashMap::new(),
            observed_public_addr: None,
            do_not_want: Spore::empty(),
            erasure_confirmed: Spore::empty(),
            erasure_synced: HashMap::new(),
            bad_bits: HashSet::new(),
            accountability: None,
            liveness: None,
        }
    }

    #[test]
    fn available_slot_count_uses_live_frontier_not_global_capacity() {
        let mut state = test_mesh_state();

        let slot0 = SlotClaim::new(0, "self".to_string());
        state.slot_coords.insert(slot0.coord);
        state.claimed_slots.insert(slot0.index, slot0);

        assert_eq!(state.available_slot_count(), 21);
        assert!((state.mesh_density() - (100.0 / 21.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn available_slot_count_deduplicates_overlapping_frontier() {
        let mut state = test_mesh_state();

        let slot0 = SlotClaim::new(0, "self".to_string());
        let slot1 = SlotClaim {
            index: 1,
            coord: HexCoord::new(1, 0, 0),
            peer_id: "peer-1".to_string(),
            public_key: None,
            confirmations: 0,
        };

        state.slot_coords.insert(slot0.coord);
        state.slot_coords.insert(slot1.coord);
        state.claimed_slots.insert(slot0.index, slot0);
        state.claimed_slots.insert(slot1.index, slot1);

        assert!(state.available_slot_count() < 42);
        assert_eq!(
            state.mesh_density(),
            (state.claimed_slots.len() as f64 / state.available_slot_count() as f64) * 100.0
        );
    }
}
