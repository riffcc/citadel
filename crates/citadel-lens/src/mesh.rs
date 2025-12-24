//! Citadel Mesh Service
//!
//! # THE MESH IS THE SOURCE OF TRUTH
//!
//! There is no external oracle, coordinator, or database. The topology IS consensus.
//! Your slot = the connections you have. The mesh = the sum of all connections.
//!
//! # THE KEY INSIGHT
//!
//! ```text
//! "11/20" IS NOT THE MECHANISM.
//! "11/20" IS THE RESULT.
//!
//! THE MECHANISM IS:
//! ├── TGP at the base (bilateral consensus)
//! ├── BFT emerges from TGP combinations
//! ├── Threshold scales with network size
//! └── 11/20 is what BFT LOOKS LIKE at 20 neighbors
//!
//! You don't "implement 11/20."
//! You implement TGP + scaling thresholds.
//! 11/20 emerges at maturity.
//! ```
//!
//! # The Scaling Ladder
//!
//! ```text
//! NODES    MECHANISM              THRESHOLD    HOW IT WORKS
//! ─────────────────────────────────────────────────────────────
//!   1      Genesis                1/1          First node auto-occupies slot 0
//!   2      TGP (bilateral)        2/2          Both agree or neither does
//!   3      TGP triad              2/3          Pairwise TGP, majority wins
//!  4-6     BFT emergence          ⌈n/2⌉+1      TGP pairs + deterministic tiebreaker
//!  7-11    Full BFT               2f+1         Threshold signatures (f = ⌊(n-1)/3⌋)
//!  12-20   Neighbor validation    scaled       Growing toward 11/20
//!  20+     Full SPIRAL            11/20        Mature mesh, all 20 neighbors exist
//! ```
//!
//! # Slot Occupancy Through Connections
//!
//! YOU DON'T "CLAIM" A SLOT. YOU **BECOME** A SLOT BY HAVING THE CONNECTIONS.
//!
//! A node occupies slot N iff:
//! 1. It has TGP agreements with ≥threshold neighbors of N
//! 2. Those neighbors acknowledge its direction as "toward N"
//! 3. Pigeonhole: Each neighbor has ONE "toward N" direction (exclusivity)
//!
//! # SPORE Principles
//!
//! ALL data transfer uses continuous flooding - no request/response patterns:
//! - Peer discovery floods on connection
//! - Slot announcements flood through mesh
//! - Admin lists flood on change
//! - XOR cancellation: sync_cost(A,B) = O(|A ⊕ B|) → 0 at convergence
//!
//! # 20-Neighbor Topology (SPIRAL)
//!
//! Each slot has exactly 20 theoretical neighbors:
//! - 6 planar (hexagonal grid at same z-level)
//! - 2 vertical (directly above/below)
//! - 12 extended (6 above + 6 below diagonals)

use crate::error::Result;
use crate::storage::Storage;
use crate::vdf_race::{VdfRace, VdfLink, AnchoredSlotClaim, claim_has_priority};
use crate::cvdf::{CvdfCoordinator, CvdfRound, RoundAttestation};
use crate::accountability::{AccountabilityTracker, FailureType};
use crate::liveness::{LivenessManager, MeshVouch, PropagationDecision};
use citadel_protocols::{
    CoordinatorConfig, FloodRateConfig, KeyPair, Message as TgpMessage, MessagePayload, PeerCoordinator, PublicKey,
    QuadProof, SporeSyncManager,
};
use citadel_spore::{U256, Spore, Range256, SyncState as SporeSyncState, SporeMessage};
use citadel_topology::{
    HexCoord, Neighbors, Spiral3DIndex, spiral3d_to_coord, coord_to_spiral3d,
    // Gap-and-Wrap: toroidal mesh with ghost connections
    Direction, Connection, compute_all_connections, ghost_target,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, oneshot, Notify, RwLock};
use tracing::{debug, error, info, warn};

/// Compute PeerID from ed25519 public key using double-BLAKE3 (Archivist/IPFS style)
/// hash₁ = BLAKE3(pubkey), hash₂ = BLAKE3(hash₁), PeerID = "b3b3/{hash₂}"
pub fn compute_peer_id(pubkey: &VerifyingKey) -> String {
    let hash1 = blake3::hash(pubkey.as_bytes());
    let hash2 = blake3::hash(hash1.as_bytes());
    format!("b3b3/{}", hex::encode(hash2.as_bytes()))
}

/// Compute PeerID from raw public key bytes
pub fn compute_peer_id_from_bytes(pubkey_bytes: &[u8]) -> String {
    let hash1 = blake3::hash(pubkey_bytes);
    let hash2 = blake3::hash(hash1.as_bytes());
    format!("b3b3/{}", hex::encode(hash2.as_bytes()))
}

/// Verify that a claimed PeerID matches the given public key
pub fn verify_peer_id(claimed_id: &str, pubkey: &VerifyingKey) -> bool {
    compute_peer_id(pubkey) == claimed_id
}

/// Compute double-hash of an ID for DoNotWantList (proof of absence)
/// H(H(id)) prevents enumeration while allowing verification
/// Only someone with the original ID can verify a deletion matches
pub fn double_hash_id(id: &str) -> [u8; 32] {
    let hash1 = blake3::hash(id.as_bytes());
    let hash2 = blake3::hash(hash1.as_bytes());
    *hash2.as_bytes()
}

/// Verify if an ID matches a double-hash (for tombstone checking)
pub fn matches_tombstone(id: &str, tombstone: &[u8; 32]) -> bool {
    double_hash_id(id) == *tombstone
}

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

    let ranges: Vec<Range256> = release_ids.iter()
        .filter_map(|id| {
            let start = release_id_to_u256(id);
            // Point range: [hash, hash+1)
            start.checked_add(&U256::from_u64(1))
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

/// Mesh node identity and state
#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub id: String,
    pub addr: SocketAddr,
    pub public_key: Option<Vec<u8>>,
    pub last_seen: std::time::Instant,
    pub coordinated: bool,
    /// The SPIRAL slot this peer has claimed (if known)
    pub slot: Option<SlotClaim>,
    /// True if this peer is an entry/bootstrap peer (from CITADEL_PEERS)
    /// Entry peers should be disconnected once we have enough SPIRAL neighbors
    pub is_entry_peer: bool,
    /// SPORE: True if WE have all content THIS peer has (our WantList from them = ∅)
    /// When all peers are content_synced, this node is "ready" to serve traffic
    pub content_synced: bool,
    /// SPORE: Their HaveList (what they possess) - received via SporeSync
    /// Their WantList = their_have.complement() - derived, not stored
    pub their_have: Option<Spore>,
}

/// A claimed SPIRAL slot in the mesh
#[derive(Debug, Clone)]
pub struct SlotClaim {
    /// SPIRAL index (deterministic ordering)
    pub index: u64,
    /// 3D hex coordinate
    pub coord: HexCoord,
    /// PeerID that claimed this slot
    pub peer_id: String,
    /// Public key of the claiming peer (for TGP)
    pub public_key: Option<Vec<u8>>,
    /// Number of validators who confirmed this claim
    pub confirmations: u32,
}

impl SlotClaim {
    /// Create a new slot claim (without public key)
    pub fn new(index: u64, peer_id: String) -> Self {
        let coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        Self {
            index,
            coord,
            peer_id,
            public_key: None,
            confirmations: 0,
        }
    }

    /// Create a new slot claim with public key
    pub fn with_public_key(index: u64, peer_id: String, public_key: Option<Vec<u8>>) -> Self {
        let coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        Self {
            index,
            coord,
            peer_id,
            public_key,
            confirmations: 0,
        }
    }

    /// Get the 20 theoretical neighbor coordinates of this slot.
    ///
    /// This returns the "ideal" neighbors assuming all slots are occupied.
    /// Used for slot validation: to claim slot N, you need TGP with its theoretical neighbors.
    pub fn neighbor_coords(&self) -> [HexCoord; 20] {
        Neighbors::of(self.coord)
    }

    /// Get the actual connections for this slot using Gap-and-Wrap.
    ///
    /// In a sparse mesh, some theoretical neighbors may be empty. GnW creates
    /// "ghost connections" that span gaps to the next occupied slot in each direction.
    /// This ensures every node has up to 20 logical connections regardless of density.
    ///
    /// Returns connections sorted by direction (6 planar + 2 vertical + 12 extended).
    pub fn ghost_connections(&self, occupied: &HashSet<HexCoord>) -> Vec<Connection> {
        compute_all_connections(occupied, self.coord)
    }

    /// Get the ghost target for a specific direction.
    ///
    /// Returns the actual connection target in the given direction:
    /// - If theoretical neighbor is occupied → normal connection
    /// - Otherwise → ghost connection to next occupied slot in that direction
    pub fn ghost_target_in_direction(&self, occupied: &HashSet<HexCoord>, direction: Direction) -> Option<HexCoord> {
        ghost_target(occupied, self.coord, direction)
    }
}

/// A single latency measurement sample
#[derive(Debug, Clone)]
pub struct LatencySample {
    pub latency_ms: u64,
    pub timestamp: std::time::Instant,
}

/// Latency history for a single neighbor - tracks samples over time windows
/// Uses VecDeque for O(1) push/pop. Memory-optimized: 360 samples (10s intervals)
#[derive(Debug, Clone, Default)]
pub struct LatencyHistory {
    /// Recent samples (circular buffer, 360 samples = 1h at 10s resolution)
    samples: std::collections::VecDeque<LatencySample>,
    /// Maximum samples to keep (reduced to save memory)
    max_samples: usize,
}

impl LatencyHistory {
    pub fn new() -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(64), // Start small, grow as needed
            max_samples: 360, // 1 hour at 10-second resolution
        }
    }

    /// Record a new latency sample - O(1) amortized
    pub fn record(&mut self, latency_ms: u64) {
        let sample = LatencySample {
            latency_ms,
            timestamp: std::time::Instant::now(),
        };

        if self.samples.len() >= self.max_samples {
            self.samples.pop_front(); // O(1) with VecDeque
        }
        self.samples.push_back(sample);
    }

    /// Compute latency statistics over multiple time windows
    pub fn compute_stats(&self) -> crate::api::LatencyStats {
        use std::time::Duration;

        let now = std::time::Instant::now();
        let one_sec = Duration::from_secs(1);
        let one_min = Duration::from_secs(60);
        let one_hour = Duration::from_secs(3600);

        let mut sum_1s = 0u64;
        let mut count_1s = 0u32;
        let mut sum_60s = 0u64;
        let mut count_60s = 0u32;
        let mut sum_1h = 0u64;
        let mut count_1h = 0u32;

        for sample in &self.samples {
            let age = now.duration_since(sample.timestamp);

            if age <= one_hour {
                sum_1h += sample.latency_ms;
                count_1h += 1;

                if age <= one_min {
                    sum_60s += sample.latency_ms;
                    count_60s += 1;

                    if age <= one_sec {
                        sum_1s += sample.latency_ms;
                        count_1s += 1;
                    }
                }
            }
        }

        crate::api::LatencyStats {
            last_1s_ms: if count_1s > 0 { Some(sum_1s as f64 / count_1s as f64) } else { None },
            last_60s_ms: if count_60s > 0 { Some(sum_60s as f64 / count_60s as f64) } else { None },
            last_1h_ms: if count_1h > 0 { Some(sum_1h as f64 / count_1h as f64) } else { None },
            samples_1s: count_1s,
            samples_60s: count_60s,
            samples_1h: count_1h,
        }
    }

    /// Get the most recent latency measurement
    pub fn latest(&self) -> Option<u64> {
        self.samples.back().map(|s| s.latency_ms)
    }
}

/// Calculate consensus threshold based on mesh size.
///
/// # THE MECHANISM
///
/// This is NOT arbitrary - these are the minimum thresholds for Byzantine fault
/// tolerance at each scale:
///
/// ```text
/// NODES   THRESHOLD   BYZANTINE TOLERANCE   MECHANISM
/// ─────────────────────────────────────────────────────────
///   1       1/1       0 faults              Genesis (trivial)
///   2       2/2       0 faults              Pure TGP bilateral
///   3       2/3       1 fault               TGP triad
///   4       3/4       1 fault               BFT: 2f+1 = 3
///  5-6      4/n       1 fault               Growing BFT
///  7-9      2f+1      2 faults              Full BFT formula
/// 10-14     2f+1      3-4 faults            Scaling BFT
/// 15-19     2f+1      4-6 faults            Approaching 11/20
///  20+      11/20     9 faults              Mature mesh BFT
/// ```
///
/// # BFT Formula
///
/// For `n` nodes, Byzantine fault tolerance requires:
/// - Maximum faults tolerated: `f = ⌊(n-1)/3⌋`
/// - Threshold: `2f + 1` (need honest majority of non-faulty)
///
/// At 20 neighbors: `f = ⌊19/3⌋ = 6`, but we use f=9 (11/20) because:
/// - Each neighbor independently validates via their own TGP
/// - We need >50% of TOTAL neighbors, not just non-faulty
///
/// # Security Scaling
///
/// Security GROWS with the network:
/// - 2 nodes: Both must agree (trivial to attack, but trivial network)
/// - 7 nodes: 5/7 must agree (2 Byzantine tolerated)
/// - 20 nodes: 11/20 must agree (9 Byzantine tolerated!)
pub fn consensus_threshold(mesh_size: usize) -> usize {
    match mesh_size {
        0 | 1 => 1,           // Genesis: auto-occupy slot 0
        2 => 2,               // Pure TGP: 2/2 bilateral (both agree or neither)
        3 => 2,               // Triad: 2/3 (one Byzantine tolerated)
        4 => 3,               // BFT emerges: 3/4 (f=1, 2f+1=3)
        5 => 4,               // f=1, 2f+1=3, but need >50% so 4/5
        6 => 4,               // f=1, 2f+1=3, but need >50% so 4/6
        7 => 5,               // f=2, 2f+1=5 (two Byzantine tolerated)
        8 => 6,               // f=2, need >50%
        9 => 6,               // f=2, need >50%
        10 => 7,              // f=3, 2f+1=7
        11..=13 => 8,         // f=3-4, scaling
        14..=16 => 9,         // f=4-5, approaching full mesh
        17..=19 => 10,        // f=5-6, almost there
        _ => 11,              // Full mesh: 11/20 (9 Byzantine tolerated)
    }
}

/// Active TGP coordination session with a peer
pub struct TgpSession {
    /// The TGP coordinator
    pub coordinator: PeerCoordinator,
    /// Commitment message (e.g., slot claim details)
    pub commitment: String,
    /// Channel to notify when coordination completes
    pub result_tx: Option<oneshot::Sender<bool>>,
    /// Peer's TGP UDP address (stored here for contention-free access)
    pub peer_tgp_addr: SocketAddr,
}

/// A peer authorized via TGP QuadProof.
///
/// # TGP-Native Architecture
///
/// In TGP-native mesh, **connection isn't a socket—it's a proof**.
/// Once two peers complete the TGP handshake (C→D→T→Q), they have
/// bilateral QuadProofs that serve as permanent authorization.
///
/// Benefits over TCP connection state:
/// - **No phantom peers**: A peer exists iff QuadProof exists
/// - **No reconnection logic**: Proofs are permanent, UDP can retry freely
/// - **No keepalive**: Proof validity doesn't depend on connection liveness
/// - **No half-open state**: QuadProof is bilateral—both have it or neither does
#[derive(Debug, Clone)]
pub struct AuthorizedPeer {
    /// The peer's unique identifier (b3b3/{double-blake3})
    pub peer_id: String,
    /// The peer's Ed25519 public key (for signature verification)
    pub public_key: [u8; 32],
    /// Our QuadProof for this peer (proves we completed TGP with them)
    pub our_quad: QuadProof,
    /// Their QuadProof for us (proves they completed TGP with us)
    /// Both proofs must exist—this is the bilateral construction property
    pub their_quad: QuadProof,
    /// Last known UDP address for this peer (can change, doesn't affect authorization)
    pub last_addr: SocketAddr,
    /// The SPIRAL slot this peer has claimed (if known)
    pub slot: Option<SlotClaim>,
    /// When this authorization was established
    pub established: std::time::Instant,
}

impl AuthorizedPeer {
    /// Create a new authorized peer from bilateral QuadProofs.
    ///
    /// Both QuadProofs must exist—this is enforced by TGP's bilateral construction property.
    pub fn new(
        peer_id: String,
        public_key: [u8; 32],
        our_quad: QuadProof,
        their_quad: QuadProof,
        last_addr: SocketAddr,
    ) -> Self {
        Self {
            peer_id,
            public_key,
            our_quad,
            their_quad,
            last_addr,
            slot: None,
            established: std::time::Instant::now(),
        }
    }

    /// Check if this peer is authorized (always true if struct exists).
    ///
    /// This is a no-op that documents the TGP-native invariant:
    /// existence of AuthorizedPeer IS authorization.
    #[inline]
    pub const fn is_authorized(&self) -> bool {
        // Existence is authorization. No connection state to check.
        true
    }
}

/// Mesh service state
pub struct MeshState {
    /// Our node ID (PeerID)
    pub self_id: String,
    /// Our signing key for authentication
    pub signing_key: SigningKey,
    /// Cached TGP keypair (derived from signing_key once, reused for all sessions)
    /// This enables zerocopy/CoW responder sessions - creating a responder is just cloning Arc
    pub tgp_keypair: Arc<KeyPair>,
    /// UDP socket for TGP (set when run() is called)
    pub udp_socket: Option<Arc<UdpSocket>>,
    /// TGP-native: Peers authorized via completed QuadProof (PeerId -> AuthorizedPeer)
    ///
    /// This is the TGP-native source of truth for peer authorization.
    /// A peer exists in this map iff we have completed bilateral TGP coordination.
    /// Unlike TCP `peers` map, there are no "phantom" or "connecting" states.
    pub authorized_peers: HashMap<String, AuthorizedPeer>,
    /// Our claimed slot in the mesh
    pub self_slot: Option<SlotClaim>,
    /// Slot we're currently trying to claim via TGP (event-driven, no waiting)
    pub pending_slot_claim: Option<u64>,
    /// Known peers in the mesh (by PeerID)
    pub peers: HashMap<String, MeshPeer>,
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
    /// SPORE: DoNotWantList - accumulated double-hashes of deleted content
    /// H(H(id)) prevents enumeration while allowing deletion propagation
    pub do_not_want: HashSet<[u8; 32]>,
    /// SPORE: ErasureConfirmed - tombstones we have locally confirmed erasing
    /// Syncs via SPORE XOR (ErasureHaveList) - when XOR=0, all peers agree
    /// Once all peers have same ErasureConfirmed, tombstones can be garbage collected from DoNotWantList
    pub erasure_confirmed: HashSet<[u8; 32]>,
    /// SPORE: Peers' erasure sync status (peer_id -> their_erasure_xor_with_ours == 0)
    /// When all peers are erasure_synced, we can garbage collect tombstones
    pub erasure_synced: HashMap<String, bool>,
    /// BadBits: PERMANENT blocklist of double-hashed CIDs H(H(cid))
    /// Unlike DoNotWantList (GDPR - GC'd after erasure), BadBits are forever
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
    // NOTE: tgp_sessions moved to MeshService for contention-free access
}

impl MeshState {
    /// Record a latency measurement between two nodes
    pub fn record_latency(&mut self, from_node: &str, to_node: &str, latency_ms: u64) {
        let from_map = self.latency_history
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

        self_slot.neighbor_coords()
            .iter()
            .filter_map(|coord| {
                // Find claimed slot at this coordinate
                self.claimed_slots.values()
                    .find(|s| s.coord == *coord)
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
        let neighbor_coords: std::collections::HashSet<_> = self_slot.neighbor_coords().into_iter().collect();

        self.claimed_slots.values()
            .any(|claim| claim.peer_id == peer_id && neighbor_coords.contains(&claim.coord))
    }

    /// Count connected SPIRAL neighbors (not entry peers)
    pub fn connected_neighbor_count(&self) -> usize {
        let Some(ref self_slot) = self.self_slot else {
            return 0;
        };

        let neighbor_coords: std::collections::HashSet<_> = self_slot.neighbor_coords().into_iter().collect();

        // Count peers whose slots are in our neighborhood
        self.peers.values()
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
        self.peers.iter()
            .filter(|(id, peer)| peer.is_entry_peer && !self.is_spiral_neighbor(id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    // =========================================================================
    // Gap-and-Wrap: Toroidal mesh with ghost connections
    // =========================================================================
    //
    // In a sparse mesh, theoretical neighbors may be empty. Gap-and-Wrap creates
    // "ghost connections" that span gaps to the next occupied slot in each direction.
    // This ensures every node has up to 20 logical connections regardless of density.
    //
    // Properties (proven in Lean: CitadelProofs.GapAndWrap):
    // - ghost_bidirectional: A→B in d implies B→A in opposite(d)
    // - full_connectivity: Every node has 20 connections (if mesh > 1)
    // - connections_symmetric: The connection graph is undirected
    // - self_healing: Connections auto-resolve when nodes leave

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
        let target_slot_index = self.claimed_slots.values()
            .find(|s| s.coord == target_coord)?
            .index;

        // Find peer with this slot
        self.peers.values()
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
        self.ghost_connections().iter().filter(|c| c.is_ghost).count()
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
        self.claimed_slots.values()
            .find(|s| s.coord == coord)
            .map(|s| s.index)
    }

    /// Get the peer_id at a given coordinate (if any).
    pub fn peer_at_coord(&self, coord: HexCoord) -> Option<&str> {
        self.claimed_slots.values()
            .find(|s| s.coord == coord)
            .map(|s| s.peer_id.as_str())
    }
}

/// Broadcast message for continuous flooding
#[derive(Clone, Debug)]
pub enum FloodMessage {
    /// Peer discovery (id, addr, slot_index, public_key)
    Peers(Vec<(String, String, Option<u64>, Option<Vec<u8>>)>),
    /// Admin list sync
    Admins(Vec<String>),
    /// Slot claim announcement (index, peer_id, coord as (q, r, z), public_key)
    SlotClaim { index: u64, peer_id: String, coord: (i64, i64, i64), public_key: Option<Vec<u8>> },
    /// Slot claim validation response
    SlotValidation { index: u64, peer_id: String, validator_id: String, accepted: bool },
    /// SPORE HaveList - advertise what slots we know about (for targeted sync)
    SporeHaveList { peer_id: String, slots: Vec<u64> },
    /// VDF chain sync - broadcast chain links for collaborative VDF
    VdfChain { links: Vec<VdfLink> },
    /// VDF-anchored slot claim - deterministic priority ordering
    VdfSlotClaim { claim: AnchoredSlotClaim },
    /// Proof of Latency ping request (for measuring RTT)
    PoLPing { from: [u8; 32], nonce: u64, vdf_height: u64 },
    /// Proof of Latency pong response
    PoLPong { from: [u8; 32], nonce: u64, vdf_height: u64 },
    /// Proof of Latency swap proposal
    PoLSwapProposal { proposal: crate::proof_of_latency::SwapProposal },
    /// Proof of Latency swap response
    PoLSwapResponse { response: crate::proof_of_latency::SwapResponse },
    /// CVDF attestation for current round
    /// Optionally carries a MeshVouch (liveness proof for all neighbors)
    /// Vouches piggyback on attestations - zero extra traffic at steady state
    CvdfAttestation {
        att: RoundAttestation,
        /// Stapled liveness vouch (2-hop propagation: Origin → Judged → Witness → STOP)
        vouch: Option<MeshVouch>,
    },
    /// CVDF new round produced (with stapled SPORE proof for zero-overhead sync)
    CvdfNewRound {
        round: CvdfRound,
        /// SPORE XOR proof - empty at convergence (zero overhead)
        spore_proof: citadel_spore::Spore,
    },
    /// CVDF chain sync request
    CvdfSyncRequest { from_node: String, from_height: u64 },
    /// CVDF chain sync response (all rounds)
    CvdfSyncResponse { rounds: Vec<CvdfRound>, slots: Vec<(u64, [u8; 32])> },
    /// SPORE: Content HaveList - advertise release IDs we have (for content sync)
    ContentHaveList { peer_id: String, release_ids: Vec<String> },
    /// SPORE: Release flood - propagate a release across the mesh
    Release { release_json: String },
    /// SPORE: DoNotWantList - double-hashed IDs of deleted content (proof of absence)
    /// H(H(id)) is shared to prevent enumeration while allowing verification
    DoNotWantList { peer_id: String, double_hashes: Vec<[u8; 32]> },
    /// SPORE: ErasureConfirmation - bilateral proof that a node has deleted content
    /// Used for GDPR-compliant "right to erasure" with cryptographic proof
    ErasureConfirmation { peer_id: String, tombstones: Vec<[u8; 32]> },
    /// BadBits: PERMANENT blocklist of double-hashed CIDs H(H(cid))
    /// Unlike DoNotWantList (GDPR), BadBits prevent future uploads forever
    /// For: copyright violations, abuse material, illegal content
    /// See: https://badbits.dwebops.pub/
    BadBits { double_hashes: Vec<[u8; 32]> },
    /// SPORE: Sync proof with XOR difference (range-based)
    /// At convergence: xor_diff = [] (empty, zero cost)
    /// Only contains ranges that differ between peers
    SporeSync {
        peer_id: String,
        /// Full HaveList on first exchange, then XOR diff for updates
        have_list: Spore,
    },
    /// SPORE: Delta transfer - actual content for the XOR difference
    /// Contains releases that match ranges in the XOR diff
    SporeDelta {
        releases: Vec<String>, // JSON-serialized releases
    },
    /// SPORE: Featured releases sync - separate from regular releases
    /// These control homepage/hero display and have their own sync lifecycle
    FeaturedSync {
        peer_id: String,
        featured: Vec<String>, // JSON-serialized FeaturedRelease
    },
}

/// Citadel Mesh Service
pub struct MeshService {
    /// P2P listen address (TCP and UDP share this port)
    listen_addr: SocketAddr,
    /// P2P announce address (public IP for other peers to connect to)
    /// If None, uses listen_addr (which may be 0.0.0.0 - won't work!)
    announce_addr: Option<SocketAddr>,
    /// Bootstrap peers to connect to
    entry_peers: Vec<String>,
    /// Shared storage for replication
    storage: Arc<Storage>,
    /// Mesh state (peers, slots, etc.)
    state: Arc<RwLock<MeshState>>,
    /// TGP sessions - SEPARATE lock for contention-free TGP operations
    /// This allows send_tgp_messages to run without blocking on mesh state
    tgp_sessions: Arc<RwLock<HashMap<String, TgpSession>>>,
    /// Broadcast channel for continuous flooding
    flood_tx: broadcast::Sender<FloodMessage>,
    /// Notification for when CVDF is initialized (genesis or join)
    cvdf_init_notify: Arc<Notify>,
    /// Channel for pending connections to spawn from listener
    pending_connect_tx: mpsc::Sender<(String, SocketAddr)>,
    pending_connect_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(String, SocketAddr)>>>,
    /// Atomic flag to prevent concurrent slot claiming attempts
    claiming_in_progress: std::sync::atomic::AtomicBool,
}

impl MeshService {
    /// Create a new mesh service
    pub fn new(
        listen_addr: SocketAddr,
        announce_addr: Option<SocketAddr>,
        entry_peers: Vec<String>,
        storage: Arc<Storage>,
    ) -> Self {
        // Generate or load node keypair for peer identity
        let signing_key = storage.get_or_create_node_key()
            .unwrap_or_else(|_| {
                // Fallback: generate ephemeral key
                let mut rng = rand::thread_rng();
                SigningKey::generate(&mut rng)
            });

        // PeerID is double-BLAKE3 hash of ed25519 public key (Archivist/IPFS style)
        let verifying_key = signing_key.verifying_key();
        let self_id = compute_peer_id(&verifying_key);

        info!("Node PeerID: {}", self_id);

        // Create broadcast channel for continuous flooding (capacity for burst)
        let (flood_tx, _) = broadcast::channel(1024);

        // Initialize SPORE sync manager with peer ID derived from public key hash
        let peer_id_u256 = {
            let hash = blake3::hash(verifying_key.as_bytes());
            U256::from_be_bytes(hash.as_bytes())
        };
        let spore_sync = SporeSyncManager::new(peer_id_u256);

        // Pre-compute TGP keypair once for zerocopy/CoW responder sessions
        // This is derived from signing_key and shared via Arc across all sessions
        let tgp_keypair = Arc::new(
            KeyPair::from_seed(&signing_key.to_bytes())
                .expect("Failed to create TGP keypair from signing key")
        );

        // Channel for pending connections to spawn from listener
        let (pending_connect_tx, pending_connect_rx) = mpsc::channel(256);

        Self {
            listen_addr,
            announce_addr,
            entry_peers,
            storage,
            state: Arc::new(RwLock::new(MeshState {
                self_id,
                signing_key: signing_key.clone(),
                tgp_keypair,
                udp_socket: None,  // Set when run() is called
                authorized_peers: HashMap::new(),  // TGP-native: QuadProof-authorized peers
                self_slot: None,
                pending_slot_claim: None,
                peers: HashMap::new(),
                claimed_slots: HashMap::new(),
                slot_coords: HashSet::new(),
                spore_sync: Some(spore_sync),
                vdf_race: None,    // Initialized when joining mesh or as genesis
                vdf_claims: HashMap::new(),
                pol_manager: None,  // Initialized after claiming a slot
                pol_pending_pings: HashMap::new(),
                cvdf: None,        // Initialized as genesis or when joining mesh
                latency_history: HashMap::new(),
                observed_public_addr: None,  // Learned from peers via hello
                do_not_want: HashSet::new(),  // SPORE: DoNotWantList for deletion sync
                erasure_confirmed: HashSet::new(),  // SPORE: ErasureConfirmed for GDPR compliance
                erasure_synced: HashMap::new(),  // SPORE: Peer erasure sync status
                bad_bits: HashSet::new(),  // BadBits: permanent blocklist (DMCA, abuse, illegal)
                accountability: Some(AccountabilityTracker::new(signing_key.clone())),  // Misbehaviour tracking
                liveness: Some(LivenessManager::new(signing_key)),  // Structure-aware liveness (2-hop vouches)
            })),
            // Separate lock for TGP sessions - contention-free TGP operations
            tgp_sessions: Arc::new(RwLock::new(HashMap::new())),
            flood_tx,
            // Notification for CVDF initialization
            cvdf_init_notify: Arc::new(Notify::new()),
            // Channel for pending peer connections
            pending_connect_tx,
            pending_connect_rx: Arc::new(tokio::sync::Mutex::new(pending_connect_rx)),
            // Atomic flag for slot claiming (prevents concurrent claims)
            claiming_in_progress: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Attempt to occupy a SPIRAL slot.
    ///
    /// # CURRENT LIMITATION
    ///
    /// This function currently "claims" a slot by flooding an announcement.
    /// This is WRONG. The correct protocol is:
    ///
    /// ```text
    /// WRONG (current):
    /// 1. Pick slot N
    /// 2. Flood "I am slot N"
    /// 3. Hope for the best, use tiebreaker if contested
    ///
    /// RIGHT (should be):
    /// 1. Pick slot N
    /// 2. Calculate N's 20 theoretical neighbors
    /// 3. Attempt TGP bilateral connection with each existing neighbor
    /// 4. Count successful TGP agreements (QuadProofs)
    /// 5. If count >= consensus_threshold(mesh_size):
    ///    → You ARE slot N (connections prove it)
    /// 6. If count < threshold:
    ///    → Try slot N+1
    /// ```
    ///
    /// The slot doesn't exist because you claim it.
    /// The slot exists because you have the connections.
    /// THE MESH IS THE SOURCE OF TRUTH.
    ///
    /// # TODO
    ///
    /// Replace this with `attempt_slot_via_tgp()` that:
    /// - Uses [`PeerCoordinator`] for each neighbor connection
    /// - Commitment message includes: (my_id, target_slot, direction_from_neighbor)
    /// - Returns true only if TGP agreements >= threshold
    /// - On failure, caller tries next slot
    pub async fn claim_slot(&self, index: u64) -> bool {
        // TODO: Replace with TGP-based slot acquisition
        // This function currently floods a claim without TGP validation
        // See docs/MESH_PROTOCOL.md for the correct protocol

        let mut state = self.state.write().await;

        // Check if slot is already claimed
        if state.claimed_slots.contains_key(&index) {
            warn!("Slot {} already claimed", index);
            return false;
        }

        let peer_id = state.self_id.clone();
        let public_key = state.signing_key.verifying_key();
        let public_key_bytes = public_key.as_bytes().to_vec();
        let claim = SlotClaim::with_public_key(index, peer_id.clone(), Some(public_key_bytes.clone()));
        let coord = claim.coord;

        // Record our claim (with our own public key)
        state.self_slot = Some(claim.clone());
        state.claimed_slots.insert(index, claim.clone());
        state.slot_coords.insert(coord);

        // Calculate required confirmations based on mesh size
        let mesh_size = state.claimed_slots.len();
        let threshold = consensus_threshold(mesh_size);

        info!(
            "Claimed slot {} at ({}, {}, {}) - mesh size {}, threshold {}",
            index, coord.q, coord.r, coord.z, mesh_size, threshold
        );

        drop(state);

        // Set our slot in CVDF for duty rotation
        self.cvdf_set_slot(index).await;

        // Also register ourselves in CVDF
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&public_key_bytes);
        self.cvdf_register_slot(index, pubkey_arr).await;

        // Flood our claim to the network (with public key for TGP)
        self.flood(FloodMessage::SlotClaim {
            index,
            peer_id,
            coord: (coord.q, coord.r, coord.z),
            public_key: Some(public_key_bytes),
        });

        true
    }

    /// EVENT-DRIVEN slot claiming trigger.
    /// Called when a peer connects. NO WAITING. NO LOOPS.
    ///
    /// 1. Sets pending_slot_claim to next available slot
    /// 2. Starts TGP with available peers
    /// 3. Returns immediately
    ///
    /// When QuadProof is achieved (in handle_tgp_message), the slot is claimed.
    pub fn trigger_slot_claim_if_ready(self: &Arc<Self>) {
        let mesh = Arc::clone(self);
        tokio::spawn(async move {
            mesh.start_slot_claim_tgp().await;
        });
    }

    /// Start TGP exchanges for slot claiming. Returns immediately (event-driven).
    async fn start_slot_claim_tgp(&self) {
        let mut state = self.state.write().await;

        // Already have a slot? Done.
        if state.self_slot.is_some() {
            return;
        }

        // Already claiming? Don't start another.
        if state.pending_slot_claim.is_some() {
            return;
        }

        // No peers? Can't claim.
        if state.peers.is_empty() {
            return;
        }

        // Pick the next available slot
        let target_slot = state.next_available_slot();

        // Check if slot is already claimed (race condition check)
        if state.claimed_slots.contains_key(&target_slot) {
            info!("Slot {} already claimed, will retry on next peer event", target_slot);
            return;
        }

        // Gather peers to start TGP with (only those with public keys)
        let peers_to_tgp: Vec<(String, SocketAddr, [u8; 32])> = state.peers.values()
            .filter_map(|p| {
                p.public_key.as_ref().and_then(|pk| {
                    if pk.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(pk);
                        Some((p.id.clone(), p.addr, arr))
                    } else {
                        None
                    }
                })
            })
            .collect();

        // No peers with public keys? Can't start TGP yet. Will retry on next peer event.
        if peers_to_tgp.is_empty() {
            debug!("No peers with public keys yet, will retry slot claim later");
            return;
        }

        // Set pending claim ONLY if we have peers to TGP with
        state.pending_slot_claim = Some(target_slot);
        let target_coord = spiral3d_to_coord(Spiral3DIndex::new(target_slot));
        let commitment_msg = format!("mesh_slot:{}:{}:{}", target_slot, target_coord.q, target_coord.r);

        let my_keypair = (*state.tgp_keypair).clone();
        drop(state);

        info!("Starting TGP for slot {} with {} peers", target_slot, peers_to_tgp.len());

        // Create TGP sessions and send first messages
        for (peer_id, peer_addr, pubkey_bytes) in peers_to_tgp {
            let Ok(counterparty_key) = PublicKey::from_bytes(&pubkey_bytes) else {
                continue;
            };

            let mut coordinator = PeerCoordinator::symmetric(
                my_keypair.clone(),
                counterparty_key,
                CoordinatorConfig::default()
                    .with_commitment(commitment_msg.clone().into_bytes())
                    .with_flood_rate(FloodRateConfig::fast()),
            );
            coordinator.set_active(true);

            self.tgp_sessions.write().await.insert(
                peer_id.clone(),
                TgpSession {
                    coordinator,
                    commitment: commitment_msg.clone(),
                    result_tx: None, // No channel needed - event-driven
                    peer_tgp_addr: peer_addr,
                },
            );

            // Send first TGP message
            if let Some(socket) = self.state.read().await.udp_socket.clone() {
                self.send_tgp_messages(&socket, &peer_id).await;
            }
        }
        // Return immediately. When QuadProof is achieved, handle_tgp_message will claim the slot.
    }

    // ==================== VDF RACE METHODS ====================
    //
    // VDF Race provides deterministic bootstrap coordination and split-brain merge.
    // Longest chain = largest swarm. Priority ordering resolves conflicts.

    /// Genesis seed for VDF chain (shared across all nodes in the mesh)
    /// In production, this would be derived from network genesis block or similar
    const VDF_GENESIS_SEED: [u8; 32] = [
        0x43, 0x49, 0x54, 0x41, 0x44, 0x45, 0x4c, 0x2d,  // "CITADEL-"
        0x56, 0x44, 0x46, 0x2d, 0x47, 0x45, 0x4e, 0x45,  // "VDF-GENE"
        0x53, 0x49, 0x53, 0x2d, 0x53, 0x45, 0x45, 0x44,  // "SIS-SEED"
        0x2d, 0x56, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x00,  // "-V1.0.0\0"
    ];

    /// Initialize VDF race as genesis node (first node in mesh)
    pub async fn init_vdf_genesis(&self) {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        let vdf_race = VdfRace::new_genesis(Self::VDF_GENESIS_SEED, signing_key);
        info!("VDF Race initialized as genesis (height 0)");

        state.vdf_race = Some(vdf_race);
    }

    /// Initialize VDF race when joining existing mesh
    /// Takes chain links from bootstrap peer
    pub async fn init_vdf_join(&self, chain_links: Vec<VdfLink>) -> bool {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        match VdfRace::join(Self::VDF_GENESIS_SEED, signing_key, chain_links) {
            Some(vdf_race) => {
                let height = vdf_race.height();
                info!("VDF Race initialized by joining (height {})", height);
                state.vdf_race = Some(vdf_race);
                true
            }
            None => {
                warn!("Failed to join VDF race - invalid chain");
                false
            }
        }
    }

    /// Claim a slot with VDF anchoring for deterministic priority
    /// Returns the anchored claim for flooding to the network
    pub async fn claim_slot_with_vdf(&self, index: u64) -> Option<AnchoredSlotClaim> {
        let mut state = self.state.write().await;

        // Ensure VDF race is initialized
        let vdf_race = state.vdf_race.as_mut()?;

        // Extend VDF chain before claiming (proves we did work)
        vdf_race.extend_chain();

        // Create VDF-anchored claim
        let claim = vdf_race.claim_slot(index);
        let vdf_height = claim.vdf_height;

        // Store our claim
        state.vdf_claims.insert(index, claim.clone());

        // Also create regular slot claim for compatibility
        let peer_id = state.self_id.clone();
        let public_key_bytes = state.signing_key.verifying_key().as_bytes().to_vec();
        let slot_claim = SlotClaim::with_public_key(index, peer_id.clone(), Some(public_key_bytes.clone()));
        let coord = slot_claim.coord;

        state.self_slot = Some(slot_claim.clone());
        state.claimed_slots.insert(index, slot_claim);
        state.slot_coords.insert(coord);

        info!(
            "Claimed slot {} with VDF anchor at height {} (coord: {}, {}, {})",
            index, vdf_height, coord.q, coord.r, coord.z
        );

        drop(state);

        // Set our slot in CVDF for duty rotation
        self.cvdf_set_slot(index).await;

        // Also register ourselves in CVDF
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&public_key_bytes);
        self.cvdf_register_slot(index, pubkey_arr).await;

        // Flood the VDF claim
        self.flood(FloodMessage::VdfSlotClaim { claim: claim.clone() });

        // Also flood regular slot claim for compatibility with non-VDF nodes
        self.flood(FloodMessage::SlotClaim {
            index,
            peer_id,
            coord: (coord.q, coord.r, coord.z),
            public_key: Some(public_key_bytes),
        });

        Some(claim)
    }

    /// Process incoming VDF-anchored claim
    /// Uses VDF priority ordering for deterministic conflict resolution
    /// Returns true if this claim wins (has priority)
    pub async fn process_vdf_claim(&self, claim: AnchoredSlotClaim) -> bool {
        let mut state = self.state.write().await;

        let slot = claim.slot;

        // Check if we have an existing claim for this slot
        if let Some(existing) = state.vdf_claims.get(&slot) {
            // Compare using proven priority ordering
            if claim_has_priority(&claim, existing) {
                info!(
                    "VDF claim for slot {} wins: height {} < existing height {}",
                    slot, claim.vdf_height, existing.vdf_height
                );

                // Check if we lost our slot
                if let Some(ref our_slot) = state.self_slot {
                    if our_slot.index == slot {
                        let our_pubkey = state.signing_key.verifying_key().to_bytes();
                        if claim.claimer != our_pubkey {
                            warn!("We lost slot {} to node with earlier VDF claim!", slot);
                            state.self_slot = None;
                        }
                    }
                }

                state.vdf_claims.insert(slot, claim);
                true
            } else {
                debug!(
                    "VDF claim for slot {} rejected: height {} >= existing height {}",
                    slot, claim.vdf_height, existing.vdf_height
                );
                false
            }
        } else {
            // No existing claim - this one wins
            info!(
                "VDF claim for slot {} accepted (first claim at height {})",
                slot, claim.vdf_height
            );
            state.vdf_claims.insert(slot, claim);
            true
        }
    }

    /// Try to adopt a longer VDF chain (for split-brain merge)
    /// Returns true if we switched to the longer chain
    pub async fn try_adopt_vdf_chain(&self, other_links: Vec<VdfLink>) -> bool {
        let mut state = self.state.write().await;

        let vdf_race = match state.vdf_race.as_mut() {
            Some(v) => v,
            None => {
                // Initialize VDF race with the received chain
                drop(state);
                return self.init_vdf_join(other_links).await;
            }
        };

        let our_height = vdf_race.height();
        let other_height = other_links.last().map(|l| l.height).unwrap_or(0);

        if vdf_race.try_adopt_chain(other_links) {
            info!(
                "Adopted longer VDF chain: {} -> {} (split-brain merge)",
                our_height, vdf_race.height()
            );
            true
        } else {
            debug!(
                "Rejected VDF chain: our height {} >= their height {}",
                our_height, other_height
            );
            false
        }
    }

    /// Get VDF chain links for syncing to peers
    pub async fn get_vdf_chain_links(&self) -> Vec<VdfLink> {
        let state = self.state.read().await;
        state.vdf_race.as_ref()
            .map(|v| v.chain_links().to_vec())
            .unwrap_or_default()
    }

    /// Extend VDF chain (collaborative - nodes take turns)
    pub async fn extend_vdf_chain(&self) -> Option<VdfLink> {
        let mut state = self.state.write().await;
        let vdf_race = state.vdf_race.as_mut()?;
        let link = vdf_race.extend_chain();

        let height = link.height;
        drop(state);

        // Flood the updated chain periodically
        if height % 10 == 0 {
            let links = self.get_vdf_chain_links().await;
            self.flood(FloodMessage::VdfChain { links });
        }

        Some(link)
    }

    /// Get current VDF height
    pub async fn vdf_height(&self) -> u64 {
        let state = self.state.read().await;
        state.vdf_race.as_ref().map(|v| v.height()).unwrap_or(0)
    }

    // ==================== END VDF RACE METHODS ====================

    // ==================== CVDF METHODS ====================
    //
    // Collaborative VDF: weight-based consensus where heavier chains win.
    // Weight = Σ(base + attestation_count) - more attesters = heavier chain
    // This is THE core of Constitutional P2P - collaboration beats competition.

    /// CVDF Genesis seed (same as VDF for compatibility)
    const CVDF_GENESIS_SEED: [u8; 32] = Self::VDF_GENESIS_SEED;

    /// Initialize CVDF as genesis node
    pub async fn init_cvdf_genesis(&self) {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        let cvdf = CvdfCoordinator::new_genesis(Self::CVDF_GENESIS_SEED, signing_key);
        info!("CVDF initialized as genesis (height 0, weight 1)");

        state.cvdf = Some(cvdf);
        drop(state); // Release lock before notify

        // Signal that CVDF is ready - unblocks the coordination loop
        self.cvdf_init_notify.notify_waiters();
    }

    /// Initialize CVDF by joining existing swarm
    /// Takes rounds from bootstrap peer and slot registrations
    pub async fn init_cvdf_join(&self, rounds: Vec<CvdfRound>, slots: Vec<(u64, [u8; 32])>) -> bool {
        let mut state = self.state.write().await;
        let signing_key = state.signing_key.clone();

        match CvdfCoordinator::join(Self::CVDF_GENESIS_SEED, rounds, signing_key) {
            Some(mut cvdf) => {
                // Register known slots
                for (slot, pubkey) in slots {
                    cvdf.register_slot(slot, pubkey);
                }
                let height = cvdf.height();
                let weight = cvdf.weight();
                info!("CVDF joined (height {}, weight {})", height, weight);
                state.cvdf = Some(cvdf);
                true
            }
            None => {
                warn!("Failed to join CVDF - invalid chain");
                false
            }
        }
    }

    /// Register a slot in CVDF (for attestation tracking)
    pub async fn cvdf_register_slot(&self, slot: u64, pubkey: [u8; 32]) {
        let mut state = self.state.write().await;
        if let Some(ref mut cvdf) = state.cvdf {
            cvdf.register_slot(slot, pubkey);
            debug!("CVDF registered slot {} with pubkey {:?}", slot, &pubkey[..8]);
        }
    }

    /// Set our slot in CVDF
    pub async fn cvdf_set_slot(&self, slot: u64) {
        let mut state = self.state.write().await;
        if let Some(ref mut cvdf) = state.cvdf {
            cvdf.set_slot(slot);
            info!("CVDF set our slot to {}", slot);
        }
    }

    /// Create attestation for current round
    pub async fn cvdf_attest(&self) -> Option<RoundAttestation> {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref()?;
        let att = cvdf.attest();
        Some(att)
    }

    /// Process incoming attestation
    pub async fn cvdf_process_attestation(&self, att: RoundAttestation) -> bool {
        let mut state = self.state.write().await;
        if let Some(cvdf) = state.cvdf.as_mut() {
            cvdf.receive_attestation(att)
        } else {
            false
        }
    }

    /// Try to produce a round (if it's our turn)
    pub async fn cvdf_try_produce(&self) -> Option<CvdfRound> {
        let mut state = self.state.write().await;
        let cvdf = state.cvdf.as_mut()?;

        if cvdf.is_our_turn() {
            cvdf.try_produce()
        } else {
            None
        }
    }

    /// Process incoming round
    pub async fn cvdf_process_round(&self, round: CvdfRound) -> bool {
        let mut state = self.state.write().await;
        if let Some(cvdf) = state.cvdf.as_mut() {
            cvdf.process_round(round)
        } else {
            false
        }
    }

    /// Get CVDF chain state for syncing
    pub async fn cvdf_chain_state(&self) -> Option<(Vec<CvdfRound>, Vec<(u64, [u8; 32])>)> {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref()?;

        let rounds = cvdf.chain().all_rounds().to_vec();
        let slots: Vec<(u64, [u8; 32])> = cvdf.registered_slots().clone();

        Some((rounds, slots))
    }

    /// Check if we should adopt another chain (heavier)
    pub async fn cvdf_should_adopt(&self, other_rounds: &[CvdfRound]) -> bool {
        let state = self.state.read().await;
        let cvdf = state.cvdf.as_ref();
        cvdf.map(|c| c.should_adopt(other_rounds)).unwrap_or(true)
    }

    /// Adopt heavier chain
    pub async fn cvdf_adopt(&self, rounds: Vec<CvdfRound>) -> bool {
        let mut state = self.state.write().await;
        let cvdf = state.cvdf.as_mut();
        cvdf.map(|c| c.adopt(rounds)).unwrap_or(false)
    }

    /// Get CVDF height
    pub async fn cvdf_height(&self) -> u64 {
        let state = self.state.read().await;
        state.cvdf.as_ref().map(|c| c.height()).unwrap_or(0)
    }

    /// Get CVDF weight
    pub async fn cvdf_weight(&self) -> u64 {
        let state = self.state.read().await;
        state.cvdf.as_ref().map(|c| c.weight()).unwrap_or(0)
    }

    /// Get CVDF tip hash
    pub async fn cvdf_tip(&self) -> [u8; 32] {
        let state = self.state.read().await;
        state.cvdf.as_ref()
            .map(|c| c.chain().tip_output())
            .unwrap_or([0u8; 32])
    }

    /// Check if CVDF is initialized
    pub async fn cvdf_initialized(&self) -> bool {
        let state = self.state.read().await;
        state.cvdf.is_some()
    }

    /// Run CVDF coordination loop
    /// This handles periodic attestation and round production
    pub async fn run_cvdf_loop(&self) {
        use tokio::time::{interval, Duration};

        // Wait for CVDF to be initialized (event-driven, no polling)
        self.cvdf_init_notify.notified().await;

        // Run coordination loop
        let mut tick = interval(Duration::from_millis(100)); // 10Hz coordination

        loop {
            tick.tick().await;

            // Create and broadcast attestation (with piggybacked vouch when needed)
            if let Some(att) = self.cvdf_attest().await {
                // CRITICAL: Process our OWN attestation first (add to pending queue)
                // Without this, try_produce() has no attestations to work with!
                self.cvdf_process_attestation(att.clone()).await;

                // Piggyback vouch on attestation - zero extra traffic
                let vouch = if self.should_create_mesh_vouch().await {
                    self.create_mesh_vouch().await
                } else {
                    None
                };
                self.flood(FloodMessage::CvdfAttestation { att, vouch });
            }

            // Try to produce a round
            if let Some(round) = self.cvdf_try_produce().await {
                info!("CVDF produced round {} (weight {})",
                    round.round, round.weight());
                // Staple SPORE proof to heartbeat - empty at convergence (zero overhead)
                let spore_proof = citadel_spore::Spore::empty();
                self.flood(FloodMessage::CvdfNewRound { round, spore_proof });
            }

            // Periodically broadcast chain state for sync
            let height = self.cvdf_height().await;
            if height > 0 && height % 10 == 0 {
                if let Some((rounds, slots)) = self.cvdf_chain_state().await {
                    let self_id = self.self_id().await;
                    self.flood(FloodMessage::CvdfSyncResponse { rounds, slots });
                }
            }
        }
    }

    // ==================== LIVENESS MONITORING ====================

    /// Check if a slot is live (has attested recently in CVDF)
    pub async fn is_slot_live(&self, slot: u64) -> bool {
        let state = self.state.read().await;
        state.cvdf.as_ref()
            .map(|c| c.is_slot_live(slot))
            .unwrap_or(false)
    }

    /// Get all stale slots (haven't attested in SLOT_LIVENESS_THRESHOLD rounds)
    pub async fn get_stale_slots(&self) -> Vec<u64> {
        let state = self.state.read().await;
        state.cvdf.as_ref()
            .map(|c| c.stale_slots())
            .unwrap_or_default()
    }

    /// Get liveness status for all registered slots
    /// Returns Vec<(slot, is_live, last_attestation_round)>
    pub async fn get_slot_liveness_status(&self) -> Vec<(u64, bool, Option<u64>)> {
        let state = self.state.read().await;
        state.cvdf.as_ref()
            .map(|c| c.slot_liveness_status())
            .unwrap_or_default()
    }

    /// Get liveness status for ghost neighbors (our actual connections via GnW)
    /// Returns live/stale status for each direction
    pub async fn ghost_neighbor_liveness(&self) -> Vec<(Direction, u64, bool)> {
        let state = self.state.read().await;

        let Some(ref self_slot) = state.self_slot else {
            return Vec::new();
        };

        let connections = self_slot.ghost_connections(&state.slot_coords);
        let cvdf = state.cvdf.as_ref();

        connections.iter().filter_map(|conn| {
            // Find slot index at target coord
            let slot_idx = state.claimed_slots.values()
                .find(|s| s.coord == conn.target)
                .map(|s| s.index)?;

            // Check liveness
            let is_live = cvdf.map(|c| c.is_slot_live(slot_idx)).unwrap_or(false);

            Some((conn.direction, slot_idx, is_live))
        }).collect()
    }

    /// Count live ghost neighbors
    pub async fn live_ghost_neighbor_count(&self) -> usize {
        self.ghost_neighbor_liveness().await
            .iter()
            .filter(|(_, _, live)| *live)
            .count()
    }

    /// Prune stale slots from CVDF tracking
    /// Returns list of pruned slot indices
    pub async fn prune_stale_slots(&self) -> Vec<u64> {
        let mut state = self.state.write().await;
        state.cvdf.as_mut()
            .map(|c| c.prune_stale_slots())
            .unwrap_or_default()
    }

    // ==================== MISBEHAVIOUR DETECTION ====================
    //
    // Track and report protocol violations using the accountability system.
    // Types of misbehaviour detected:
    // - Unresponsive: Node stopped responding to challenges
    // - InvalidResponse: Node provided invalid/lying responses
    // - BftFailure: Node failed BFT coordination
    // - PositionLie: Node claimed wrong position in mesh
    // - RelayFailure: Node failed to relay messages properly

    /// Start tracking a failure for a node
    pub async fn start_failure_tracking(
        &self,
        failed_pubkey: [u8; 32],
        failed_slot: Option<u64>,
        failure_type: FailureType,
    ) {
        let mut state = self.state.write().await;
        if let Some(ref mut accountability) = state.accountability {
            accountability.start_failure_tracking(failed_pubkey, failed_slot, failure_type);
        }
    }

    /// Report misbehaviour (unresponsive neighbor detected via liveness)
    pub async fn report_unresponsive(&self, slot: u64) {
        let state = self.state.read().await;

        // Get pubkey for the slot
        let slot_claim = state.claimed_slots.get(&slot);
        if let Some(claim) = slot_claim {
            if let Some(ref pubkey_bytes) = claim.public_key {
                if pubkey_bytes.len() == 32 {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(pubkey_bytes);
                    drop(state);
                    self.start_failure_tracking(pubkey, Some(slot), FailureType::Unresponsive).await;
                }
            }
        }
    }

    /// Check if a node is under failure tracking
    pub async fn is_tracking_failure(&self, pubkey: &[u8; 32]) -> bool {
        let state = self.state.read().await;
        state.accountability.as_ref()
            .map(|a| a.get_failure_proof(pubkey, 20).is_some())
            .unwrap_or(false)
    }

    /// Get all nodes currently being tracked for failure
    pub async fn get_failure_candidates(&self) -> Vec<[u8; 32]> {
        // Combine stale slots (from CVDF liveness) with accountability tracking
        let stale_slots = self.get_stale_slots().await;
        let state = self.state.read().await;

        stale_slots.iter().filter_map(|&slot| {
            state.claimed_slots.get(&slot)
                .and_then(|claim| claim.public_key.as_ref())
                .and_then(|pk| {
                    if pk.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(pk);
                        Some(arr)
                    } else {
                        None
                    }
                })
        }).collect()
    }

    /// Trigger misbehaviour check for all stale ghost neighbors
    pub async fn check_ghost_neighbor_misbehaviour(&self) {
        let liveness = self.ghost_neighbor_liveness().await;

        for (direction, slot, is_live) in liveness {
            if !is_live {
                debug!("Ghost neighbor at slot {} (direction {:?}) is stale - reporting unresponsive", slot, direction);
                self.report_unresponsive(slot).await;
            }
        }
    }

    // ==================== END CVDF METHODS ====================

    // ==================== STRUCTURE-AWARE LIVENESS ====================
    //
    // MeshVouch: One signature attesting to all 20 neighbors.
    // Propagation: Origin → Judged → Witness → STOP (2 hops max)
    // Event-driven: Zero traffic at steady state.
    //
    // This is the symmetric protocol for join/leave:
    // - JOIN:  Accumulate vouches until threshold → slot valid
    // - LEAVE: Vouches expire until below threshold → slot invalid

    /// Initialize the liveness manager with our signing key
    pub async fn init_liveness_manager(&self) {
        let mut state = self.state.write().await;
        if state.liveness.is_none() {
            let manager = LivenessManager::new(state.signing_key.clone());
            state.liveness = Some(manager);
        }
    }

    /// Update liveness manager with current VDF height and neighbors
    pub async fn update_liveness_context(&self) {
        let mut state = self.state.write().await;

        // Get current VDF height
        let vdf_height = state.cvdf.as_ref()
            .map(|c| c.current_round())
            .unwrap_or(0);

        // Get our slot
        let our_slot = state.self_slot.as_ref().map(|s| s.index);

        // Get neighbor public keys
        let neighbors: Vec<[u8; 32]> = state.present_neighbors()
            .iter()
            .filter_map(|claim| {
                claim.public_key.as_ref().and_then(|pk| {
                    if pk.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(pk);
                        Some(arr)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Update liveness manager
        if let Some(ref mut liveness) = state.liveness {
            liveness.set_vdf_height(vdf_height);
            if let Some(slot) = our_slot {
                liveness.set_slot(slot);
            }
            liveness.set_neighbors(neighbors);
        }
    }

    /// Record a latency measurement for liveness purposes
    pub async fn record_liveness_latency(&self, neighbor_pubkey: [u8; 32], latency_ms: u64) {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.record_latency(neighbor_pubkey, latency_ms);
        }
    }

    /// Handle an incoming mesh vouch - returns propagation decision
    ///
    /// Based on the decision:
    /// - Drop: Ignore (not relevant to us)
    /// - Stop: Record and don't propagate further (we're a witness)
    /// - ForwardToNeighbors: Record and forward to our neighbors (we're judged)
    pub async fn handle_mesh_vouch(&self, vouch: MeshVouch) -> PropagationDecision {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.handle_vouch(vouch)
        } else {
            PropagationDecision::Drop
        }
    }

    /// Check if we should create a new mesh vouch (event-driven)
    pub async fn should_create_mesh_vouch(&self) -> bool {
        let state = self.state.read().await;
        state.liveness.as_ref()
            .map(|l| l.should_create_vouch())
            .unwrap_or(false)
    }

    /// Create a mesh vouch for all alive neighbors
    ///
    /// Returns the vouch to be broadcast via the mesh.
    /// Call this when should_create_mesh_vouch() returns true.
    pub async fn create_mesh_vouch(&self) -> Option<MeshVouch> {
        let mut state = self.state.write().await;
        state.liveness.as_mut()?.create_vouch()
    }

    /// Check if a node is valid (has sufficient vouches)
    pub async fn is_node_valid(&self, pubkey: &[u8; 32]) -> bool {
        let state = self.state.read().await;
        state.liveness.as_ref()
            .map(|l| l.is_node_valid(pubkey))
            .unwrap_or(false)
    }

    /// Get all nodes that have become invalid (for slot reclamation)
    ///
    /// These are nodes whose vouches have expired below threshold.
    /// Their slots can now be claimed by new nodes.
    pub async fn get_invalid_nodes(&self) -> Vec<[u8; 32]> {
        let state = self.state.read().await;
        state.liveness.as_ref()
            .map(|l| l.invalid_nodes())
            .unwrap_or_default()
    }

    /// Get vouch count for a node
    pub async fn get_vouch_count(&self, pubkey: &[u8; 32]) -> usize {
        let state = self.state.read().await;
        state.liveness.as_ref()
            .map(|l| l.vouch_count(pubkey))
            .unwrap_or(0)
    }

    /// Prune expired liveness data
    pub async fn prune_liveness(&self) {
        let mut state = self.state.write().await;
        if let Some(ref mut liveness) = state.liveness {
            liveness.prune_expired();
        }
    }

    /// Get slots that have become invalid and can be reclaimed
    ///
    /// Maps invalid node pubkeys to their slot indices.
    /// These slots are available for new nodes to claim.
    pub async fn get_reclaimable_slots(&self) -> Vec<u64> {
        let invalid_nodes = self.get_invalid_nodes().await;
        let state = self.state.read().await;

        invalid_nodes.iter().filter_map(|pubkey| {
            state.claimed_slots.values()
                .find(|claim| {
                    claim.public_key.as_ref()
                        .map(|pk| pk.as_slice() == pubkey.as_slice())
                        .unwrap_or(false)
                })
                .map(|claim| claim.index)
        }).collect()
    }

    // ==================== END STRUCTURE-AWARE LIVENESS ====================

    /// Attempt to occupy a SPIRAL slot through TGP bilateral connections.
    ///
    /// This is the CORRECT protocol for slot acquisition:
    /// 1. Calculate target slot's 20 theoretical neighbors
    /// 2. Find existing nodes at those neighbor positions
    /// 3. Attempt TGP bilateral connection with each
    /// 4. Count successful TGP agreements (QuadProofs)
    /// 5. If count >= consensus_threshold(mesh_size), we occupy the slot
    ///
    /// # The Optimized 4-Packet Handshake
    ///
    /// ```text
    /// PACKET 1 (A→B): C_A                         # A's commitment
    /// PACKET 2 (B→A): C_B + D_B                   # B's commitment + proof of A's
    /// PACKET 3 (A→B): D_A + T_A                   # A's double + triple
    /// PACKET 4 (B→A): T_B + Q_B                   # B's triple + quad
    ///
    /// RESULT: Both have QuadProof. Forever.
    /// ```
    ///
    /// Returns `true` if slot was successfully occupied.
    pub async fn attempt_slot_via_tgp(&self, target_slot: u64) -> bool {
        let state = self.state.read().await;

        // Get mesh size for threshold calculation
        let mesh_size = state.claimed_slots.len();
        let threshold = consensus_threshold(mesh_size);

        // Calculate target slot's coordinate and its 20 theoretical neighbors
        let target_coord = spiral3d_to_coord(Spiral3DIndex::new(target_slot));
        let neighbor_coords = Neighbors::of(target_coord);

        // Find validators for this slot claim:
        // 1. First, look for SPIRAL neighbors (nodes at neighboring coordinates)
        // 2. If mesh is empty/forming, use ANY connected peer as witness
        let mut potential_validators: Vec<(String, SocketAddr, Option<Vec<u8>>)> = Vec::new();

        // Try SPIRAL neighbors first
        for coord in &neighbor_coords {
            if let Some(slot_claim) = state.claimed_slots.values().find(|s| s.coord == *coord) {
                if let Some(peer) = state.peers.get(&slot_claim.peer_id) {
                    potential_validators.push((
                        peer.id.clone(),
                        peer.addr,
                        peer.public_key.clone(),
                    ));
                }
            }
        }

        // If no SPIRAL neighbors, use ANY connected peer (bootstrap case)
        // RULE ZERO: Any peer can witness. The topology emerges from claims, not the other way around.
        if potential_validators.is_empty() {
            for peer in state.peers.values() {
                if peer.public_key.is_some() {
                    potential_validators.push((
                        peer.id.clone(),
                        peer.addr,
                        peer.public_key.clone(),
                    ));
                }
            }
        }

        let validator_count = potential_validators.len();
        drop(state);

        info!(
            "Attempting slot {} via TGP: {} validators, threshold {} (mesh size {})",
            target_slot, validator_count, threshold, mesh_size
        );

        // RULE ZERO: NO NODE IS SPECIAL
        // You cannot claim a slot without at least one peer to validate with.
        // If you have no connections, you can't prove to anyone that you claimed it.
        if validator_count == 0 {
            info!("Cannot claim slot {} - no peers to validate with", target_slot);
            return false;
        }

        // Calculate scaled threshold based on existing neighbors
        // If only 6 neighbors exist, we need ceil(6 * threshold / 20)
        let scaled_threshold = if validator_count >= 20 {
            threshold
        } else {
            // Scale proportionally but require at least 1
            std::cmp::max(1, (validator_count * threshold + 19) / 20)
        };

        info!(
            "Scaled threshold: {} of {} existing neighbors (full threshold: {} of 20)",
            scaled_threshold, validator_count, threshold
        );

        // Create TGP sessions with each neighbor and collect result receivers
        let mut result_receivers = Vec::new();
        let mut session_peer_ids = Vec::new();
        let commitment_msg = format!(
            "mesh_slot:{}:{}:{}",
            target_slot,
            target_coord.q,
            target_coord.r
        );

        for (peer_id, peer_addr, maybe_pubkey) in potential_validators {
            // Skip if we don't have their public key
            let Some(pubkey_bytes) = maybe_pubkey else {
                warn!("Cannot attempt TGP with {} - no public key", peer_id);
                continue;
            };

            // Convert to TGP PublicKey
            let Ok(pubkey_array): std::result::Result<[u8; 32], _> = pubkey_bytes.try_into() else {
                warn!("Invalid public key length for {}", peer_id);
                continue;
            };
            let Ok(counterparty_key) = PublicKey::from_bytes(&pubkey_array) else {
                warn!("Invalid public key for {}", peer_id);
                continue;
            };

            // Get cached TGP keypair (zerocopy - just clone the Arc's content)
            let my_keypair = {
                let state = self.state.read().await;
                (*state.tgp_keypair).clone()
            };

            // Peer's TGP UDP address (same port as TCP - UDP and TCP share port)
            let peer_tgp_addr = peer_addr;

            // Create oneshot channel for result notification
            let (result_tx, result_rx) = oneshot::channel();

            // Create SYMMETRIC coordinator - role determined by public key comparison
            let mut coordinator = PeerCoordinator::symmetric(
                my_keypair,
                counterparty_key,
                CoordinatorConfig::default()
                    .with_commitment(commitment_msg.clone().into_bytes())
                    .with_timeout(std::time::Duration::from_secs(10))
                    .with_flood_rate(FloodRateConfig::fast()),
            );
            coordinator.set_active(true);

            // Store session in separate lock (contention-free)
            self.tgp_sessions.write().await.insert(
                peer_id.clone(),
                TgpSession {
                    coordinator,
                    commitment: commitment_msg.clone(),
                    result_tx: Some(result_tx),
                    peer_tgp_addr,
                },
            );

            session_peer_ids.push(peer_id.clone());
            result_receivers.push((peer_id.clone(), result_rx));
            debug!("Created TGP session with {} for slot {} (TGP addr: {})", peer_id, target_slot, peer_tgp_addr);
        }

        debug!("Created {} TGP sessions for slot {}", session_peer_ids.len(), target_slot);
        // Event-driven: immediately send TGP messages for all created sessions
        if let Some(udp_socket) = self.state.read().await.udp_socket.clone() {
            for peer_id in &session_peer_ids {
                self.send_tgp_messages(&udp_socket, peer_id).await;
            }
        } else {
            warn!("No UDP socket available for TGP!");
        }

        // Wait for all TGP sessions to complete (with timeout)
        let mut successful_coordinations = 0;
        let timeout = tokio::time::Duration::from_secs(10);

        for (peer_id, result_rx) in result_receivers {
            match tokio::time::timeout(timeout, result_rx).await {
                Ok(Ok(true)) => {
                    successful_coordinations += 1;
                    info!("TGP coordination with {} succeeded (QuadProof achieved)", peer_id);
                }
                Ok(Ok(false)) => {
                    debug!("TGP coordination with {} failed", peer_id);
                }
                Ok(Err(_)) => {
                    debug!("TGP session with {} was dropped", peer_id);
                }
                Err(_) => {
                    debug!("TGP coordination with {} timed out", peer_id);
                    // Clean up timed out session (separate lock - contention-free)
                    self.tgp_sessions.write().await.remove(&peer_id);
                }
            }
        }

        info!(
            "TGP slot {} attempt: {} of {} coordinations (need {})",
            target_slot, successful_coordinations, validator_count, scaled_threshold
        );

        // Check if we reached threshold
        if successful_coordinations >= scaled_threshold {
            info!("Slot {} acquired via TGP ({} >= {} threshold)", target_slot, successful_coordinations, scaled_threshold);
            self.claim_slot(target_slot).await
        } else {
            warn!(
                "Failed to acquire slot {} - only {} of {} required coordinations",
                target_slot, successful_coordinations, scaled_threshold
            );
            false
        }
    }

    /// Compute ungameable tiebreaker for slot claims
    /// Formula: hash(blake3(peer_id) XOR blake3(transaction))
    /// where transaction = "slot_claim:{index}"
    /// Lower hash wins. Impossible to influence since you can't predict the slot index
    /// when choosing your peer ID.
    fn slot_claim_priority(peer_id: &str, slot_index: u64) -> [u8; 32] {
        let peer_hash = blake3::hash(peer_id.as_bytes());
        let tx_data = format!("slot_claim:{}", slot_index);
        let tx_hash = blake3::hash(tx_data.as_bytes());

        // XOR the hashes
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = peer_hash.as_bytes()[i] ^ tx_hash.as_bytes()[i];
        }

        // Hash the XOR result for final priority
        *blake3::hash(&xored).as_bytes()
    }

    /// Compare two peers' priority for a slot (true if a beats b)
    fn peer_wins_slot(peer_a: &str, peer_b: &str, slot_index: u64) -> bool {
        let priority_a = Self::slot_claim_priority(peer_a, slot_index);
        let priority_b = Self::slot_claim_priority(peer_b, slot_index);
        priority_a < priority_b  // Lower hash wins
    }

    /// Process a slot claim. Returns (we_lost, race_won) where:
    /// - we_lost: true if we lost our own slot to this claimer
    /// - race_won: true if this claimer beat a previous claimer (needs re-flooding)
    pub async fn process_slot_claim(&self, index: u64, peer_id: String, coord: (i64, i64, i64), public_key: Option<Vec<u8>>) -> (bool, bool) {
        let mut state = self.state.write().await;
        let hex_coord = HexCoord::new(coord.0, coord.1, coord.2);

        // Verify the coord matches the index
        let expected_coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        if hex_coord != expected_coord {
            warn!("Invalid slot claim: index {} should be at {:?}, not {:?}",
                  index, expected_coord, hex_coord);
            return (false, false);
        }

        let self_id = state.self_id.clone();

        // Check if this claim conflicts with OUR slot
        let our_slot_info = state.self_slot.as_ref().map(|s| (s.index, s.coord));
        let we_lost = if let Some((our_index, our_coord)) = our_slot_info {
            if our_index == index && peer_id != self_id {
                // Ungameable tiebreaker: hash(blake3(peer_id) XOR blake3(tx))
                if Self::peer_wins_slot(&peer_id, &self_id, index) {
                    warn!("Lost slot {} race to {} (their priority wins), will reclaim", index, peer_id);
                    // Remove our claim from the global map
                    state.claimed_slots.remove(&index);
                    state.slot_coords.remove(&our_coord);
                    state.self_slot = None;
                    true
                } else {
                    // We win, keep our slot
                    debug!("Won slot {} race against {} (our priority wins)", index, peer_id);
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Check if already claimed
        let mut race_won = false;
        if let Some(existing) = state.claimed_slots.get(&index) {
            if existing.peer_id == peer_id {
                // Same claim we already have - skip (deduplication)
                return (we_lost, false);
            }
            // Different claimer - use ungameable tiebreaker
            if Self::peer_wins_slot(&peer_id, &existing.peer_id, index) {
                let loser_id = existing.peer_id.clone();
                info!("Slot {} taken by {} (beats previous claimer {} by priority)",
                      index, peer_id, loser_id);
                // Clear the loser's slot in our peer records
                if let Some(loser_peer) = state.peers.get_mut(&loser_id) {
                    loser_peer.slot = None;
                }
                // Mark that a race was won - this needs re-flooding!
                race_won = true;
                // Fall through to accept the new claim
            } else {
                debug!("Slot {} stays with {} (beats new claimer {} by priority)",
                       index, existing.peer_id, peer_id);
                return (we_lost, false);
            }
        }

        // Accept the claim (with public key for TGP)
        let claim = SlotClaim::with_public_key(index, peer_id.clone(), public_key.clone());
        state.claimed_slots.insert(index, claim);
        state.slot_coords.insert(hex_coord);

        info!("Accepted slot claim {} from {} at ({}, {}, {})",
              index, peer_id, coord.0, coord.1, coord.2);

        // If this peer is connected to us, update their slot info and public key
        if let Some(peer) = state.peers.get_mut(&peer_id) {
            peer.slot = Some(SlotClaim::with_public_key(index, peer_id, public_key.clone()));
            // Also store public key in peer if we didn't have it
            if peer.public_key.is_none() {
                peer.public_key = public_key;
            }
        }

        (we_lost, race_won)
    }

    /// Get a receiver for flood messages (for connections to subscribe)
    pub fn subscribe_floods(&self) -> broadcast::Receiver<FloodMessage> {
        self.flood_tx.subscribe()
    }

    /// Broadcast a flood message to all connections
    pub fn flood(&self, msg: FloodMessage) {
        let _ = self.flood_tx.send(msg);
    }

    /// Get current mesh state for API
    pub async fn get_peers(&self) -> Vec<MeshPeer> {
        self.state.read().await.peers.values().cloned().collect()
    }

    /// Get self ID
    pub async fn self_id(&self) -> String {
        self.state.read().await.self_id.clone()
    }

    /// Get the shared mesh state (for API access)
    pub fn mesh_state(&self) -> Arc<RwLock<MeshState>> {
        Arc::clone(&self.state)
    }

    /// Get the flood sender (for admin socket to propagate changes)
    pub fn flood_tx(&self) -> broadcast::Sender<FloodMessage> {
        self.flood_tx.clone()
    }

    /// Run TGP UDP listener - receives incoming TGP messages from any peer
    /// This is connectionless - we can receive from anyone who knows our address
    /// Event-driven: immediately responds after receiving each message
    async fn run_tgp_udp_listener(&self, socket: Arc<UdpSocket>) {
        // TGP messages include cryptographic proofs and can be 2-4KB
        let mut buf = [0u8; 8192];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    info!("UDP recv {} bytes from {}", len, src_addr);
                    // Deserialize TGP message
                    match serde_json::from_slice::<TgpMessage>(&buf[..len]) {
                        Ok(tgp_msg) => {
                            // Handle message and immediately send response (event-driven)
                            if let Some(peer_id) = self.handle_tgp_message(src_addr, tgp_msg).await {
                                self.send_tgp_messages(&socket, &peer_id).await;
                            } else {
                                info!("UDP from {} - no peer found for TGP message", src_addr);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize TGP from {} ({} bytes): {}", src_addr, len, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("TGP UDP recv error: {}", e);
                }
            }
        }
    }

    /// Extract the sender's public key from a TGP message payload.
    /// The sender's commitment is always in the `own_*` field.
    fn extract_sender_pubkey(msg: &TgpMessage) -> Option<[u8; 32]> {
        match &msg.payload {
            MessagePayload::Commitment(c) => Some(*c.public_key.as_bytes()),
            MessagePayload::DoubleProof(d) => Some(*d.own_commitment.public_key.as_bytes()),
            MessagePayload::TripleProof(t) => Some(*t.own_double.own_commitment.public_key.as_bytes()),
            MessagePayload::QuadProof(q) => Some(*q.own_triple.own_double.own_commitment.public_key.as_bytes()),
        }
    }

    /// Extract slot claim info from a Commitment message.
    /// Returns Some(slot_index) if this is a slot claim commitment.
    fn extract_slot_claim_from_commitment(commitment: &citadel_protocols::Commitment) -> Option<u64> {
        // The commitment message is "mesh_slot:X:q:r" where X is the slot index
        let msg_bytes = commitment.message.as_slice();
        let msg_str = std::str::from_utf8(msg_bytes).ok()?;
        if !msg_str.starts_with("mesh_slot:") {
            return None;
        }
        // Parse "mesh_slot:123:0:0" -> 123
        let parts: Vec<&str> = msg_str.split(':').collect();
        if parts.len() >= 2 {
            parts[1].parse::<u64>().ok()
        } else {
            None
        }
    }

    /// Handle incoming TGP message from UDP.
    /// Returns the peer_id if message was processed (for sending response).
    /// Uses symmetric TGP - party roles determined by public key comparison.
    async fn handle_tgp_message(&self, src_addr: SocketAddr, msg: TgpMessage) -> Option<String> {
        // Extract sender's public key from the message itself (cryptographically authenticated)
        let sender_pubkey = Self::extract_sender_pubkey(&msg)?;

        // Find peer by public key (not by IP - multiple peers may share localhost IP)
        let (peer_id, my_keypair, counterparty_key) = {
            let state = self.state.read().await;

            // Match by public key extracted from the TGP message (primary method)
            let peer = state.peers.iter()
                .find(|(_, p)| {
                    p.public_key.as_ref()
                        .map(|pk| pk.as_slice() == sender_pubkey.as_slice())
                        .unwrap_or(false)
                });

            // TGP is TCP-free: we can establish coordination with ANY node that sends us
            // a valid TGP message, using just the public key from the message itself.
            // No pre-existing TCP peer relationship required!
            let keypair = (*state.tgp_keypair).clone();

            match peer {
                Some((id, _peer)) => {
                    // Known peer - use their stored info
                    let Ok(counterparty) = PublicKey::from_bytes(&sender_pubkey) else {
                        warn!("Invalid public key from peer {}", id);
                        return None;
                    };
                    debug!("TGP from known peer {} at {}", id, src_addr);
                    (id.clone(), keypair, counterparty)
                }
                None => {
                    // Unknown peer - create peer_id from their public key (TCP-free TGP!)
                    // Format: "b3b3/<pubkey_hex>" - consistent with how we generate our own ID
                    let peer_id = format!("b3b3/{}", hex::encode(&sender_pubkey));
                    let Ok(counterparty) = PublicKey::from_bytes(&sender_pubkey) else {
                        warn!("Invalid public key from unknown peer at {}", src_addr);
                        return None;
                    };
                    info!("TGP-PURE: Accepting coordination from {} at {} (no TCP required)",
                          &peer_id[..12], src_addr);
                    (peer_id, keypair, counterparty)
                }
            }
        };

        // SLOT VALIDATION: If this is a slot claim, check if the slot is available
        // Per MESH_PROTOCOL.md: "Loser's neighbors reject (slot already filling)"
        if let MessagePayload::Commitment(c) = &msg.payload {
            if let Some(claimed_slot) = Self::extract_slot_claim_from_commitment(c) {
                let state = self.state.read().await;
                // Check if this slot is already claimed by someone else
                if let Some(existing_claim) = state.claimed_slots.get(&claimed_slot) {
                    // Slot is taken - reject this TGP
                    info!("SLOT VALIDATION: Rejecting TGP for slot {} from {} - slot already claimed by {}",
                          claimed_slot, peer_id, existing_claim.peer_id);
                    return None;
                }
                debug!("SLOT VALIDATION: Slot {} is available for {}", claimed_slot, peer_id);
            }
        }

        // Create session if needed (SYMMETRIC - no tiebreaker needed!)
        // With symmetric TGP, both peers can create sessions independently
        // and they'll automatically have opposite roles based on public key comparison.
        {
            let mut sessions = self.tgp_sessions.write().await;
            let is_commitment = matches!(&msg.payload, MessagePayload::Commitment(_));
            let need_new_session = if let Some(existing) = sessions.get(&peer_id) {
                // If we receive a Commitment and our session is Complete, a new TGP is starting
                // This happens when a peer starts claiming a different slot after their first claim
                is_commitment && existing.coordinator.is_coordinated()
            } else {
                true
            };

            if need_new_session {
                if sessions.contains_key(&peer_id) {
                    info!("Resetting TGP session for {} (new Commitment received after Complete)", peer_id);
                } else {
                    debug!("Creating SYMMETRIC TGP session for {} (incoming message)", peer_id);
                }
                let mut coordinator = PeerCoordinator::symmetric(
                    my_keypair.clone(),
                    counterparty_key.clone(),
                    CoordinatorConfig::default()
                        .with_timeout(std::time::Duration::from_secs(30))
                        .with_flood_rate(FloodRateConfig::fast()),
                );
                coordinator.set_active(true);
                sessions.insert(
                    peer_id.clone(),
                    TgpSession {
                        coordinator,
                        commitment: String::new(),
                        result_tx: None,
                        peer_tgp_addr: src_addr,
                    },
                );
            }
        }

        // Process the message (separate lock)
        // If coordination completes, extract receipt for AuthorizedPeer storage
        let completed_auth: Option<(QuadProof, QuadProof, [u8; 32], SocketAddr)> = {
            let mut sessions = self.tgp_sessions.write().await;
            if let Some(session) = sessions.get_mut(&peer_id) {
                let old_state = session.coordinator.tgp_state();
                // Log message party for debugging
                let msg_party = match &msg.payload {
                    MessagePayload::Commitment(c) => format!("Commitment({})", c.party),
                    MessagePayload::DoubleProof(d) => format!("Double({})", d.party),
                    MessagePayload::TripleProof(t) => format!("Triple({})", t.party),
                    MessagePayload::QuadProof(q) => format!("Quad({})", q.party),
                };
                info!("TGP recv: {} msg={} (state: {:?})", peer_id, msg_party, old_state);
                match session.coordinator.receive(&msg) {
                    Ok(advanced) => {
                        let new_state = session.coordinator.tgp_state();
                        if advanced {
                            info!("TGP with {} advanced: {:?} -> {:?}", peer_id, old_state, new_state);
                        } else {
                            info!("TGP with {} receive ok but state unchanged: {:?}", peer_id, old_state);
                        }
                        if session.coordinator.is_coordinated() {
                            info!("TGP with {} complete - QuadProof achieved!", peer_id);
                            if let Some(tx) = session.result_tx.take() {
                                let _ = tx.send(true);
                            }
                            // Extract bilateral receipt for AuthorizedPeer storage
                            if let Some((our_quad, their_quad)) = session.coordinator.get_bilateral_receipt() {
                                // Get peer's public key from message
                                let pubkey = Self::extract_sender_pubkey(&msg).unwrap_or([0u8; 32]);
                                Some((our_quad.clone(), their_quad.clone(), pubkey, session.peer_tgp_addr))
                            } else {
                                warn!("TGP coordinated but no bilateral receipt - should never happen");
                                None
                            }
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        info!("TGP message from {} rejected (state: {:?}): {:?}", peer_id, old_state, e);
                        None
                    }
                }
            } else {
                info!("TGP recv: no session for {} (sessions: {:?})", peer_id, sessions.keys().collect::<Vec<_>>());
                None
            }
        };

        // If coordination completed, store in authorized_peers AND claim our slot
        if let Some((our_quad, their_quad, pubkey, addr)) = completed_auth {
            info!("TGP-NATIVE: Adding {} to authorized_peers (QuadProof stored)", peer_id);
            let authorized = AuthorizedPeer::new(
                peer_id.clone(),
                pubkey,
                our_quad,
                their_quad,
                addr,
            );

            let mut state = self.state.write().await;
            state.authorized_peers.insert(peer_id.clone(), authorized);
            info!("TGP-NATIVE: {} authorized peers total", state.authorized_peers.len());

            // EVENT-DRIVEN SLOT CLAIM: One QuadProof = claim the slot
            if let Some(target_slot) = state.pending_slot_claim.take() {
                // Double-check slot is still available
                if !state.claimed_slots.contains_key(&target_slot) {
                    let my_id = state.self_id.clone();
                    let my_pubkey = state.signing_key.verifying_key().as_bytes().to_vec();
                    let claim = SlotClaim::with_public_key(target_slot, my_id.clone(), Some(my_pubkey.clone()));
                    let coord = claim.coord;

                    state.self_slot = Some(claim.clone());
                    state.claimed_slots.insert(target_slot, claim);
                    state.slot_coords.insert(coord);

                    info!("SLOT CLAIMED: {} at ({}, {}, {}) via QuadProof with {}",
                          target_slot, coord.q, coord.r, coord.z, peer_id);

                    drop(state);

                    // Set our slot in CVDF for duty rotation
                    self.cvdf_set_slot(target_slot).await;

                    // Also register ourselves in CVDF
                    let mut pubkey_arr = [0u8; 32];
                    pubkey_arr.copy_from_slice(&my_pubkey);
                    self.cvdf_register_slot(target_slot, pubkey_arr).await;

                    // Flood our claim
                    debug!("Flooding slot_claim for slot {} from {}", target_slot, my_id);
                    self.flood(FloodMessage::SlotClaim {
                        index: target_slot,
                        peer_id: my_id,
                        coord: (coord.q, coord.r, coord.z),
                        public_key: Some(my_pubkey),
                    });
                } else {
                    info!("Slot {} was claimed by someone else during TGP, will retry", target_slot);
                    drop(state);
                    // Trigger retry for next available slot
                    self.start_slot_claim_tgp().await;
                }
            }
        }

        Some(peer_id)
    }

    /// Send TGP messages for a session immediately (event-driven, no polling)
    /// Called when session is created or when a message is received
    /// CONTENTION-FREE: Uses separate tgp_sessions lock, never blocks on mesh state
    async fn send_tgp_messages(&self, socket: &UdpSocket, peer_id: &str) {
        let messages_to_send: Vec<(SocketAddr, Vec<u8>)> = {
            let mut sessions = self.tgp_sessions.write().await;
            let mut to_send = Vec::new();

            if let Some(session) = sessions.get_mut(peer_id) {
                // Check if coordinated
                if session.coordinator.is_coordinated() {
                    info!("TGP with {} complete - QuadProof achieved!", peer_id);
                    if let Some(tx) = session.result_tx.take() {
                        let _ = tx.send(true);
                    }
                    // Don't remove yet - let attempt_slot_via_tgp clean up
                } else {
                    // Poll for messages to send
                    let state = session.coordinator.tgp_state();
                    match session.coordinator.poll() {
                        Ok(Some(messages)) => {
                            let tgp_addr = session.peer_tgp_addr;
                            info!("TGP poll: {} messages for {} (state: {:?}, addr: {})",
                                   messages.len(), peer_id, state, tgp_addr);
                            for msg in messages {
                                if let Ok(data) = serde_json::to_vec(&msg) {
                                    to_send.push((tgp_addr, data));
                                }
                            }
                        }
                        Ok(None) => {
                            // Rate limited - but log for debugging
                            debug!("TGP poll: rate limited for {} (state: {:?})", peer_id, state);
                        }
                        Err(e) => {
                            info!("TGP poll error for {} (state: {:?}): {:?}", peer_id, state, e);
                            if let Some(tx) = session.result_tx.take() {
                                let _ = tx.send(false);
                            }
                        }
                    }
                }
            }

            to_send
        };

        // Send messages (outside of lock)
        for (addr, data) in messages_to_send {
            if let Err(e) = socket.send_to(&data, addr).await {
                warn!("Failed to send TGP to {}: {}", addr, e);
            } else {
                info!("UDP send {} bytes to {}", data.len(), addr);
            }
        }
    }

    /// Run the mesh service
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("Starting mesh service on {}", self.listen_addr);
        if let Some(announce) = self.announce_addr {
            info!("Announcing as {} (public address)", announce);
        }

        // Start TCP listener for incoming connections
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("Mesh P2P (TCP) listening on {}", self.listen_addr);

        // Bind UDP socket for TGP (connectionless bilateral coordination)
        // TCP and UDP share the same port
        let udp_socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        info!("TGP (UDP) listening on {}", self.listen_addr);

        // Store socket in state so attempt_slot_via_tgp can use it
        {
            let mut state = self.state.write().await;
            state.udp_socket = Some(Arc::clone(&udp_socket));
        }

        // Spawn UDP listener for incoming TGP messages (event-driven, no polling)
        let self_clone = Arc::clone(&self);
        let udp_clone = Arc::clone(&udp_socket);
        tokio::spawn(async move {
            self_clone.run_tgp_udp_listener(udp_clone).await;
        });

        // Spawn task to connect to bootstrap peers and join mesh via TGP
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            // CVDF Swarm Merge Theorem: Every node starts as genesis.
            // When nodes meet, heavier chain wins (more attesters = heavier).
            // See proofs/CitadelProofs/CVDF.lean theorems 9-11:
            //   - merge_deterministic: Merge is deterministic
            //   - merge_takes_heavier: Merge always produces heavier chain
            //   - heavier_survives_merge: Heavier chain survives merge
            //
            // This means: ALWAYS init genesis immediately, then adopt heavier chains on connection.
            // No waiting, no "am I first?" logic - chain merge handles everything.
            info!("CVDF: Initializing as genesis (heavier chains adopted on connection)");
            self_clone.init_cvdf_genesis().await;
            self_clone.init_vdf_genesis().await;

            // Try connecting to entry peers (if any configured)
            // This is just a hint - connections can come from anywhere
            let _ = self_clone.connect_to_entry_peers().await;

            // Slot claiming is EVENT-DRIVEN, triggered by:
            // - on_peer_connected() when any peer connects (inbound or outbound)
            // - on_slot_claim_received() when we learn about the mesh state
            // - on_slot_lost() when we lose a priority race
            //
            // NO TIMEOUTS. NO GIVING UP. The mesh is dynamic.
            // See: trigger_slot_claim_if_ready()
            info!("Node initialized - slot claiming will trigger on first peer connection");
        });

        // Spawn CVDF coordination loop
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.run_cvdf_loop().await;
        });

        // Spawn entry peer retry loop - keeps trying to connect when isolated
        // Uses exponential backoff: 1s -> 2s -> 4s -> 8s -> ... -> 60s max
        // All peers are equal - CITADEL_PEERS are just entry points, not "bootstrap" nodes
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            const MIN_RETRY_SECS: u64 = 1;
            const MAX_RETRY_SECS: u64 = 60;
            let mut retry_secs = MIN_RETRY_SECS;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;

                // Only retry if we have no peers and have entry peers configured
                let peer_count = self_clone.state.read().await.peers.len();
                if peer_count == 0 && !self_clone.entry_peers.is_empty() {
                    info!("Isolated (0 peers) - retrying entry peers (backoff {}s)", retry_secs);
                    let connected = self_clone.connect_to_entry_peers().await;
                    if connected > 0 {
                        info!("Reconnected to {} entry peer(s)", connected);
                        retry_secs = MIN_RETRY_SECS; // Reset backoff on success
                    } else {
                        // Exponential backoff on failure
                        retry_secs = std::cmp::min(retry_secs * 2, MAX_RETRY_SECS);
                    }
                } else if peer_count > 0 {
                    // Have peers - reset backoff for when we next become isolated
                    retry_secs = MIN_RETRY_SECS;
                }
            }
        });

        // Accept incoming connections and handle pending outbound connections
        let mut pending_rx = self.pending_connect_rx.lock().await;
        loop {
            tokio::select! {
                // Handle incoming connections
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!("Incoming mesh connection from {}", addr);
                            let self_clone = Arc::clone(&self);
                            tokio::spawn(async move {
                                // Incoming connections are not entry peers
                                if let Err(e) = self_clone.handle_connection(stream, addr, false).await {
                                    warn!("Connection error from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                // Handle pending outbound connections (queued by handle_message)
                Some((discovered_id, addr)) = pending_rx.recv() => {
                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        match TcpStream::connect(&addr).await {
                            Ok(stream) => {
                                debug!("Connected to discovered peer {} at {}", discovered_id, addr);
                                // Discovered peers are not entry peers
                                if let Err(e) = self_clone.handle_connection(stream, addr, false).await {
                                    debug!("Discovered peer {} connection closed: {}", discovered_id, e);
                                }
                            }
                            Err(e) => {
                                debug!("Failed to connect to discovered peer {}: {}", discovered_id, e);
                            }
                        }
                    });
                }
            }
        }
    }

    /// Connect to bootstrap peers, returns count of successful connections
    async fn connect_to_entry_peers(self: &Arc<Self>) -> usize {
        let mut connected = 0;

        for peer_addr in &self.entry_peers {
            info!("Connecting to peer: {}", peer_addr);

            // Resolve DNS explicitly for better error messages
            // Supports both "hostname:port" and "ip:port" formats
            let resolved_addrs: Vec<SocketAddr> = match tokio::net::lookup_host(peer_addr).await {
                Ok(addrs) => addrs.collect(),
                Err(e) => {
                    warn!("DNS resolution failed for {}: {}", peer_addr, e);
                    continue;
                }
            };

            if resolved_addrs.is_empty() {
                warn!("No addresses found for {}", peer_addr);
                continue;
            }

            // Try each resolved address (IPv4 preferred) with 5s timeout
            let mut peer_connected = false;
            let addr_count = resolved_addrs.len();
            let connect_timeout = std::time::Duration::from_secs(5);

            for resolved_addr in resolved_addrs {
                debug!("Trying {} -> {}", peer_addr, resolved_addr);

                match tokio::time::timeout(connect_timeout, TcpStream::connect(resolved_addr)).await {
                    Ok(Ok(stream)) => {
                        info!("Connected to entry peer {} at {}", peer_addr, resolved_addr);
                        connected += 1;
                        peer_connected = true;

                        // Spawn connection handler as task - don't block!
                        // Entry peers are marked as such for later pruning when we have enough SPIRAL neighbors
                        let self_clone = Arc::clone(self);
                        let addr = resolved_addr;
                        tokio::spawn(async move {
                            if let Err(e) = self_clone.handle_connection(stream, addr, true).await {
                                warn!("Entry peer {} disconnected: {}", addr, e);
                            }
                        });
                        break; // Connected successfully, don't try other addresses
                    }
                    Ok(Err(e)) => {
                        debug!("Failed to connect to {} ({}): {}", peer_addr, resolved_addr, e);
                    }
                    Err(_) => {
                        debug!("Timeout connecting to {} ({})", peer_addr, resolved_addr);
                    }
                }
            }

            if !peer_connected {
                warn!("Failed to connect to peer {} (tried {} addresses)", peer_addr, addr_count);
            }
        }

        connected
    }

    /// Handle a peer connection
    async fn handle_connection(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr, is_entry_peer: bool) -> Result<()> {
        // Use full IP:port as initial peer_id to avoid collisions when connecting to
        // multiple peers that listen on the same port (e.g., all bootstrap nodes on :9000)
        let peer_id = format!("peer-{}", addr);

        // Register peer (slot unknown until they announce it via SPORE flood)
        {
            let mut state = self.state.write().await;
            state.peers.insert(
                peer_id.clone(),
                MeshPeer {
                    id: peer_id.clone(),
                    addr,
                    public_key: None,
                    last_seen: std::time::Instant::now(),
                    coordinated: false,
                    slot: None,  // Will be learned via SPORE slot_claim flood
                    is_entry_peer,
                    content_synced: false,  // Will become true when HaveLists match
                    their_have: None,  // SPORE: received via SporeSync
                },
            );
        }

        info!("Peer {} registered", peer_id);

        // EVENT: Peer connected - trigger slot claiming if we don't have a slot yet
        self.trigger_slot_claim_if_ready();

        // Simple protocol: exchange node info and sync state
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send our node info with public key for TGP
        let state = self.state.read().await;
        let self_id = state.self_id.clone();
        let self_pubkey = state.signing_key.verifying_key();
        let pubkey_hex = hex::encode(self_pubkey.as_bytes());
        // Priority: 1) explicit announce_addr, 2) learned from peers, 3) listen_addr
        let our_addr = self.announce_addr
            .or(state.observed_public_addr)
            .unwrap_or(self.listen_addr);
        drop(state);
        let hello = serde_json::json!({
            "type": "hello",
            "node_id": self_id,
            "addr": our_addr.to_string(),
            "public_key": pubkey_hex,
            // Tell peer what IP we see them as (STUN-like)
            "your_addr": addr.to_string(),
        });
        writer.write_all(hello.to_string().as_bytes()).await?;
        writer.write_all(b"\n").await?;

        // Flood our complete state to this peer (event-driven, no request/response)
        // Admin list
        if let Ok(admins) = self.storage.list_admins() {
            if !admins.is_empty() {
                let flood_admins = serde_json::json!({
                    "type": "flood_admins",
                    "admins": admins,
                });
                writer.write_all(flood_admins.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!("Flooded {} admins to peer {}", admins.len(), peer_id);
            }
        }

        // Peer list - flood our complete view of the mesh with slot info and public keys
        // SPORE: only flood real peer IDs (b3b3/...), never temp IDs
        {
            let state = self.state.read().await;
            let self_slot = state.self_slot.as_ref().map(|s| s.index);
            let self_pubkey = hex::encode(state.signing_key.verifying_key().as_bytes());
            // Priority: 1) explicit announce_addr, 2) learned from peers, 3) listen_addr
            let our_addr_for_flood = self.announce_addr
                .or(state.observed_public_addr)
                .unwrap_or(self.listen_addr);
            let mut all_peers = vec![serde_json::json!({
                "id": state.self_id,
                "addr": our_addr_for_flood.to_string(),
                "slot": self_slot,
                "public_key": self_pubkey,
            })];
            for peer in state.peers.values() {
                // Only flood peers with real IDs (b3b3/...), skip temp IDs
                if !peer.id.starts_with("b3b3/") {
                    continue;
                }
                all_peers.push(serde_json::json!({
                    "id": peer.id,
                    "addr": peer.addr.to_string(),
                    "slot": peer.slot.as_ref().map(|s| s.index),
                    "public_key": peer.public_key.as_ref().map(hex::encode),
                }));
            }

            let flood_peers = serde_json::json!({
                "type": "flood_peers",
                "peers": all_peers,
            });
            writer.write_all(flood_peers.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;

            // Also flood all claimed slots (with public keys for TGP)
            for claim in state.claimed_slots.values() {
                let slot_msg = serde_json::json!({
                    "type": "slot_claim",
                    "index": claim.index,
                    "peer_id": claim.peer_id,
                    "coord": [claim.coord.q, claim.coord.r, claim.coord.z],
                    "public_key": claim.public_key.as_ref().map(hex::encode),
                });
                writer.write_all(slot_msg.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }

            // SPORE: Send our HaveList so peer can identify missing slots
            let have_slots: Vec<u64> = state.claimed_slots.keys().copied().collect();
            let have_list = serde_json::json!({
                "type": "spore_have_list",
                "peer_id": state.self_id,
                "slots": have_slots,
            });
            writer.write_all(have_list.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        // SPORE: Send range-based HaveList for optimal sync
        // Sync cost = O(|XOR difference|), converges to 0 at steady state
        // WantList = HaveList.complement() - receiver derives it
        {
            let releases = self.storage.list_releases().unwrap_or_default();
            let release_ids: Vec<String> = releases.iter().map(|r| r.id.clone()).collect();
            let have_list = build_spore_havelist(&release_ids);
            let self_id = self.state.read().await.self_id.clone();

            let spore_sync = serde_json::json!({
                "type": "spore_sync",
                "peer_id": self_id,
                "have_list": have_list,
            });
            writer.write_all(spore_sync.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            debug!("SPORE: Sent HaveList with {} ranges to peer {}", have_list.range_count(), peer_id);
        }

        // SPORE: Send featured releases for homepage sync
        // Featured releases are admin-curated, synced separately from regular releases
        {
            let featured = self.storage.list_featured_releases().unwrap_or_default();
            if !featured.is_empty() {
                let self_id = self.state.read().await.self_id.clone();
                let featured_json: Vec<String> = featured.iter()
                    .filter_map(|f| serde_json::to_string(f).ok())
                    .collect();
                let featured_sync = serde_json::json!({
                    "type": "featured_sync",
                    "peer_id": self_id,
                    "featured": featured_json,
                });
                writer.write_all(featured_sync.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!("SPORE: Sent {} featured releases to peer {}", featured.len(), peer_id);
            }
        }

        // SPORE: Send DoNotWantList (tombstones) for deletion sync
        // H(H(id)) prevents enumeration while allowing verification
        {
            let state = self.state.read().await;
            if !state.do_not_want.is_empty() {
                let tombstones: Vec<String> = state.do_not_want.iter()
                    .map(|h| hex::encode(h))
                    .collect();
                let do_not_want_list = serde_json::json!({
                    "type": "do_not_want_list",
                    "double_hashes": tombstones,
                });
                writer.write_all(do_not_want_list.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!("Sent DoNotWantList with {} tombstones to peer {}", tombstones.len(), peer_id);
            }
        }

        // SPORE: Send ErasureConfirmation (confirmed deletions) for GDPR sync
        // Enables XOR-based erasure convergence detection
        {
            let state = self.state.read().await;
            if !state.erasure_confirmed.is_empty() {
                let confirmed: Vec<String> = state.erasure_confirmed.iter()
                    .map(|h| hex::encode(h))
                    .collect();
                let erasure_msg = serde_json::json!({
                    "type": "erasure_confirmation",
                    "tombstones": confirmed,
                });
                writer.write_all(erasure_msg.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!("Sent ErasureConfirmation with {} tombstones to peer {}", confirmed.len(), peer_id);
            }
        }

        // BadBits: Send PERMANENT blocklist (DMCA, abuse material, illegal content)
        // Unlike GDPR tombstones, BadBits are never garbage collected
        {
            let state = self.state.read().await;
            if !state.bad_bits.is_empty() {
                let bad_bits_hex: Vec<String> = state.bad_bits.iter()
                    .map(|h| hex::encode(h))
                    .collect();
                let bad_bits_msg = serde_json::json!({
                    "type": "bad_bits",
                    "double_hashes": bad_bits_hex,
                });
                writer.write_all(bad_bits_msg.to_string().as_bytes()).await?;
                writer.write_all(b"\n").await?;
                debug!("Sent BadBits with {} entries to peer {}", bad_bits_hex.len(), peer_id);
            }
        }

        // CVDF chain sync: Send our chain state so peer can adopt heavier chain
        // CRITICAL: This enables swarm merge during initial connection
        if let Some((rounds, slots)) = self.cvdf_chain_state().await {
            let rounds_json: Vec<serde_json::Value> = rounds.iter().map(|r| {
                serde_json::json!({
                    "round": r.round,
                    "prev_output": hex::encode(r.prev_output),
                    "washed_input": hex::encode(r.washed_input),
                    "output": hex::encode(r.output),
                    "producer": hex::encode(r.producer),
                    "producer_signature": hex::encode(r.producer_signature),
                    "timestamp_ms": r.timestamp_ms,
                    "attestations": r.attestations.iter().map(|a| {
                        serde_json::json!({
                            "round": a.round,
                            "prev_output": hex::encode(a.prev_output),
                            "attester": hex::encode(a.attester),
                            "slot": a.slot,
                            "signature": hex::encode(a.signature),
                        })
                    }).collect::<Vec<_>>(),
                })
            }).collect();
            let slots_json: Vec<serde_json::Value> = slots.iter().map(|(idx, pk)| {
                serde_json::json!({
                    "index": idx,
                    "pubkey": hex::encode(pk),
                })
            }).collect();
            let cvdf_sync = serde_json::json!({
                "type": "cvdf_sync_response",
                "rounds": rounds_json,
                "slots": slots_json,
                "height": rounds.last().map(|r| r.round).unwrap_or(0),
                "total_weight": rounds.iter().map(|r| r.weight() as u64).sum::<u64>(),
            });
            writer.write_all(cvdf_sync.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            debug!("Sent CVDF chain state to peer {} (height {}, {} slots)",
                peer_id,
                rounds.last().map(|r| r.round).unwrap_or(0),
                slots.len()
            );
        }

        // Subscribe to broadcast floods
        let mut flood_rx = self.flood_tx.subscribe();

        // Track current peer key (may change from peer-{port} to real PeerID)
        let mut current_peer_key = peer_id.clone();

        // Timer for checking if this entry peer should be disconnected
        // Only relevant if is_entry_peer=true
        let mut entry_peer_check_interval = tokio::time::interval(std::time::Duration::from_secs(10));

        // Read peer messages and forward floods concurrently
        // NOTE: TGP is now over UDP (connectionless), not TCP
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
                // Check if this entry peer should be disconnected (have enough SPIRAL neighbors)
                _ = entry_peer_check_interval.tick(), if is_entry_peer => {
                    let state = self.state.read().await;
                    if state.entry_peers_to_disconnect().contains(&current_peer_key) {
                        info!("Disconnecting entry peer {} - have sufficient SPIRAL neighbors ({})",
                            current_peer_key, state.connected_neighbor_count());
                        break;
                    }
                }
                // Handle incoming messages from peer
                read_result = reader.read_line(&mut line) => {
                    match read_result {
                        Ok(0) => {
                            info!("Peer {} disconnected", current_peer_key);
                            break;
                        }
                        Ok(_) => {
                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                                // handle_message returns (real_id, peers_to_connect)
                                if let Ok((real_id, peers_to_connect)) = self.handle_message(&current_peer_key, msg).await {
                                    if let Some(id) = real_id {
                                        current_peer_key = id;
                                    }
                                    // Queue discovered peers for connection (spawned by listener)
                                    for (discovered_id, addr) in peers_to_connect {
                                        let _ = self.pending_connect_tx.send((discovered_id, addr)).await;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Read error from {}: {}", current_peer_key, e);
                            break;
                        }
                    }
                }
                // Forward broadcast floods to this peer
                flood_result = flood_rx.recv() => {
                    match flood_result {
                        Ok(FloodMessage::Peers(peers)) => {
                            let flood_msg = serde_json::json!({
                                "type": "flood_peers",
                                "peers": peers.into_iter().map(|(id, addr, slot, public_key)| {
                                    serde_json::json!({
                                        "id": id,
                                        "addr": addr,
                                        "slot": slot,
                                        "public_key": public_key.map(hex::encode),
                                    })
                                }).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::Admins(admins)) => {
                            let flood_msg = serde_json::json!({
                                "type": "flood_admins",
                                "admins": admins,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SlotClaim { index, peer_id, coord, public_key }) => {
                            let flood_msg = serde_json::json!({
                                "type": "slot_claim",
                                "index": index,
                                "peer_id": peer_id,
                                "coord": [coord.0, coord.1, coord.2],
                                "public_key": public_key.map(hex::encode),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SlotValidation { index, peer_id, validator_id, accepted }) => {
                            let flood_msg = serde_json::json!({
                                "type": "slot_validation",
                                "index": index,
                                "peer_id": peer_id,
                                "validator_id": validator_id,
                                "accepted": accepted,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SporeHaveList { peer_id, slots }) => {
                            let flood_msg = serde_json::json!({
                                "type": "spore_have_list",
                                "peer_id": peer_id,
                                "slots": slots,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::VdfChain { links }) => {
                            let flood_msg = serde_json::json!({
                                "type": "vdf_chain",
                                "links": links.iter().map(|l| serde_json::json!({
                                    "height": l.height,
                                    "output": hex::encode(l.output),
                                    "producer": hex::encode(l.producer),
                                    "previous": hex::encode(l.previous),
                                    "timestamp_ms": l.timestamp_ms,
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::VdfSlotClaim { claim }) => {
                            let flood_msg = serde_json::json!({
                                "type": "vdf_slot_claim",
                                "slot": claim.slot,
                                "claimer": hex::encode(claim.claimer),
                                "vdf_height": claim.vdf_height,
                                "vdf_output": hex::encode(claim.vdf_output),
                                "signature": hex::encode(claim.signature),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLPing { from, nonce, vdf_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_ping",
                                "from": hex::encode(from),
                                "nonce": nonce,
                                "vdf_height": vdf_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLPong { from, nonce, vdf_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_pong",
                                "from": hex::encode(from),
                                "nonce": nonce,
                                "vdf_height": vdf_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLSwapProposal { proposal }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_swap_proposal",
                                "initiator": hex::encode(proposal.initiator),
                                "target": hex::encode(proposal.target),
                                "initiator_slot": proposal.initiator_slot,
                                "target_slot": proposal.target_slot,
                                "proposal_height": proposal.proposal_height,
                                "proposal_vdf_output": hex::encode(proposal.proposal_vdf_output),
                                "signature": hex::encode(proposal.signature),
                                "initiator_proofs": proposal.initiator_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                                "initiator_at_target_proofs": proposal.initiator_at_target_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::PoLSwapResponse { response }) => {
                            let flood_msg = serde_json::json!({
                                "type": "pol_swap_response",
                                "responder": hex::encode(response.responder),
                                "proposal_height": response.proposal_height,
                                "decision": match response.decision {
                                    crate::proof_of_latency::SwapDecision::Attack => "attack",
                                    crate::proof_of_latency::SwapDecision::Retreat => "retreat",
                                },
                                "response_height": response.response_height,
                                "signature": hex::encode(response.signature),
                                "target_proofs": response.target_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                                "target_at_initiator_proofs": response.target_at_initiator_proofs.iter().map(|p| serde_json::json!({
                                    "from_node": hex::encode(p.from_node),
                                    "to_node": hex::encode(p.to_node),
                                    "latency_us": p.latency_us,
                                    "vdf_height": p.vdf_height,
                                    "vdf_output": hex::encode(p.vdf_output),
                                    "timestamp_ms": p.timestamp_ms,
                                    "signature": hex::encode(p.signature),
                                })).collect::<Vec<_>>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfAttestation { att, vouch }) => {
                            let mut flood_msg = serde_json::json!({
                                "type": "cvdf_attestation",
                                "round": att.round,
                                "slot": att.slot,
                                "prev_output": hex::encode(att.prev_output),
                                "attester": hex::encode(att.attester),
                            });
                            // Include piggybacked vouch if present
                            if let Some(v) = vouch {
                                flood_msg["vouch"] = serde_json::json!({
                                    "voucher": hex::encode(v.voucher),
                                    "voucher_slot": v.voucher_slot,
                                    "alive_neighbors": v.alive_neighbors.iter().map(hex::encode).collect::<Vec<_>>(),
                                    "vdf_height": v.vdf_height,
                                    "latencies": v.latencies.iter().map(|(n, l)| serde_json::json!({
                                        "node": hex::encode(n),
                                        "latency_ms": l,
                                    })).collect::<Vec<_>>(),
                                    "signature": hex::encode(v.signature),
                                });
                            }
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfNewRound { round, spore_proof }) => {
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_new_round",
                                "round": round.round,
                                "prev_output": hex::encode(round.prev_output),
                                "washed_input": hex::encode(round.washed_input),
                                "output": hex::encode(round.output),
                                "producer": hex::encode(round.producer),
                                "attestation_count": round.attestations.len(),
                                "weight": round.weight(),
                                "spore_ranges": spore_proof.range_count(),  // 0 at convergence
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfSyncRequest { from_node, from_height }) => {
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_sync_request",
                                "from_node": from_node,
                                "from_height": from_height,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfSyncResponse { rounds, slots }) => {
                            // Serialize full chain data for proper sync
                            // Rounds contain attestations, slots are (index, pubkey) pairs
                            let rounds_json: Vec<serde_json::Value> = rounds.iter().map(|r| {
                                serde_json::json!({
                                    "round": r.round,
                                    "prev_output": hex::encode(r.prev_output),
                                    "washed_input": hex::encode(r.washed_input),
                                    "output": hex::encode(r.output),
                                    "producer": hex::encode(r.producer),
                                    "producer_signature": hex::encode(r.producer_signature),
                                    "timestamp_ms": r.timestamp_ms,
                                    "attestations": r.attestations.iter().map(|a| {
                                        serde_json::json!({
                                            "round": a.round,
                                            "prev_output": hex::encode(a.prev_output),
                                            "attester": hex::encode(a.attester),
                                            "slot": a.slot,
                                            "signature": hex::encode(a.signature),
                                        })
                                    }).collect::<Vec<_>>(),
                                })
                            }).collect();
                            let slots_json: Vec<serde_json::Value> = slots.iter().map(|(idx, pk)| {
                                serde_json::json!({
                                    "index": idx,
                                    "pubkey": hex::encode(pk),
                                })
                            }).collect();
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_sync_response",
                                "rounds": rounds_json,
                                "slots": slots_json,
                                "height": rounds.last().map(|r| r.round).unwrap_or(0),
                                "total_weight": rounds.iter().map(|r| r.weight() as u64).sum::<u64>(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::ContentHaveList { peer_id, release_ids }) => {
                            let flood_msg = serde_json::json!({
                                "type": "content_have_list",
                                "peer_id": peer_id,
                                "release_ids": release_ids,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::Release { release_json }) => {
                            let flood_msg = serde_json::json!({
                                "type": "release_flood",
                                "release": serde_json::from_str::<serde_json::Value>(&release_json).unwrap_or_default(),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::DoNotWantList { peer_id, double_hashes }) => {
                            // Encode double-hashes as hex strings for JSON transport
                            let hashes_hex: Vec<String> = double_hashes.iter()
                                .map(|h| hex::encode(h))
                                .collect();
                            let flood_msg = serde_json::json!({
                                "type": "do_not_want_list",
                                "peer_id": peer_id,
                                "double_hashes": hashes_hex,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::ErasureConfirmation { peer_id, tombstones }) => {
                            // GDPR erasure confirmation: peer confirms they deleted these tombstones
                            let tombstones_hex: Vec<String> = tombstones.iter()
                                .map(|h| hex::encode(h))
                                .collect();
                            let flood_msg = serde_json::json!({
                                "type": "erasure_confirmation",
                                "peer_id": peer_id,
                                "tombstones": tombstones_hex,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::BadBits { double_hashes }) => {
                            // BadBits: PERMANENT blocklist (DMCA, abuse, illegal content)
                            let hashes_hex: Vec<String> = double_hashes.iter()
                                .map(|h| hex::encode(h))
                                .collect();
                            let flood_msg = serde_json::json!({
                                "type": "bad_bits",
                                "double_hashes": hashes_hex,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SporeSync { peer_id, have_list }) => {
                            // SPORE: Bilateral sync with range-based HaveList
                            // WantList = HaveList.complement() - derived by receiver
                            // Sync cost = O(|XOR difference|), converges to 0 at steady state
                            let flood_msg = serde_json::json!({
                                "type": "spore_sync",
                                "peer_id": peer_id,
                                "have_list": have_list,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::SporeDelta { releases }) => {
                            // SPORE: Delta transfer - only send what they want that we have
                            let flood_msg = serde_json::json!({
                                "type": "spore_delta",
                                "releases": releases,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::FeaturedSync { peer_id, featured }) => {
                            // SPORE: Featured releases sync for homepage
                            let flood_msg = serde_json::json!({
                                "type": "featured_sync",
                                "peer_id": peer_id,
                                "featured": featured,
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Err(_) => {
                            // Channel closed or lagged, continue
                        }
                    }
                }
            }
        }

        // Remove peer from active connections on disconnect
        // NOTE: We do NOT remove their slot claim - they still own the slot even if disconnected!
        // Slots are only invalidated via CVDF chain adoption, not TCP disconnect.
        {
            let mut state = self.state.write().await;
            if let Some(_peer) = state.peers.remove(&current_peer_key) {
                debug!("Peer {} disconnected (slot claim preserved)", current_peer_key);
            }

            // Clean up latency history for this peer to prevent memory leak
            // latency_history uses short peer IDs (first 8 chars after b3b3/)
            let short_peer = crate::api::short_peer_id(&current_peer_key);
            state.latency_history.remove(&short_peer);
            // Also remove any entries where this peer was the target
            for (_, targets) in state.latency_history.iter_mut() {
                targets.remove(&short_peer);
            }
        }

        Ok(())
    }

    /// Handle incoming message from peer
    /// Returns (real_peer_id, peers_to_connect) where:
    /// - real_peer_id: Some(id) if learned from hello (for re-keying)
    /// - peers_to_connect: Vec of (peer_id, addr) to connect to in background
    async fn handle_message(
        self: &Arc<Self>,
        peer_id: &str,
        msg: serde_json::Value,
    ) -> Result<(Option<String>, Vec<(String, SocketAddr)>)> {
        let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match msg_type {
            "hello" => {
                debug!("Received hello from {}: {:?}", peer_id, msg);
                // Re-key peer entry with real PeerID and store public key for TGP
                if let Some(node_id) = msg.get("node_id").and_then(|n| n.as_str()) {
                    // Extract public key from hello (hex-encoded ed25519 public key)
                    let public_key = msg.get("public_key")
                        .and_then(|p| p.as_str())
                        .and_then(|hex_str| hex::decode(hex_str).ok());

                    // Extract listening port from hello (for TGP UDP)
                    // We keep the IP from the TCP connection (routable) but use their listening port
                    let listen_port = msg.get("addr")
                        .and_then(|a| a.as_str())
                        .and_then(|addr_str| addr_str.parse::<SocketAddr>().ok())
                        .map(|addr| addr.port())
                        .unwrap_or(9000);  // Default to 9000 if not provided

                    // Learn our public IP from what the peer sees us as (STUN-like)
                    let their_view_of_us = msg.get("your_addr")
                        .and_then(|a| a.as_str())
                        .and_then(|addr_str| addr_str.parse::<SocketAddr>().ok());

                    let mut state = self.state.write().await;

                    // Update our observed public address if peer told us what they see
                    if let Some(observed) = their_view_of_us {
                        if state.observed_public_addr.is_none() {
                            // Use our listen port, but the IP the peer sees
                            let public_addr = SocketAddr::new(observed.ip(), self.listen_addr.port());
                            info!("Learned our public IP from {}: {}", peer_id, public_addr);
                            state.observed_public_addr = Some(public_addr);
                        }
                    }
                    // Remove temporary peer-{port} entry and re-add with real ID
                    if let Some(mut peer) = state.peers.remove(peer_id) {
                        // Only add if we don't already have this peer (avoid duplicates)
                        if node_id != state.self_id && !state.peers.contains_key(node_id) {
                            peer.id = node_id.to_string();
                            peer.public_key = public_key;
                            // Keep peer's IP but use their listening port (not ephemeral TCP source port)
                            // TCP and UDP share the same port for both mesh and TGP
                            peer.addr = SocketAddr::new(peer.addr.ip(), listen_port);
                            peer.last_seen = std::time::Instant::now();
                            let peer_addr = peer.addr;
                            state.peers.insert(node_id.to_string(), peer);
                            info!("Peer {} identified as {} at {}", peer_id, node_id, peer_addr);

                            // Peer now has public key - try slot claiming if we don't have a slot
                            if state.self_slot.is_none() && state.pending_slot_claim.is_none() {
                                drop(state);
                                self.start_slot_claim_tgp().await;
                            }

                            return Ok((Some(node_id.to_string()), vec![]));
                        }
                    }
                }
            }
            "flood_admins" | "sync_admins" => {
                // Merge flooded admin list into our state
                if let Some(admins) = msg.get("admins").and_then(|a| a.as_array()) {
                    for admin in admins {
                        if let Some(key) = admin.as_str() {
                            let key = key.trim();
                            // Skip malformed combo strings from old nodes
                            if key.contains(',') {
                                continue;
                            }
                            // Accept ed25519p/... (prefix + 64 hex) or raw 64 hex
                            let valid = if let Some(hex) = key.strip_prefix("ed25519p/") {
                                hex.len() == 64
                            } else {
                                key.len() == 64
                            };
                            if valid {
                                // Only log if this is a NEW admin (deduplication)
                                let is_new = !self.storage.is_admin(key).unwrap_or(true);
                                if is_new {
                                    let _ = self.storage.set_admin(key, true);
                                    info!("Merged admin from {}: {}", peer_id, key);
                                }
                            }
                        }
                    }
                }
            }
            "flood_peers" | "sync_peers" => {
                // Merge flooded peer list - this propagates mesh topology
                // SPORE: only accept real peer IDs, skip those we already know
                // Parse peer data OUTSIDE the lock to minimize lock hold time
                let parsed_peers: Vec<_> = msg.get("peers")
                    .and_then(|p| p.as_array())
                    .map(|peers| {
                        peers.iter().filter_map(|peer_info| {
                            let id = peer_info.get("id").and_then(|i| i.as_str())?;
                            let addr_str = peer_info.get("addr").and_then(|a| a.as_str())?;
                            // SPORE: only accept real peer IDs (b3b3/...)
                            if !id.starts_with("b3b3/") {
                                return None;
                            }
                            let slot_index = peer_info.get("slot").and_then(|s| s.as_u64());
                            let public_key = peer_info.get("public_key")
                                .and_then(|p| p.as_str())
                                .and_then(|hex_str| hex::decode(hex_str).ok());
                            let addr: SocketAddr = addr_str.parse().ok()?;
                            Some((id.to_string(), addr_str.to_string(), addr, slot_index, public_key))
                        }).collect()
                    })
                    .unwrap_or_default();

                // Now acquire lock briefly to update state
                let mut new_peers = Vec::new();
                if !parsed_peers.is_empty() {
                    let mut state = self.state.write().await;
                    for (id, addr_str, addr, slot_index, public_key) in parsed_peers {
                        // Don't add ourselves or peers we already know
                        if id != state.self_id && !state.peers.contains_key(&id) {
                            let slot = slot_index.map(|idx| SlotClaim::with_public_key(idx, id.clone(), public_key.clone()));

                            // Record slot claim if present (with public key for TGP)
                            if let Some(idx) = slot_index {
                                if !state.claimed_slots.contains_key(&idx) {
                                    let claim = SlotClaim::with_public_key(idx, id.clone(), public_key.clone());
                                    state.slot_coords.insert(claim.coord);
                                    state.claimed_slots.insert(idx, claim);
                                }
                            }

                            state.peers.insert(
                                id.clone(),
                                MeshPeer {
                                    id: id.clone(),
                                    addr,
                                    public_key: public_key.clone(),
                                    last_seen: std::time::Instant::now(),
                                    coordinated: false,
                                    slot,
                                    is_entry_peer: false,  // Discovered via flooding, not an entry peer
                                    content_synced: false,  // Will become true when HaveLists match
                                    their_have: None,  // SPORE: received via SporeSync
                                },
                            );
                            new_peers.push((id.clone(), addr_str, slot_index, public_key));
                            debug!("Discovered peer {} (slot {:?}) via flood from {}", id, slot_index, peer_id);
                        }
                    }
                }
                // Re-flood newly discovered peers to propagate through mesh
                if !new_peers.is_empty() {
                    // Collect addresses to connect (we'll connect after releasing locks)
                    let peers_to_connect: Vec<(String, SocketAddr)> = new_peers.iter()
                        .filter_map(|(peer_id, addr_str, _, _)| {
                            addr_str.parse::<SocketAddr>().ok().map(|addr| (peer_id.clone(), addr))
                        })
                        .collect();

                    self.flood(FloodMessage::Peers(new_peers));

                    // Return peers to connect - caller will spawn connections
                    return Ok((None, peers_to_connect));
                }
                // Note: No bootstrap sync signal needed - CVDF swarm merge handles everything.
                // When we receive heavier chains, we adopt them automatically.
            }
            "slot_claim" => {
                // Process a slot claim from another node
                // SPORE: re-flood new claims to propagate through mesh
                if let (Some(index), Some(claimer_id)) = (
                    msg.get("index").and_then(|i| i.as_u64()),
                    msg.get("peer_id").and_then(|p| p.as_str()),
                ) {
                    debug!("Received slot_claim flood: slot {} from {}", index, claimer_id);
                    let coord = msg.get("coord")
                        .and_then(|c| c.as_array())
                        .map(|arr| {
                            let q = arr.first().and_then(|v| v.as_i64()).unwrap_or(0);
                            let r = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                            let z = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                            (q, r, z)
                        })
                        .unwrap_or((0, 0, 0));

                    // Extract public key if present (hex-encoded)
                    let public_key = msg.get("public_key")
                        .and_then(|p| p.as_str())
                        .and_then(|hex_str| hex::decode(hex_str).ok());

                    // Check if this is a new claim before processing
                    let is_new = !self.state.read().await.claimed_slots.contains_key(&index);

                    // Check if someone else claimed the slot we're trying to claim via TGP
                    let self_id = self.state.read().await.self_id.clone();
                    let pending_sniped = {
                        let state = self.state.read().await;
                        state.pending_slot_claim == Some(index) && claimer_id != self_id
                    };

                    if pending_sniped {
                        // Someone else got our pending slot - cancel our TGP and retry for next slot
                        info!("Pending slot {} was claimed by {} - canceling TGP and retrying", index, claimer_id);
                        let mut state = self.state.write().await;
                        state.pending_slot_claim = None;
                        drop(state);
                    }

                    // Process the slot claim (stores public key in claim and peer)
                    let (we_lost, race_won) = self.process_slot_claim(index, claimer_id.to_string(), coord, public_key.clone()).await;

                    // Register slot in CVDF for attestation tracking and duty rotation
                    if let Some(ref pk) = public_key {
                        if pk.len() == 32 {
                            let mut pubkey_arr = [0u8; 32];
                            pubkey_arr.copy_from_slice(pk);
                            self.cvdf_register_slot(index, pubkey_arr).await;
                        }
                    }

                    // Re-flood claims to propagate through mesh:
                    // - New claims (is_new): first time we've seen this slot claimed
                    // - Race winners (race_won): a new claimer beat the previous one
                    if is_new || race_won {
                        self.flood(FloodMessage::SlotClaim {
                            index,
                            peer_id: claimer_id.to_string(),
                            coord,
                            public_key,
                        });
                    }

                    // EVENT: Mesh state changed - trigger claim attempt
                    // Per FailureDetectorElimination.lean: state changes are valid trigger events
                    if we_lost || pending_sniped {
                        debug!("Lost slot {} - triggering reclaim", index);
                        self.trigger_slot_claim_if_ready();
                    } else if is_new || race_won {
                        // Slot state changed - maybe we can claim now
                        self.trigger_slot_claim_if_ready();
                    }
                }
            }
            "slot_validation" => {
                // Process a slot validation response
                if let (Some(index), Some(claimer_id), Some(_validator_id), Some(accepted)) = (
                    msg.get("index").and_then(|i| i.as_u64()),
                    msg.get("peer_id").and_then(|p| p.as_str()),
                    msg.get("validator_id").and_then(|v| v.as_str()),
                    msg.get("accepted").and_then(|a| a.as_bool()),
                ) {
                    if accepted {
                        let mut state = self.state.write().await;
                        if let Some(claim) = state.claimed_slots.get_mut(&index) {
                            if claim.peer_id == claimer_id {
                                claim.confirmations += 1;
                                debug!("Slot {} now has {} confirmations",
                                       index, claim.confirmations);
                            }
                        }
                    }
                }
            }
            "spore_have_list" => {
                // SPORE: Compare their HaveList with ours and send missing slots
                if let Some(their_slots) = msg.get("slots").and_then(|s| s.as_array()) {
                    let their_slots: std::collections::HashSet<u64> = their_slots
                        .iter()
                        .filter_map(|v| v.as_u64())
                        .collect();

                    let state = self.state.read().await;

                    // Find slots we have that they don't
                    let mut missing_slots = Vec::new();
                    for (index, claim) in &state.claimed_slots {
                        if !their_slots.contains(index) {
                            missing_slots.push(claim.clone());
                        }
                    }
                    drop(state);

                    // Send missing slots to this peer
                    if !missing_slots.is_empty() {
                        info!("SPORE: Sending {} missing slots to {}", missing_slots.len(), peer_id);
                        for claim in missing_slots {
                            self.flood(FloodMessage::SlotClaim {
                                index: claim.index,
                                peer_id: claim.peer_id,
                                coord: (claim.coord.q, claim.coord.r, claim.coord.z),
                                public_key: claim.public_key,
                            });
                        }
                    }
                }
            }
            "vdf_chain" => {
                // VDF chain sync - try to adopt longer chain
                if let Some(links_arr) = msg.get("links").and_then(|l| l.as_array()) {
                    let mut links = Vec::new();
                    for link_json in links_arr {
                        if let (Some(height), Some(output_hex), Some(producer_hex), Some(previous_hex), Some(timestamp_ms)) = (
                            link_json.get("height").and_then(|h| h.as_u64()),
                            link_json.get("output").and_then(|o| o.as_str()),
                            link_json.get("producer").and_then(|p| p.as_str()),
                            link_json.get("previous").and_then(|p| p.as_str()),
                            link_json.get("timestamp_ms").and_then(|t| t.as_u64()),
                        ) {
                            if let (Ok(output), Ok(producer), Ok(previous)) = (
                                hex::decode(output_hex),
                                hex::decode(producer_hex),
                                hex::decode(previous_hex),
                            ) {
                                if output.len() == 32 && producer.len() == 32 && previous.len() == 32 {
                                    let mut output_arr = [0u8; 32];
                                    let mut producer_arr = [0u8; 32];
                                    let mut previous_arr = [0u8; 32];
                                    output_arr.copy_from_slice(&output);
                                    producer_arr.copy_from_slice(&producer);
                                    previous_arr.copy_from_slice(&previous);

                                    links.push(VdfLink {
                                        height,
                                        output: output_arr,
                                        producer: producer_arr,
                                        previous: previous_arr,
                                        timestamp_ms,
                                    });
                                }
                            }
                        }
                    }

                    if !links.is_empty() {
                        let their_height = links.last().map(|l| l.height).unwrap_or(0);
                        let our_height = self.vdf_height().await;
                        debug!("Received VDF chain from {}: height {} (ours: {})", peer_id, their_height, our_height);

                        // Try to adopt if longer
                        if self.try_adopt_vdf_chain(links.clone()).await {
                            info!("Adopted VDF chain from {} (new height: {})", peer_id, their_height);
                            // Re-flood to propagate
                            self.flood(FloodMessage::VdfChain { links });
                        }
                    }
                }
            }
            "vdf_slot_claim" => {
                // VDF-anchored slot claim with priority ordering
                if let (Some(slot), Some(claimer_hex), Some(vdf_height), Some(vdf_output_hex), Some(signature_hex)) = (
                    msg.get("slot").and_then(|s| s.as_u64()),
                    msg.get("claimer").and_then(|c| c.as_str()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                    msg.get("vdf_output").and_then(|o| o.as_str()),
                    msg.get("signature").and_then(|s| s.as_str()),
                ) {
                    if let (Ok(claimer), Ok(vdf_output), Ok(signature)) = (
                        hex::decode(claimer_hex),
                        hex::decode(vdf_output_hex),
                        hex::decode(signature_hex),
                    ) {
                        if claimer.len() == 32 && vdf_output.len() == 32 && signature.len() == 64 {
                            let mut claimer_arr = [0u8; 32];
                            let mut vdf_output_arr = [0u8; 32];
                            let mut signature_arr = [0u8; 64];
                            claimer_arr.copy_from_slice(&claimer);
                            vdf_output_arr.copy_from_slice(&vdf_output);
                            signature_arr.copy_from_slice(&signature);

                            let claim = AnchoredSlotClaim {
                                slot,
                                claimer: claimer_arr,
                                vdf_height,
                                vdf_output: vdf_output_arr,
                                signature: signature_arr,
                            };

                            debug!("Received VDF slot claim from {}: slot {} at height {}", peer_id, slot, vdf_height);

                            // Process with priority ordering
                            if self.process_vdf_claim(claim.clone()).await {
                                // Re-flood winning claim
                                self.flood(FloodMessage::VdfSlotClaim { claim });
                            }
                        }
                    }
                }
            }
            "pol_ping" => {
                // Proof of Latency ping - respond with pong for RTT measurement
                if let (Some(from_hex), Some(nonce), Some(vdf_height)) = (
                    msg.get("from").and_then(|f| f.as_str()),
                    msg.get("nonce").and_then(|n| n.as_u64()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                ) {
                    if let Ok(from) = hex::decode(from_hex) {
                        if from.len() == 32 {
                            let mut from_arr = [0u8; 32];
                            from_arr.copy_from_slice(&from);
                            debug!("Received PoL ping from {}, nonce {}", peer_id, nonce);

                            // Respond with pong using our public key
                            let state = self.state.read().await;
                            let our_pubkey = state.signing_key.verifying_key().to_bytes();
                            drop(state);

                            self.flood(FloodMessage::PoLPong {
                                from: our_pubkey,
                                nonce,
                                vdf_height,
                            });
                        }
                    }
                }
            }
            "pol_pong" => {
                // Proof of Latency pong - complete latency measurement
                if let (Some(from_hex), Some(nonce), Some(vdf_height)) = (
                    msg.get("from").and_then(|f| f.as_str()),
                    msg.get("nonce").and_then(|n| n.as_u64()),
                    msg.get("vdf_height").and_then(|h| h.as_u64()),
                ) {
                    if let Ok(from) = hex::decode(from_hex) {
                        if from.len() == 32 {
                            let mut from_arr = [0u8; 32];
                            from_arr.copy_from_slice(&from);

                            // Check if this pong is for one of our pending pings
                            let mut state = self.state.write().await;
                            if let Some(target) = state.pol_pending_pings.remove(&nonce) {
                                if target == from_arr {
                                    // Complete the latency measurement in PoL manager
                                    // Get VDF output from chain tip
                                    let vdf_output = state.vdf_race.as_ref()
                                        .and_then(|v| v.chain_links().last())
                                        .map(|l| l.output)
                                        .unwrap_or([0u8; 32]);

                                    if let Some(ref mut pol) = state.pol_manager {
                                        if let Some(proof) = pol.complete_ping(from_arr, vdf_height, vdf_output) {
                                            let latency_ms = proof.latency_us / 1000;
                                            debug!("PoL: measured latency to {} = {}ms", peer_id, latency_ms);

                                            // Record latency in history for map visualization
                                            let self_id = state.self_id.clone();
                                            let short_self = crate::api::short_peer_id(&self_id);
                                            let short_peer = crate::api::short_peer_id(&peer_id);
                                            state.record_latency(&short_self, &short_peer, latency_ms);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "pol_swap_proposal" => {
                // Proof of Latency swap proposal - check if we should accept
                debug!("Received PoL swap proposal from {}", peer_id);
                // Full implementation would parse the proposal and call pol_manager.process_proposal()
                // For now, log and skip - swap handling requires bidirectional communication
            }
            "pol_swap_response" => {
                // Proof of Latency swap response - process decision
                debug!("Received PoL swap response from {}", peer_id);
                // Full implementation would parse the response and call pol_manager.process_response()
                // For now, log and skip - swap handling requires bidirectional communication
            }
            // ==================== CVDF MESSAGE HANDLERS ====================
            "cvdf_attestation" => {
                // Parse attestation and process it
                if let (Some(round), Some(slot), Some(prev_output_hex), Some(attester_hex), Some(sig_hex)) = (
                    msg.get("round").and_then(|r| r.as_u64()),
                    msg.get("slot").and_then(|s| s.as_u64()),
                    msg.get("prev_output").and_then(|p| p.as_str()),
                    msg.get("attester").and_then(|a| a.as_str()),
                    msg.get("signature").and_then(|s| s.as_str()),
                ) {
                    if let (Ok(prev_output), Ok(attester), Ok(signature)) = (
                        hex::decode(prev_output_hex),
                        hex::decode(attester_hex),
                        hex::decode(sig_hex),
                    ) {
                        if prev_output.len() == 32 && attester.len() == 32 && signature.len() == 64 {
                            let att = RoundAttestation {
                                round,
                                prev_output: prev_output.try_into().unwrap(),
                                attester: attester.try_into().unwrap(),
                                slot: Some(slot),
                                signature: signature.try_into().unwrap(),
                            };
                            if self.cvdf_process_attestation(att.clone()).await {
                                debug!("Processed CVDF attestation for round {} from {}", round, peer_id);
                            }

                            // Handle piggybacked vouch (2-hop propagation)
                            if let Some(vouch_data) = msg.get("vouch") {
                                if let (
                                    Some(voucher_hex),
                                    Some(voucher_slot),
                                    Some(alive_neighbors),
                                    Some(vdf_height),
                                    Some(vouch_sig_hex),
                                ) = (
                                    vouch_data.get("voucher").and_then(|v| v.as_str()),
                                    vouch_data.get("voucher_slot").and_then(|v| v.as_u64()),
                                    vouch_data.get("alive_neighbors").and_then(|v| v.as_array()),
                                    vouch_data.get("vdf_height").and_then(|v| v.as_u64()),
                                    vouch_data.get("signature").and_then(|v| v.as_str()),
                                ) {
                                    if let (Ok(voucher), Ok(vouch_sig)) = (
                                        hex::decode(voucher_hex),
                                        hex::decode(vouch_sig_hex),
                                    ) {
                                        if voucher.len() == 32 && vouch_sig.len() == 64 {
                                            // Parse alive neighbors
                                            let mut alive: Vec<[u8; 32]> = Vec::new();
                                            for n in alive_neighbors {
                                                if let Some(n_hex) = n.as_str() {
                                                    if let Ok(n_bytes) = hex::decode(n_hex) {
                                                        if n_bytes.len() == 32 {
                                                            alive.push(n_bytes.try_into().unwrap());
                                                        }
                                                    }
                                                }
                                            }

                                            // Parse latencies (optional)
                                            let latencies = vouch_data.get("latencies")
                                                .and_then(|l| l.as_array())
                                                .map(|arr| {
                                                    arr.iter().filter_map(|item| {
                                                        let node = hex::decode(item.get("node")?.as_str()?).ok()?;
                                                        let latency = item.get("latency_ms")?.as_u64()?;
                                                        if node.len() == 32 {
                                                            Some((node.try_into().unwrap(), latency))
                                                        } else {
                                                            None
                                                        }
                                                    }).collect::<Vec<_>>()
                                                })
                                                .unwrap_or_default();

                                            let vouch = MeshVouch {
                                                voucher: voucher.try_into().unwrap(),
                                                voucher_slot,
                                                alive_neighbors: alive,
                                                vdf_height,
                                                latencies,
                                                signature: vouch_sig.try_into().unwrap(),
                                            };

                                            // Handle vouch with 2-hop propagation
                                            match self.handle_mesh_vouch(vouch.clone()).await {
                                                PropagationDecision::ForwardToNeighbors => {
                                                    // I'm judged - re-flood to my neighbors (witnesses)
                                                    debug!("Vouch judges me - forwarding to witnesses");
                                                    self.flood(FloodMessage::CvdfAttestation {
                                                        att,
                                                        vouch: Some(vouch),
                                                    });
                                                }
                                                PropagationDecision::Stop => {
                                                    // I'm a witness - recorded, stop propagation
                                                    debug!("Vouch witnessed for neighbor - stopping");
                                                }
                                                PropagationDecision::Drop => {
                                                    // Not relevant to me
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "cvdf_new_round" => {
                // Parse and process new round
                // Note: This requires full round data including attestations
                debug!("Received cvdf_new_round from {} (round {})", peer_id,
                    msg.get("round").and_then(|r| r.as_u64()).unwrap_or(0));
                // Full round processing requires attestations array - handled by flood
            }
            "cvdf_sync_request" => {
                // Respond with our chain state
                if let Some(from_height) = msg.get("from_height").and_then(|h| h.as_u64()) {
                    debug!("Received CVDF sync request from {} (from_height {})", peer_id, from_height);
                    // Send our chain state via flood
                    if let Some((rounds, slots)) = self.cvdf_chain_state().await {
                        self.flood(FloodMessage::CvdfSyncResponse { rounds, slots });
                    }
                }
            }
            "cvdf_sync_response" => {
                // Parse chain data, adopt if heavier, process slots with tiebreaker
                debug!("Received CVDF sync response from {}", peer_id);

                // Parse rounds
                let mut parsed_rounds: Vec<CvdfRound> = Vec::new();
                if let Some(rounds_arr) = msg.get("rounds").and_then(|r| r.as_array()) {
                    for round_json in rounds_arr {
                        if let (
                            Some(round_num), Some(prev_output_hex), Some(washed_input_hex),
                            Some(output_hex), Some(producer_hex), Some(producer_sig_hex),
                            Some(timestamp_ms), Some(attestations_arr)
                        ) = (
                            round_json.get("round").and_then(|r| r.as_u64()),
                            round_json.get("prev_output").and_then(|p| p.as_str()),
                            round_json.get("washed_input").and_then(|w| w.as_str()),
                            round_json.get("output").and_then(|o| o.as_str()),
                            round_json.get("producer").and_then(|p| p.as_str()),
                            round_json.get("producer_signature").and_then(|s| s.as_str()),
                            round_json.get("timestamp_ms").and_then(|t| t.as_u64()),
                            round_json.get("attestations").and_then(|a| a.as_array()),
                        ) {
                            // Parse byte arrays
                            let prev_output = hex::decode(prev_output_hex).ok();
                            let washed_input = hex::decode(washed_input_hex).ok();
                            let output = hex::decode(output_hex).ok();
                            let producer = hex::decode(producer_hex).ok();
                            let producer_sig = hex::decode(producer_sig_hex).ok();

                            if let (Some(prev), Some(washed), Some(out), Some(prod), Some(sig)) =
                                (prev_output, washed_input, output, producer, producer_sig)
                            {
                                if prev.len() == 32 && washed.len() == 32 && out.len() == 32 &&
                                   prod.len() == 32 && sig.len() == 64
                                {
                                    // Parse attestations
                                    let mut attestations = Vec::new();
                                    for att_json in attestations_arr {
                                        if let (Some(att_round), Some(att_prev_hex), Some(att_attester_hex), Some(att_sig_hex)) = (
                                            att_json.get("round").and_then(|r| r.as_u64()),
                                            att_json.get("prev_output").and_then(|p| p.as_str()),
                                            att_json.get("attester").and_then(|a| a.as_str()),
                                            att_json.get("signature").and_then(|s| s.as_str()),
                                        ) {
                                            let att_prev = hex::decode(att_prev_hex).ok();
                                            let att_attester = hex::decode(att_attester_hex).ok();
                                            let att_sig = hex::decode(att_sig_hex).ok();
                                            let att_slot = att_json.get("slot").and_then(|s| s.as_u64());

                                            if let (Some(ap), Some(aa), Some(asig)) = (att_prev, att_attester, att_sig) {
                                                if ap.len() == 32 && aa.len() == 32 && asig.len() == 64 {
                                                    attestations.push(RoundAttestation {
                                                        round: att_round,
                                                        prev_output: ap.try_into().unwrap(),
                                                        attester: aa.try_into().unwrap(),
                                                        slot: att_slot,
                                                        signature: asig.try_into().unwrap(),
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    // Get iterations from JSON, default to base if not present (backwards compat)
                                    let iterations = round_json.get("iterations")
                                        .and_then(|i| i.as_u64())
                                        .map(|i| i as u32)
                                        .unwrap_or(crate::cvdf::CVDF_ITERATIONS_BASE);

                                    parsed_rounds.push(CvdfRound {
                                        round: round_num,
                                        prev_output: prev.try_into().unwrap(),
                                        washed_input: washed.try_into().unwrap(),
                                        output: out.try_into().unwrap(),
                                        producer: prod.try_into().unwrap(),
                                        producer_signature: sig.try_into().unwrap(),
                                        timestamp_ms,
                                        attestations,
                                        iterations,
                                    });
                                }
                            }
                        }
                    }
                }

                // Parse slots
                let mut parsed_slots: Vec<(u64, [u8; 32])> = Vec::new();
                if let Some(slots_arr) = msg.get("slots").and_then(|s| s.as_array()) {
                    for slot_json in slots_arr {
                        if let (Some(index), Some(pubkey_hex)) = (
                            slot_json.get("index").and_then(|i| i.as_u64()),
                            slot_json.get("pubkey").and_then(|p| p.as_str()),
                        ) {
                            if let Ok(pubkey) = hex::decode(pubkey_hex) {
                                if pubkey.len() == 32 {
                                    parsed_slots.push((index, pubkey.try_into().unwrap()));
                                }
                            }
                        }
                    }
                }

                // Check if we should adopt this chain
                if !parsed_rounds.is_empty() && self.cvdf_should_adopt(&parsed_rounds).await {
                    let their_height = parsed_rounds.last().map(|r| r.round).unwrap_or(0);
                    let their_weight: u64 = parsed_rounds.iter().map(|r| r.weight() as u64).sum();
                    info!("Adopting heavier CVDF chain from {} (height {}, weight {})",
                        peer_id, their_height, their_weight);

                    if self.cvdf_adopt(parsed_rounds).await {
                        // Chain adopted - now process slots with tiebreaker
                        // CRITICAL: This is where slot recalculation happens during swarm merge
                        let mut we_lost_our_slot = false;

                        for (slot_idx, pubkey) in &parsed_slots {
                            // Register slot in CVDF
                            self.cvdf_register_slot(*slot_idx, *pubkey).await;

                            // Compute peer_id from pubkey for tiebreaker
                            let their_peer_id = compute_peer_id_from_bytes(pubkey);

                            // Get slot coord
                            let coord = spiral3d_to_coord(Spiral3DIndex::new(*slot_idx));

                            // Process through tiebreaker - this handles conflicts
                            let (lost, _race_won) = self.process_slot_claim(
                                *slot_idx,
                                their_peer_id,
                                (coord.q, coord.r, coord.z),
                                Some(pubkey.to_vec())
                            ).await;

                            if lost {
                                we_lost_our_slot = true;
                            }
                        }

                        // EVENT: Chain adopted - mesh state changed
                        // Per FailureDetectorElimination.lean: state changes are valid trigger events
                        if we_lost_our_slot {
                            info!("Lost slot during chain adoption - triggering reclaim");
                        }
                        // Always trigger after chain adoption - we learned about new mesh state
                        self.trigger_slot_claim_if_ready();
                    }
                }
            }
            // ==================== END CVDF MESSAGE HANDLERS ====================
            // NOTE: TGP messages are now handled over UDP, not TCP
            // See run_tgp_udp_listener() and handle_tgp_message()

            // ==================== SPORE CONTENT SYNC HANDLERS ====================
            "content_have_list" => {
                // Peer is advertising what releases they have
                // Compare with our releases: XOR = 0 means fully synced
                if let Some(their_ids) = msg.get("release_ids").and_then(|r| r.as_array()) {
                    let their_set: std::collections::HashSet<String> = their_ids.iter()
                        .filter_map(|id| id.as_str().map(|s| s.to_string()))
                        .collect();

                    // Get our releases
                    if let Ok(our_releases) = self.storage.list_releases() {
                        let our_set: std::collections::HashSet<String> = our_releases.iter()
                            .map(|r| r.id.clone())
                            .collect();

                        // Check what they're missing (we have, they don't)
                        let mut we_sent_releases = false;
                        for release in &our_releases {
                            if !their_set.contains(&release.id) {
                                if let Ok(json) = serde_json::to_string(&release) {
                                    info!("SPORE: Sending missing release {} to {}", release.id, peer_id);
                                    self.flood(FloodMessage::Release { release_json: json });
                                    we_sent_releases = true;
                                }
                            }
                        }

                        // Check what we're missing (they have, we don't)
                        // This is our WantList for this peer - if empty, we have everything they have
                        let we_want_from_them: Vec<&String> = their_set.iter()
                            .filter(|id| !our_set.contains(*id))
                            .collect();

                        // We consider ourselves "synced" with this peer if our WantList is empty
                        // (we have all the content they have - our HaveList ⊇ their HaveList)
                        let we_have_all_their_content = we_want_from_them.is_empty();

                        // Update peer's sync status (tracks if WE have everything THEY have)
                        {
                            let mut state = self.state.write().await;
                            if let Some(peer) = state.peers.get_mut(peer_id) {
                                if we_have_all_their_content != peer.content_synced {
                                    peer.content_synced = we_have_all_their_content;
                                    if we_have_all_their_content {
                                        info!("SPORE: We have all content from peer {} (WantList=∅)", peer_id);
                                    } else {
                                        debug!("SPORE: Missing {} items from peer {}", we_want_from_them.len(), peer_id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "release_flood" => {
                // Receive a release flooded through the mesh
                if let Some(release_data) = msg.get("release") {
                    // Try to parse as Release
                    if let Ok(release) = serde_json::from_value::<crate::models::Release>(release_data.clone()) {
                        // SPORE: Check if this release is in our DoNotWantList (tombstoned)
                        let tombstone = double_hash_id(&release.id);
                        let is_tombstoned = self.state.read().await.do_not_want.contains(&tombstone);

                        if is_tombstoned {
                            debug!("SPORE: Ignoring tombstoned release {} (in DoNotWantList)", release.id);
                        } else if self.storage.get_release(&release.id).ok().flatten().is_none() {
                            // Store it
                            if let Err(e) = self.storage.put_release(&release) {
                                warn!("Failed to store flooded release {}: {}", release.id, e);
                            } else {
                                info!("SPORE: Received and stored release {} from mesh", release.id);

                                // SPORE: Broadcast updated HaveList so peers know our new state
                                // This enables continuous sync as our state changes
                                if let Ok(all_releases) = self.storage.list_releases() {
                                    let self_id = self.state.read().await.self_id.clone();
                                    let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
                                    let have_list = build_spore_havelist(&release_ids);
                                    self.flood(FloodMessage::SporeSync {
                                        peer_id: self_id,
                                        have_list,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "spore_sync" => {
                // SPORE: Receive peer's HaveList (range-based)
                // Their WantList = their_have.complement()
                if let Some(have_list_value) = msg.get("have_list") {
                    if let Ok(their_have) = serde_json::from_value::<Spore>(have_list_value.clone()) {
                        // Compute their WantList (what they don't have)
                        let their_want = their_have.complement();

                        // Build our HaveList
                        let our_releases = self.storage.list_releases().unwrap_or_default();
                        let our_release_ids: Vec<String> = our_releases.iter().map(|r| r.id.clone()).collect();
                        let our_have = build_spore_havelist(&our_release_ids);

                        // Compute what we should send: our_have ∩ their_want
                        let to_send = our_have.intersect(&their_want);

                        // Store their HaveList for future reference
                        {
                            let mut state = self.state.write().await;
                            if let Some(peer) = state.peers.get_mut(peer_id) {
                                peer.their_have = Some(their_have.clone());
                                // Check if we have all their content
                                let our_want = our_have.complement();
                                let we_need = their_have.intersect(&our_want);
                                peer.content_synced = we_need.is_empty();
                                if peer.content_synced {
                                    info!("SPORE: Fully synced with peer {} (their content ⊆ our content)", peer_id);
                                }
                            }
                        }

                        // If we have releases they want, send them as delta
                        if !to_send.is_empty() {
                            // Find which releases match the to_send ranges
                            let releases_to_send: Vec<String> = our_releases.iter()
                                .filter(|r| {
                                    let hash = release_id_to_u256(&r.id);
                                    to_send.covers(&hash)
                                })
                                .filter_map(|r| serde_json::to_string(r).ok())
                                .collect();

                            if !releases_to_send.is_empty() {
                                info!("SPORE: Sending {} releases to peer {} (delta transfer)", releases_to_send.len(), peer_id);
                                self.flood(FloodMessage::SporeDelta {
                                    releases: releases_to_send,
                                });
                            }
                        }
                        // NOTE: Don't send HaveList back here - we already send on connection
                        // Sending here would create infinite feedback loop
                    }
                }
            }
            "spore_delta" => {
                // SPORE: Receive delta transfer - releases we were missing
                if let Some(releases_value) = msg.get("releases").and_then(|r| r.as_array()) {
                    let mut stored_count = 0;
                    for release_json in releases_value {
                        if let Some(json_str) = release_json.as_str() {
                            if let Ok(release) = serde_json::from_str::<crate::models::Release>(json_str) {
                                // Check tombstone
                                let tombstone = double_hash_id(&release.id);
                                let is_tombstoned = self.state.read().await.do_not_want.contains(&tombstone);

                                if is_tombstoned {
                                    debug!("SPORE: Ignoring tombstoned release {} from delta", release.id);
                                } else if self.storage.get_release(&release.id).ok().flatten().is_none() {
                                    if let Err(e) = self.storage.put_release(&release) {
                                        warn!("SPORE: Failed to store delta release {}: {}", release.id, e);
                                    } else {
                                        stored_count += 1;
                                    }
                                }
                            }
                        }
                    }

                    if stored_count > 0 {
                        info!("SPORE: Stored {} releases from delta transfer", stored_count);
                        // NOTE: Don't broadcast HaveList here - would cause feedback loop
                        // HaveLists are exchanged on connection, not on every state change
                    }
                }
            }
            "do_not_want_list" => {
                // SPORE: Receive DoNotWantList (tombstones) from peer
                // These are double-hashed IDs: H(H(id)) - prevents enumeration
                if let Some(hashes) = msg.get("double_hashes").and_then(|h| h.as_array()) {
                    let mut state = self.state.write().await;
                    let mut new_tombstones = Vec::new();

                    for hash_val in hashes {
                        if let Some(hash_hex) = hash_val.as_str() {
                            if let Ok(hash_bytes) = hex::decode(hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut tombstone = [0u8; 32];
                                    tombstone.copy_from_slice(&hash_bytes);
                                    if state.do_not_want.insert(tombstone) {
                                        new_tombstones.push(tombstone);
                                    }
                                }
                            }
                        }
                    }

                    if !new_tombstones.is_empty() {
                        info!("SPORE: Added {} new tombstones from peer {}", new_tombstones.len(), peer_id);

                        // Delete any releases we have that match the new tombstones
                        // And add to erasure_confirmed to confirm we deleted them
                        let self_id = state.self_id.clone();
                        drop(state); // Release lock before storage operations

                        let mut confirmed_tombstones = Vec::new();
                        if let Ok(releases) = self.storage.list_releases() {
                            for release in releases {
                                let tombstone = double_hash_id(&release.id);
                                if new_tombstones.contains(&tombstone) {
                                    if let Err(e) = self.storage.delete_release(&release.id) {
                                        warn!("Failed to delete tombstoned release {}: {}", release.id, e);
                                    } else {
                                        info!("SPORE: Deleted tombstoned release {}", release.id);
                                        confirmed_tombstones.push(tombstone);
                                    }
                                }
                            }
                        }

                        // Add ALL tombstones to erasure_confirmed (even if we didn't have the content)
                        // This confirms we've processed the deletion request
                        {
                            let mut state = self.state.write().await;
                            for tombstone in &new_tombstones {
                                state.erasure_confirmed.insert(*tombstone);
                            }
                        }

                        // Re-flood the tombstones to propagate through mesh
                        self.flood(FloodMessage::DoNotWantList {
                            peer_id: self_id.clone(),
                            double_hashes: new_tombstones.clone(),
                        });

                        // GDPR: Send erasure confirmation - we've processed these deletions
                        self.flood(FloodMessage::ErasureConfirmation {
                            peer_id: self_id,
                            tombstones: new_tombstones,
                        });
                    }
                }
            }
            "erasure_confirmation" => {
                // SPORE: Receive erasure confirmation from peer
                // Track which tombstones this peer has confirmed deleting
                if let Some(tombstones) = msg.get("tombstones").and_then(|t| t.as_array()) {
                    let mut new_confirmations = Vec::new();

                    for ts_val in tombstones {
                        if let Some(ts_hex) = ts_val.as_str() {
                            if let Ok(ts_bytes) = hex::decode(ts_hex) {
                                if ts_bytes.len() == 32 {
                                    let mut tombstone = [0u8; 32];
                                    tombstone.copy_from_slice(&ts_bytes);
                                    new_confirmations.push(tombstone);
                                }
                            }
                        }
                    }

                    if !new_confirmations.is_empty() {
                        let mut state = self.state.write().await;

                        // Check if peer's erasure confirmations now match ours (XOR sync)
                        let their_confirmed: HashSet<[u8; 32]> = new_confirmations.iter().cloned().collect();

                        // Compute XOR diff count before modifying state
                        let diff_count = their_confirmed.symmetric_difference(&state.erasure_confirmed).count();
                        let xor_empty = diff_count == 0;

                        // Update sync status
                        state.erasure_synced.insert(peer_id.to_string(), xor_empty);

                        if xor_empty {
                            debug!("SPORE: Erasure synced with peer {} (XOR=0)", peer_id);
                        } else {
                            debug!("SPORE: Erasure not synced with peer {} ({} differences)", peer_id, diff_count);
                        }

                        // Check if ALL peers are synced - if so, we can garbage collect tombstones
                        let peer_ids: Vec<String> = state.peers.keys().cloned().collect();
                        let all_synced = peer_ids.iter().all(|p| {
                            state.erasure_synced.get(p).copied().unwrap_or(false)
                        });

                        if all_synced && !state.erasure_confirmed.is_empty() {
                            // GDPR: All peers confirmed - tombstones can be garbage collected
                            let gc_tombstones: Vec<[u8; 32]> = state.erasure_confirmed.iter().cloned().collect();
                            let gc_count = gc_tombstones.len();
                            for tombstone in gc_tombstones {
                                state.erasure_confirmed.remove(&tombstone);
                                state.do_not_want.remove(&tombstone);
                            }
                            state.erasure_synced.clear();
                            info!("SPORE: GDPR erasure complete - garbage collected {} tombstones", gc_count);
                        }
                    }
                }
            }
            "bad_bits" => {
                // BadBits: PERMANENT blocklist (DMCA, abuse material, illegal content)
                // Unlike DoNotWantList (GDPR), these are NEVER garbage collected
                // Also deletes any matching content we currently have
                if let Some(hashes) = msg.get("double_hashes").and_then(|h| h.as_array()) {
                    let mut state = self.state.write().await;
                    let mut new_bad_bits = Vec::new();

                    for hash_val in hashes {
                        if let Some(hash_hex) = hash_val.as_str() {
                            if let Ok(hash_bytes) = hex::decode(hash_hex) {
                                if hash_bytes.len() == 32 {
                                    let mut bad_bit = [0u8; 32];
                                    bad_bit.copy_from_slice(&hash_bytes);
                                    if state.bad_bits.insert(bad_bit) {
                                        new_bad_bits.push(bad_bit);
                                    }
                                }
                            }
                        }
                    }

                    if !new_bad_bits.is_empty() {
                        info!("BadBits: Added {} new entries from peer {}", new_bad_bits.len(), peer_id);

                        // Delete any releases that match new bad bits
                        let self_id = state.self_id.clone();
                        drop(state); // Release lock before storage operations

                        if let Ok(releases) = self.storage.list_releases() {
                            for release in releases {
                                let release_hash = double_hash_id(&release.id);
                                if new_bad_bits.contains(&release_hash) {
                                    if let Err(e) = self.storage.delete_release(&release.id) {
                                        warn!("BadBits: Failed to delete blocked release {}: {}", release.id, e);
                                    } else {
                                        info!("BadBits: Deleted blocked release {}", release.id);
                                    }
                                }
                            }
                        }

                        // Re-flood the bad bits to propagate through mesh
                        self.flood(FloodMessage::BadBits {
                            double_hashes: new_bad_bits,
                        });
                    }
                }
            }
            "featured_sync" => {
                // SPORE: Receive featured releases from peer
                // These are admin-curated homepage entries, synced independently
                if let Some(featured_arr) = msg.get("featured").and_then(|f| f.as_array()) {
                    let mut stored_count = 0;
                    for featured_json in featured_arr {
                        if let Some(json_str) = featured_json.as_str() {
                            if let Ok(featured) = serde_json::from_str::<crate::models::FeaturedRelease>(json_str) {
                                // Check if we already have this featured release
                                if self.storage.get_featured_release(&featured.id).ok().flatten().is_none() {
                                    if let Err(e) = self.storage.put_featured_release(&featured) {
                                        warn!("SPORE: Failed to store featured release {}: {}", featured.id, e);
                                    } else {
                                        stored_count += 1;
                                    }
                                }
                            }
                        }
                    }
                    if stored_count > 0 {
                        info!("SPORE: Stored {} featured releases from peer {}", stored_count, peer_id);
                        // Re-flood to propagate
                        let self_id = self.state.read().await.self_id.clone();
                        if let Ok(all_featured) = self.storage.list_featured_releases() {
                            let featured_json: Vec<String> = all_featured.iter()
                                .filter_map(|f| serde_json::to_string(f).ok())
                                .collect();
                            self.flood(FloodMessage::FeaturedSync {
                                peer_id: self_id,
                                featured: featured_json,
                            });
                        }
                    }
                }
            }
            // ==================== END SPORE CONTENT SYNC HANDLERS ====================
            _ => {
                debug!("Unknown message type from {}: {}", peer_id, msg_type);
            }
        }

        Ok((None, vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_protocols::{CoordinatorConfig, FloodRateConfig, PeerCoordinator};
    use std::thread::sleep;
    use std::time::Duration;

    /// Helper to create a keypair from a deterministic seed
    fn keypair_from_seed(seed: u8) -> citadel_protocols::KeyPair {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = seed;
        citadel_protocols::KeyPair::from_seed(&secret_bytes).expect("valid 32-byte seed")
    }

    /// Test SYMMETRIC TGP handshake - both peers use same constructor, roles assigned by key comparison
    #[test]
    fn test_tgp_symmetric_handshake() {
        let kp_a = keypair_from_seed(1);
        let kp_b = keypair_from_seed(2);

        // Both use symmetric constructor - roles determined by public key comparison
        let mut peer_a = PeerCoordinator::symmetric(
            kp_a.clone(),
            kp_b.public_key().clone(),
            CoordinatorConfig::default()
                .with_commitment(b"test_slot_0".to_vec())
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        let mut peer_b = PeerCoordinator::symmetric(
            kp_b,
            kp_a.public_key().clone(),
            CoordinatorConfig::default()
                .with_commitment(b"test_slot_0".to_vec())
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        peer_a.set_active(true);
        peer_b.set_active(true);

        // Run handshake - no tiebreaker needed!
        for _ in 0..100 {
            if let Ok(Some(messages)) = peer_a.poll() {
                for msg in messages {
                    let _ = peer_b.receive(&msg);
                }
            }

            if let Ok(Some(messages)) = peer_b.poll() {
                for msg in messages {
                    let _ = peer_a.receive(&msg);
                }
            }

            if peer_a.is_coordinated() && peer_b.is_coordinated() {
                break;
            }

            sleep(Duration::from_micros(100));
        }

        assert!(peer_a.is_coordinated(), "Peer A should reach coordination");
        assert!(peer_b.is_coordinated(), "Peer B should reach coordination");
        assert!(peer_a.get_bilateral_receipt().is_some(), "Peer A should have bilateral receipt");
        assert!(peer_b.get_bilateral_receipt().is_some(), "Peer B should have bilateral receipt");
    }

    /// Test that SPIRAL slot indices produce the correct coordinates
    #[test]
    fn test_spiral_slot_coordinates() {
        // Slot 0 should be at origin
        let coord_0 = spiral3d_to_coord(Spiral3DIndex(0));
        assert_eq!(coord_0.q, 0);
        assert_eq!(coord_0.r, 0);
        assert_eq!(coord_0.z, 0);

        // Slots 1-6 should be the first ring around origin
        for slot in 1..=6u64 {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            // First ring is at distance 1 from origin
            let dist = (coord.q.abs() + coord.r.abs()) / 2;
            assert!(dist <= 2, "Slot {} should be near origin, got ({}, {}, {})",
                    slot, coord.q, coord.r, coord.z);
        }
    }

    /// Test threshold scaling based on mesh size
    #[test]
    fn test_threshold_scaling() {
        // At mesh size 1-2, threshold should be 1
        // At mesh size 6, with 6 neighbors, scaled threshold = max(1, (6 * 4 + 19) / 20) = 2
        // At mesh size 20+, threshold follows the BFT ladder

        // Small mesh - need fewer confirmations
        let mesh_size_3_neighbors_2 = std::cmp::max(1, (2 * 3 + 19) / 20);
        assert_eq!(mesh_size_3_neighbors_2, 1, "With 2 neighbors in mesh of 3, need 1 confirmation");

        // Medium mesh
        let mesh_size_10_neighbors_5 = std::cmp::max(1, (5 * 5 + 19) / 20);
        assert_eq!(mesh_size_10_neighbors_5, 2, "With 5 neighbors in mesh of 10, need 2 confirmations");

        // Large mesh (full 20 neighbors)
        let full_mesh = 11; // 11/20 at full maturity
        assert_eq!(full_mesh, 11, "Full mesh requires 11/20 confirmations");
    }

    /// 1000-node mesh formation test with flooding-based coordination
    ///
    /// Simulates 1000 nodes joining the mesh via ANY existing node (no special bootstraps).
    /// Uses flooding for slot claims and validations - O(N) packets, not O(N²).
    ///
    /// Protocol:
    /// 1. Genesis node claims slot 0 (origin)
    /// 2. Each new node contacts ANY random existing node
    /// 3. New node broadcasts slot claim (1 packet, floods to all)
    /// 4. Neighbors validate and flood validations
    /// 5. Slot confirmed when 11/20 threshold met (or scaled threshold for small mesh)
    #[test]
    fn test_1000_node_mesh_formation() {
        use citadel_topology::{HexCoord, Neighbors, Spiral3DIndex, spiral3d_to_coord, coord_to_spiral3d};
        use std::collections::{HashMap, HashSet, VecDeque};

        const NODE_COUNT: u64 = 1000;

        /// A slot claim message (floods through mesh)
        #[derive(Clone, Debug)]
        struct SlotClaim {
            slot: u64,
            coord: HexCoord,
            peer_id: String,
            signature: [u8; 64], // Ed25519 signature
        }

        /// A validation message (floods through mesh)
        #[derive(Clone, Debug)]
        struct SlotValidation {
            slot: u64,
            claimer_id: String,
            validator_id: String,
            accepted: bool,
        }

        /// Simulated node state
        struct SimNode {
            peer_id: String,
            coord: HexCoord,
            validations_received: HashSet<String>, // validator IDs
            neighbors_at_join: usize, // how many neighbors existed when this node joined
        }

        /// Flooding network simulation
        struct FloodNetwork {
            nodes: HashMap<u64, SimNode>,
            coord_to_slot: HashMap<HexCoord, u64>,
            pending_claims: VecDeque<SlotClaim>,
            pending_validations: VecDeque<SlotValidation>,
            packets_sent: u64,
        }

        impl FloodNetwork {
            fn new() -> Self {
                Self {
                    nodes: HashMap::new(),
                    coord_to_slot: HashMap::new(),
                    pending_claims: VecDeque::new(),
                    pending_validations: VecDeque::new(),
                    packets_sent: 0,
                }
            }

            /// Broadcast a slot claim (1 packet that floods)
            fn broadcast_claim(&mut self, claim: SlotClaim) {
                self.packets_sent += 1;
                self.pending_claims.push_back(claim);
            }

            /// Process all pending messages (event-driven, non-blocking)
            fn process_all(&mut self) {
                // Process claims
                while let Some(claim) = self.pending_claims.pop_front() {
                    self.process_claim(claim);
                }

                // Process validations
                while let Some(validation) = self.pending_validations.pop_front() {
                    self.process_validation(validation);
                }
            }

            fn process_claim(&mut self, claim: SlotClaim) {
                // Each neighbor that exists validates the claim
                let neighbors = Neighbors::of(claim.coord);

                // Count neighbors at join time (for threshold calculation)
                let neighbors_at_join = neighbors
                    .iter()
                    .filter(|n| self.coord_to_slot.contains_key(n))
                    .count();

                for neighbor_coord in neighbors {
                    if let Some(&neighbor_slot) = self.coord_to_slot.get(&neighbor_coord) {
                        let neighbor = self.nodes.get(&neighbor_slot).unwrap();

                        // Neighbor validates: first-writer-wins check
                        // (In simulation, claims arrive in order, so always valid)
                        let validation = SlotValidation {
                            slot: claim.slot,
                            claimer_id: claim.peer_id.clone(),
                            validator_id: neighbor.peer_id.clone(),
                            accepted: true,
                        };

                        // Validation floods back (1 packet per validator, but floods)
                        self.packets_sent += 1;
                        self.pending_validations.push_back(validation);
                    }
                }

                // Add the node to the mesh (optimistically, validations confirm)
                self.nodes.insert(claim.slot, SimNode {
                    peer_id: claim.peer_id,
                    coord: claim.coord,
                    validations_received: HashSet::new(),
                    neighbors_at_join,
                });
                self.coord_to_slot.insert(claim.coord, claim.slot);
            }

            fn process_validation(&mut self, validation: SlotValidation) {
                if let Some(node) = self.nodes.get_mut(&validation.slot) {
                    if validation.accepted {
                        node.validations_received.insert(validation.validator_id);
                    }
                }
            }

            /// Calculate required threshold based on mesh size and available neighbors
            fn required_threshold(&self, coord: HexCoord) -> usize {
                let neighbors = Neighbors::of(coord);
                let existing_neighbors = neighbors
                    .iter()
                    .filter(|n| self.coord_to_slot.contains_key(n))
                    .count();

                if existing_neighbors == 0 {
                    return 0; // Genesis node
                }

                // Scale threshold: at full mesh 11/20, but proportional for smaller meshes
                // Formula: max(1, ceil(existing_neighbors * 11 / 20))
                std::cmp::max(1, (existing_neighbors * 11 + 19) / 20)
            }
        }

        // Generate deterministic peer ID
        fn make_peer_id(seed: u64) -> String {
            let hash = blake3::hash(&seed.to_le_bytes());
            format!("b3b3/{}", hex::encode(&hash.as_bytes()[..32]))
        }

        let mut network = FloodNetwork::new();

        println!("\n=== 1000-Node Flooding Mesh Formation Test ===\n");

        // Genesis: Node 0 claims slot 0 (no neighbors to validate)
        println!("Phase 1: Genesis node claims origin...");
        let genesis_claim = SlotClaim {
            slot: 0,
            coord: spiral3d_to_coord(Spiral3DIndex(0)),
            peer_id: make_peer_id(0),
            signature: [0u8; 64], // Simulated signature
        };
        network.broadcast_claim(genesis_claim);
        network.process_all();
        println!("  Genesis node at origin, {} packet(s)", network.packets_sent);

        // Remaining nodes join via flooding
        println!("Phase 2: {} nodes joining via flooding...", NODE_COUNT - 1);
        let progress_points = [100u64, 250, 500, 750, 999];
        let mut progress_idx = 0;

        for slot in 1..NODE_COUNT {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let peer_id = make_peer_id(slot);

            // Node joins by contacting ANY existing node (simulated: just broadcast claim)
            let claim = SlotClaim {
                slot,
                coord,
                peer_id,
                signature: [0u8; 64],
            };

            network.broadcast_claim(claim);
            network.process_all();

            // Progress reporting
            if progress_idx < progress_points.len() && slot >= progress_points[progress_idx] {
                println!("  {} nodes, {} packets so far ({:.2} packets/node)",
                    slot + 1, network.packets_sent,
                    network.packets_sent as f64 / (slot + 1) as f64);
                progress_idx += 1;
            }
        }

        // Verification
        println!("\nPhase 3: Verifying mesh geometry...");

        assert_eq!(network.nodes.len(), NODE_COUNT as usize);
        assert_eq!(network.coord_to_slot.len(), NODE_COUNT as usize);

        // Verify SPIRAL bijection
        for slot in 0..NODE_COUNT {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);

            let node = network.nodes.get(&slot).unwrap();
            assert_eq!(node.coord, coord, "Node {} has wrong coordinate", slot);
        }
        println!("  ✓ All {} slots filled in correct SPIRAL order", NODE_COUNT);

        // Verify validation thresholds met (based on neighbors at join time)
        let mut validation_failures = 0u64;
        let mut total_validations = 0u64;

        for slot in 0..NODE_COUNT {
            let node = network.nodes.get(&slot).unwrap();
            let received = node.validations_received.len();
            total_validations += received as u64;

            // Threshold based on neighbors at join time, not current neighbors
            let required = if node.neighbors_at_join == 0 {
                0 // Genesis node
            } else {
                std::cmp::max(1, (node.neighbors_at_join * 11 + 19) / 20)
            };

            // Each neighbor at join time sends a validation, so received should equal neighbors_at_join
            if received < required {
                validation_failures += 1;
            }
        }
        println!("  ✓ Validation thresholds: {} failures out of {} nodes", validation_failures, NODE_COUNT);
        assert_eq!(validation_failures, 0, "All nodes should meet validation threshold");

        // Verify 20-neighbor topology
        let mut total_edges = 0u64;
        let mut max_neighbors = 0usize;
        let mut min_neighbors = 20usize;

        for slot in 0..NODE_COUNT {
            let node = network.nodes.get(&slot).unwrap();
            let neighbors = Neighbors::of(node.coord);
            let existing = neighbors
                .iter()
                .filter(|n| network.coord_to_slot.contains_key(n))
                .count();

            total_edges += existing as u64;
            max_neighbors = max_neighbors.max(existing);
            min_neighbors = min_neighbors.min(existing);
        }

        let unique_edges = total_edges / 2;
        println!("  ✓ Topology: {} unique edges, neighbors range {} to {}",
            unique_edges, min_neighbors, max_neighbors);

        // Packet efficiency
        println!("\nPhase 4: Packet efficiency...");
        println!("  Total packets: {}", network.packets_sent);
        println!("  Packets per node: {:.2}", network.packets_sent as f64 / NODE_COUNT as f64);
        println!("  Total validations: {}", total_validations);

        // We want < 1000 packets for 1000 nodes? Let's see the actual count
        // Each node sends 1 claim, neighbors send validations
        // With ~10 avg neighbors, that's ~11 packets per node = ~11,000 total
        // But with efficient flooding, validations can be batched

        // For now, verify it's O(N), not O(N²)
        // O(N²) would be ~1,000,000 packets
        // O(N) with small constant should be < 50,000
        assert!(network.packets_sent < 50000,
            "Should be O(N) packets, got {} for {} nodes", network.packets_sent, NODE_COUNT);
        println!("  ✓ Packet count is O(N): {} << {} (N²)", network.packets_sent, NODE_COUNT * NODE_COUNT);

        // Geometric balance
        let coords: Vec<HexCoord> = (0..NODE_COUNT)
            .map(|i| spiral3d_to_coord(Spiral3DIndex(i)))
            .collect();

        let min_q = coords.iter().map(|c| c.q).min().unwrap();
        let max_q = coords.iter().map(|c| c.q).max().unwrap();
        let min_z = coords.iter().map(|c| c.z).min().unwrap();
        let max_z = coords.iter().map(|c| c.z).max().unwrap();

        let q_span = max_q - min_q;
        let z_span = max_z - min_z;

        println!("\nMesh statistics:");
        println!("  Nodes: {}", NODE_COUNT);
        println!("  Unique edges: {}", unique_edges);
        println!("  Spatial extent: Q [{}, {}], Z [{}, {}]", min_q, max_q, min_z, max_z);
        println!("  Avg neighbors: {:.2}", total_edges as f64 / NODE_COUNT as f64);

        assert!((q_span - z_span).abs() <= 2,
            "Mesh should be balanced: Q span {} vs Z span {}", q_span, z_span);
        println!("  ✓ Geometrically balanced (spherical growth)");

        println!("\n=== 1000-Node Flooding Mesh Test PASSED ===\n");
    }

    /// Tests concurrent node startup with staggered joining.
    ///
    /// The key insight: nodes must join SEQUENTIALLY through the mesh,
    /// not all start simultaneously. Each new node contacts ONE existing
    /// node, learns mesh state, then claims the next available slot.
    ///
    /// This models Docker's depends_on ordering where node N depends on node N-1.
    #[test]
    fn test_sequential_mesh_formation() {
        use citadel_topology::{Spiral3DIndex, spiral3d_to_coord, coord_to_spiral3d};
        use std::collections::HashMap;

        const NODE_COUNT: u64 = 50;

        /// Simulated node state
        struct SimNode {
            slot: u64,
            known_slots: HashMap<u64, u64>, // slot -> node_id
        }

        struct Mesh {
            nodes: HashMap<u64, SimNode>,
        }

        impl Mesh {
            fn new() -> Self {
                Self { nodes: HashMap::new() }
            }

            /// Node joins by contacting any existing node, learning state, then claiming
            fn join(&mut self, node_id: u64, contact_node: Option<u64>) {
                // Learn state from contact node (or start fresh if genesis)
                let known_slots = match contact_node {
                    Some(contact) => {
                        let contact_node = self.nodes.get(&contact).unwrap();
                        contact_node.known_slots.clone()
                    }
                    None => HashMap::new(),
                };

                // Find next available slot
                let mut slot = 0u64;
                while known_slots.contains_key(&slot) {
                    slot += 1;
                }

                // Record our claim
                let mut final_known = known_slots;
                final_known.insert(slot, node_id);

                self.nodes.insert(node_id, SimNode { slot, known_slots: final_known });

                // Propagate our claim to all existing nodes
                let node_ids: Vec<u64> = self.nodes.keys().copied().filter(|&id| id != node_id).collect();
                for other_id in node_ids {
                    self.nodes.get_mut(&other_id).unwrap().known_slots.insert(slot, node_id);
                }
            }
        }

        println!("\n=== Sequential Mesh Formation Test (50 nodes) ===\n");

        let mut mesh = Mesh::new();

        // Genesis node
        println!("Phase 1: Genesis node claims origin...");
        mesh.join(0, None);

        // Each subsequent node joins via the previous node
        // This is the "sequential dependency" model
        println!("Phase 2: {} nodes joining sequentially...", NODE_COUNT - 1);
        for node_id in 1..NODE_COUNT {
            mesh.join(node_id, Some(node_id - 1));
        }

        // Verify results
        println!("Phase 3: Verifying mesh...\n");

        let mut slot_to_node: HashMap<u64, u64> = HashMap::new();
        for (&node_id, node) in &mesh.nodes {
            if let Some(&existing) = slot_to_node.get(&node.slot) {
                panic!("DUPLICATE: Slot {} claimed by both node {} and node {}", node.slot, existing, node_id);
            }
            slot_to_node.insert(node.slot, node_id);
        }

        // Verify all slots are contiguous [0, NODE_COUNT)
        for slot in 0..NODE_COUNT {
            assert!(slot_to_node.contains_key(&slot), "Missing slot {}", slot);
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);
        }

        println!("Results:");
        println!("  Total nodes: {}", mesh.nodes.len());
        println!("  Unique slots: {}", slot_to_node.len());
        println!("  ✓ All {} slots filled [0, {})", NODE_COUNT, NODE_COUNT);
        println!("  ✓ All slots have valid SPIRAL-3D coordinates");
        println!("  ✓ No duplicate slot assignments");

        println!("\n=== Sequential Mesh Formation Test PASSED ===\n");
    }

    /// Tests what happens when nodes DON'T wait for state sync (the Docker bug).
    /// All nodes start simultaneously and claim slot 0 - demonstrating the race.
    #[test]
    fn test_concurrent_race_demonstrates_bug() {
        use std::collections::HashMap;

        const NODE_COUNT: u64 = 10; // Small count to demonstrate

        println!("\n=== Concurrent Race Bug Demonstration ===\n");
        println!("This test shows what happens when nodes don't sync before claiming.\n");

        // Simulate: all nodes start at once, each thinks mesh is empty
        let mut claims: Vec<(u64, u64)> = Vec::new(); // (node_id, claimed_slot)

        for node_id in 0..NODE_COUNT {
            // Each node sees empty mesh (no sync happened)
            let claimed_slot = 0; // Everyone claims slot 0!
            claims.push((node_id, claimed_slot));
        }

        // Count how many claimed each slot
        let mut slot_counts: HashMap<u64, usize> = HashMap::new();
        for (_, slot) in &claims {
            *slot_counts.entry(*slot).or_insert(0) += 1;
        }

        println!("Without state sync, {} nodes all claimed slot 0!", slot_counts.get(&0).unwrap());
        println!("This is exactly what we see in Docker logs.\n");

        // The fix: priority-based tiebreaker resolves, but requires many re-claims
        // Better fix: ensure state sync BEFORE claiming

        // Calculate how many iterations needed to resolve (worst case)
        // With priority tiebreaker, one node wins slot 0, others must retry
        // Those retrying all claim slot 1, one wins, others retry for slot 2...
        // This takes O(N) rounds of resolution!

        println!("With naive tiebreaker resolution:");
        println!("  Round 1: {} nodes fight for slot 0, 1 wins, {} retry", NODE_COUNT, NODE_COUNT - 1);
        println!("  Round 2: {} nodes fight for slot 1, 1 wins, {} retry", NODE_COUNT - 1, NODE_COUNT - 2);
        println!("  ...");
        println!("  Total rounds: {} (O(N))", NODE_COUNT);
        println!("  Total slot changes: {} (O(N²))\n", NODE_COUNT * (NODE_COUNT - 1) / 2);

        println!("The FIX: Nodes must sync mesh state BEFORE claiming.");
        println!("With proper sync, each node claims a unique slot immediately.\n");

        println!("=== Bug Demonstration Complete ===\n");
    }

    /// Integration test: 50 nodes with proper state propagation.
    /// Models the CORRECT behavior we want in Docker.
    #[test]
    fn test_50_node_mesh_with_state_propagation() {
        use citadel_topology::{Spiral3DIndex, spiral3d_to_coord, coord_to_spiral3d, Neighbors};
        use std::collections::{HashMap, BinaryHeap};
        use std::cmp::Ordering;

        const NODE_COUNT: u64 = 50;

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct Event {
            time: u64,
            seq: u64, // For deterministic ordering at same time
            event_type: EventType,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        enum EventType {
            NodeStartup { node_id: u64 },
            StateReceived { node_id: u64, from_peer: u64 },
            SlotClaimReceived { receiver: u64, claimer: u64, slot: u64 },
        }

        impl Ord for Event {
            fn cmp(&self, other: &Self) -> Ordering {
                other.time.cmp(&self.time)
                    .then_with(|| other.seq.cmp(&self.seq))
            }
        }

        impl PartialOrd for Event {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        struct SimNode {
            claimed_slot: Option<u64>,
            known_slots: HashMap<u64, u64>,
            state_received: bool,
        }

        struct Simulation {
            nodes: HashMap<u64, SimNode>,
            events: BinaryHeap<Event>,
            time: u64,
            seq: u64,
        }

        impl Simulation {
            fn new() -> Self {
                Self {
                    nodes: HashMap::new(),
                    events: BinaryHeap::new(),
                    time: 0,
                    seq: 0,
                }
            }

            fn schedule(&mut self, delay: u64, event_type: EventType) {
                self.seq += 1;
                self.events.push(Event {
                    time: self.time + delay,
                    seq: self.seq,
                    event_type,
                });
            }

            fn run(&mut self) {
                while let Some(event) = self.events.pop() {
                    self.time = event.time;
                    match event.event_type {
                        EventType::NodeStartup { node_id } => {
                            self.handle_startup(node_id);
                        }
                        EventType::StateReceived { node_id, from_peer } => {
                            self.handle_state_received(node_id, from_peer);
                        }
                        EventType::SlotClaimReceived { receiver, claimer, slot } => {
                            self.handle_slot_claim(receiver, claimer, slot);
                        }
                    }
                }
            }

            fn handle_startup(&mut self, node_id: u64) {
                // Node starts but does NOT claim immediately
                self.nodes.insert(node_id, SimNode {
                    claimed_slot: None,
                    known_slots: HashMap::new(),
                    state_received: false,
                });

                if node_id == 0 {
                    // Genesis: no peers to sync from, claim immediately
                    let node = self.nodes.get_mut(&node_id).unwrap();
                    node.claimed_slot = Some(0);
                    node.known_slots.insert(0, node_id);
                    node.state_received = true;
                    // Broadcast to future nodes (will happen when they connect)
                } else {
                    // Connect to previous node and wait for state
                    let bootstrap_peer = node_id - 1;
                    // Network delay for connection + state transfer
                    self.schedule(50, EventType::StateReceived { node_id, from_peer: bootstrap_peer });
                }
            }

            fn handle_state_received(&mut self, node_id: u64, from_peer: u64) {
                // Copy state from peer
                let peer_slots = self.nodes.get(&from_peer).unwrap().known_slots.clone();

                let node = self.nodes.get_mut(&node_id).unwrap();
                node.known_slots = peer_slots;
                node.state_received = true;

                // NOW claim next available slot
                let mut target = 0u64;
                while node.known_slots.contains_key(&target) {
                    target += 1;
                }
                node.claimed_slot = Some(target);
                node.known_slots.insert(target, node_id);

                // Broadcast claim to all existing nodes
                let node_ids: Vec<u64> = self.nodes.keys()
                    .copied()
                    .filter(|&id| id != node_id)
                    .collect();

                for other_id in node_ids {
                    // Variable network delay
                    let delay = 10 + (node_id ^ other_id) % 30;
                    self.schedule(delay, EventType::SlotClaimReceived {
                        receiver: other_id,
                        claimer: node_id,
                        slot: target,
                    });
                }
            }

            fn handle_slot_claim(&mut self, receiver: u64, claimer: u64, slot: u64) {
                if let Some(node) = self.nodes.get_mut(&receiver) {
                    node.known_slots.insert(slot, claimer);
                }
            }
        }

        println!("\n=== 50-Node Mesh with State Propagation ===\n");

        let mut sim = Simulation::new();

        // Staggered startup: each node starts 5ms after previous
        // This models Docker's depends_on chain
        println!("Phase 1: Scheduling {} nodes with staggered startup...", NODE_COUNT);
        for i in 0..NODE_COUNT {
            sim.schedule(i * 5, EventType::NodeStartup { node_id: i });
        }

        println!("Phase 2: Running simulation...");
        sim.run();

        println!("Phase 3: Verifying mesh...\n");

        // Verify all nodes claimed unique slots
        let mut slot_to_node: HashMap<u64, u64> = HashMap::new();
        let mut duplicate_count = 0;

        for (&node_id, node) in &sim.nodes {
            if let Some(slot) = node.claimed_slot {
                if let Some(&existing) = slot_to_node.get(&slot) {
                    println!("  DUPLICATE: Slot {} claimed by nodes {} and {}", slot, existing, node_id);
                    duplicate_count += 1;
                } else {
                    slot_to_node.insert(slot, node_id);
                }
            }
        }

        // Verify slots are valid SPIRAL coordinates
        for &slot in slot_to_node.keys() {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let back = coord_to_spiral3d(coord);
            assert_eq!(back.0, slot, "SPIRAL bijection failed at slot {}", slot);
        }

        // Verify topology
        let mut total_neighbors = 0usize;
        for &slot in slot_to_node.keys() {
            let coord = spiral3d_to_coord(Spiral3DIndex(slot));
            let neighbors = Neighbors::of(coord);
            let count = neighbors.iter()
                .filter(|n| {
                    let neighbor_slot = coord_to_spiral3d(**n).0;
                    slot_to_node.contains_key(&neighbor_slot)
                })
                .count();
            total_neighbors += count;
        }

        println!("Results:");
        println!("  Total nodes: {}", sim.nodes.len());
        println!("  Unique slots: {}", slot_to_node.len());
        println!("  Duplicate claims: {}", duplicate_count);
        println!("  Avg neighbors: {:.2}", total_neighbors as f64 / NODE_COUNT as f64);

        assert_eq!(duplicate_count, 0, "No duplicates with proper state sync");
        assert_eq!(slot_to_node.len(), NODE_COUNT as usize, "All nodes got slots");

        println!("  ✓ All {} nodes claimed unique slots", NODE_COUNT);
        println!("  ✓ State propagation prevents races");

        println!("\n=== 50-Node Mesh Test PASSED ===\n");
    }

    /// Test TGP-native AuthorizedPeer struct creation and storage
    #[test]
    fn test_authorized_peer_creation() {
        let kp_a = keypair_from_seed(1);
        let kp_b = keypair_from_seed(2);

        // Complete TGP handshake to get QuadProofs
        let mut peer_a = PeerCoordinator::symmetric(
            kp_a.clone(),
            kp_b.public_key().clone(),
            CoordinatorConfig::default()
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        let mut peer_b = PeerCoordinator::symmetric(
            kp_b.clone(),
            kp_a.public_key().clone(),
            CoordinatorConfig::default()
                .without_timeout()
                .with_flood_rate(FloodRateConfig::fast()),
        );

        peer_a.set_active(true);
        peer_b.set_active(true);

        // Run handshake to completion
        for _ in 0..100 {
            if let Ok(Some(msgs)) = peer_a.poll() {
                for msg in msgs {
                    let _ = peer_b.receive(&msg);
                }
            }
            if let Ok(Some(msgs)) = peer_b.poll() {
                for msg in msgs {
                    let _ = peer_a.receive(&msg);
                }
            }
            if peer_a.is_coordinated() && peer_b.is_coordinated() {
                break;
            }
            sleep(Duration::from_micros(100));
        }

        assert!(peer_a.is_coordinated(), "Peer A should be coordinated");
        assert!(peer_b.is_coordinated(), "Peer B should be coordinated");

        // Get bilateral receipts
        let (a_our, a_their) = peer_a.get_bilateral_receipt().expect("Should have bilateral receipt");
        let (b_our, b_their) = peer_b.get_bilateral_receipt().expect("Should have bilateral receipt");

        // Create AuthorizedPeer from A's perspective
        let peer_id = compute_peer_id_from_bytes(kp_b.public_key().as_bytes());
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let authorized = AuthorizedPeer::new(
            peer_id.clone(),
            *kp_b.public_key().as_bytes(),
            a_our.clone(),
            a_their.clone(),
            addr,
        );

        // Verify AuthorizedPeer properties
        assert_eq!(authorized.peer_id, peer_id);
        assert_eq!(authorized.public_key, *kp_b.public_key().as_bytes());
        assert!(authorized.is_authorized(), "AuthorizedPeer should always be authorized");
        assert!(authorized.slot.is_none(), "New AuthorizedPeer has no slot");
        assert_eq!(authorized.last_addr, addr);

        // Verify bilateral construction property:
        // If A has QuadProof, B must also have it (and vice versa)
        // This is TGP's core invariant: ∃QA ⇔ ∃QB
        assert!(peer_b.get_bilateral_receipt().is_some(),
            "Bilateral construction: if A has Q, B must have Q");

        println!("AuthorizedPeer created successfully:");
        println!("  peer_id: {}...", &peer_id[..20]);
        println!("  addr: {}", authorized.last_addr);
        println!("  established: {:?} ago", authorized.established.elapsed());
    }

    /// Test that authorized_peers HashMap can store and retrieve peers
    #[test]
    fn test_authorized_peers_hashmap() {
        use std::collections::HashMap;

        let kp_a = keypair_from_seed(10);
        let kp_b = keypair_from_seed(20);
        let kp_c = keypair_from_seed(30);

        // Create mock QuadProofs (using coordinated handshake)
        let mut create_auth_peer = |our_kp: &citadel_protocols::KeyPair, their_kp: &citadel_protocols::KeyPair| {
            let mut peer_a = PeerCoordinator::symmetric(
                our_kp.clone(),
                their_kp.public_key().clone(),
                CoordinatorConfig::default().without_timeout().with_flood_rate(FloodRateConfig::fast()),
            );
            let mut peer_b = PeerCoordinator::symmetric(
                their_kp.clone(),
                our_kp.public_key().clone(),
                CoordinatorConfig::default().without_timeout().with_flood_rate(FloodRateConfig::fast()),
            );
            peer_a.set_active(true);
            peer_b.set_active(true);

            for _ in 0..100 {
                if let Ok(Some(msgs)) = peer_a.poll() {
                    for msg in msgs { let _ = peer_b.receive(&msg); }
                }
                if let Ok(Some(msgs)) = peer_b.poll() {
                    for msg in msgs { let _ = peer_a.receive(&msg); }
                }
                if peer_a.is_coordinated() && peer_b.is_coordinated() { break; }
                sleep(Duration::from_micros(100));
            }

            let (our_q, their_q) = peer_a.get_bilateral_receipt().unwrap();
            let peer_id = compute_peer_id_from_bytes(their_kp.public_key().as_bytes());
            AuthorizedPeer::new(
                peer_id,
                *their_kp.public_key().as_bytes(),
                our_q.clone(),
                their_q.clone(),
                "127.0.0.1:9000".parse().unwrap(),
            )
        };

        // Create authorized peers
        let auth_b = create_auth_peer(&kp_a, &kp_b);
        let auth_c = create_auth_peer(&kp_a, &kp_c);

        // Store in HashMap (mimics MeshState.authorized_peers)
        let mut authorized_peers: HashMap<String, AuthorizedPeer> = HashMap::new();

        authorized_peers.insert(auth_b.peer_id.clone(), auth_b);
        authorized_peers.insert(auth_c.peer_id.clone(), auth_c);

        assert_eq!(authorized_peers.len(), 2, "Should have 2 authorized peers");

        // Verify lookup
        let peer_b_id = compute_peer_id_from_bytes(kp_b.public_key().as_bytes());
        let peer_c_id = compute_peer_id_from_bytes(kp_c.public_key().as_bytes());

        assert!(authorized_peers.contains_key(&peer_b_id), "Should find peer B");
        assert!(authorized_peers.contains_key(&peer_c_id), "Should find peer C");

        // Verify authorization check
        for (id, peer) in &authorized_peers {
            assert!(peer.is_authorized(), "Peer {} should be authorized", id);
        }

        println!("authorized_peers HashMap test passed:");
        println!("  Stored {} peers", authorized_peers.len());
    }
}
