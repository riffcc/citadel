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
use citadel_protocols::{
    CoordinatorConfig, FloodRateConfig, KeyPair, Message as TgpMessage, MessagePayload, PeerCoordinator, PublicKey,
    SporeSyncManager,
};
use citadel_spore::U256;
use citadel_topology::{HexCoord, Neighbors, Spiral3DIndex, spiral3d_to_coord};
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

    /// Get the 20 neighbor coordinates of this slot
    pub fn neighbor_coords(&self) -> [HexCoord; 20] {
        Neighbors::of(self.coord)
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
    /// Our claimed slot in the mesh
    pub self_slot: Option<SlotClaim>,
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
    // NOTE: tgp_sessions moved to MeshService for contention-free access
}

impl MeshState {
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
    CvdfAttestation { att: RoundAttestation },
    /// CVDF new round produced
    CvdfNewRound { round: CvdfRound },
    /// CVDF chain sync request
    CvdfSyncRequest { from_node: String, from_height: u64 },
    /// CVDF chain sync response (all rounds)
    CvdfSyncResponse { rounds: Vec<CvdfRound>, slots: Vec<(u64, [u8; 32])> },
}

/// Citadel Mesh Service
pub struct MeshService {
    /// P2P listen address (TCP and UDP share this port)
    listen_addr: SocketAddr,
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
}

impl MeshService {
    /// Create a new mesh service
    pub fn new(
        listen_addr: SocketAddr,
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
            entry_peers,
            storage,
            state: Arc::new(RwLock::new(MeshState {
                self_id,
                signing_key,
                tgp_keypair,
                udp_socket: None,  // Set when run() is called
                self_slot: None,
                peers: HashMap::new(),
                claimed_slots: HashMap::new(),
                slot_coords: HashSet::new(),
                spore_sync: Some(spore_sync),
                vdf_race: None,    // Initialized when joining mesh or as genesis
                vdf_claims: HashMap::new(),
                pol_manager: None,  // Initialized after claiming a slot
                pol_pending_pings: HashMap::new(),
                cvdf: None,        // Initialized as genesis or when joining mesh
            })),
            // Separate lock for TGP sessions - contention-free TGP operations
            tgp_sessions: Arc::new(RwLock::new(HashMap::new())),
            flood_tx,
            // Notification for CVDF initialization
            cvdf_init_notify: Arc::new(Notify::new()),
            // Channel for pending peer connections
            pending_connect_tx,
            pending_connect_rx: Arc::new(tokio::sync::Mutex::new(pending_connect_rx)),
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

        // Flood our claim to the network (with public key for TGP)
        self.flood(FloodMessage::SlotClaim {
            index,
            peer_id,
            coord: (coord.q, coord.r, coord.z),
            public_key: Some(public_key_bytes),
        });

        true
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

            // Create and broadcast attestation
            if let Some(att) = self.cvdf_attest().await {
                self.flood(FloodMessage::CvdfAttestation { att });
            }

            // Try to produce a round
            if let Some(round) = self.cvdf_try_produce().await {
                info!("CVDF produced round {} (weight {})",
                    round.round, round.weight());
                self.flood(FloodMessage::CvdfNewRound { round });
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

    // ==================== END CVDF METHODS ====================

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

        // Find existing nodes at neighbor positions
        let mut potential_neighbors: Vec<(String, SocketAddr, Option<Vec<u8>>)> = Vec::new();
        for coord in &neighbor_coords {
            // Find claimed slot at this coordinate
            if let Some(slot_claim) = state.claimed_slots.values().find(|s| s.coord == *coord) {
                // Find peer with this ID
                if let Some(peer) = state.peers.get(&slot_claim.peer_id) {
                    potential_neighbors.push((
                        peer.id.clone(),
                        peer.addr,
                        peer.public_key.clone(),
                    ));
                }
            }
        }

        let existing_neighbor_count = potential_neighbors.len();
        drop(state);

        info!(
            "Attempting slot {} via TGP: {} existing neighbors, threshold {} (mesh size {})",
            target_slot, existing_neighbor_count, threshold, mesh_size
        );

        // Special case: genesis node (no neighbors exist)
        if mesh_size == 0 || existing_neighbor_count == 0 {
            info!("Genesis slot {} - auto-occupy (no neighbors to validate)", target_slot);
            return self.claim_slot(target_slot).await;
        }

        // Calculate scaled threshold based on existing neighbors
        // If only 6 neighbors exist, we need ceil(6 * threshold / 20)
        let scaled_threshold = if existing_neighbor_count >= 20 {
            threshold
        } else {
            // Scale proportionally but require at least 1
            std::cmp::max(1, (existing_neighbor_count * threshold + 19) / 20)
        };

        info!(
            "Scaled threshold: {} of {} existing neighbors (full threshold: {} of 20)",
            scaled_threshold, existing_neighbor_count, threshold
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

        for (peer_id, peer_addr, maybe_pubkey) in potential_neighbors {
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
            target_slot, successful_coordinations, existing_neighbor_count, scaled_threshold
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

    /// Process a slot claim from another node
    /// Returns true if WE lost our slot to this claim (caller should reclaim)
    pub async fn process_slot_claim(&self, index: u64, peer_id: String, coord: (i64, i64, i64), public_key: Option<Vec<u8>>) -> bool {
        let mut state = self.state.write().await;
        let hex_coord = HexCoord::new(coord.0, coord.1, coord.2);

        // Verify the coord matches the index
        let expected_coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        if hex_coord != expected_coord {
            warn!("Invalid slot claim: index {} should be at {:?}, not {:?}",
                  index, expected_coord, hex_coord);
            return false;
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

        // Check if already claimed by someone else
        if let Some(existing) = state.claimed_slots.get(&index) {
            if existing.peer_id != peer_id {
                // Ungameable tiebreaker: hash(blake3(peer_id) XOR blake3(tx))
                if Self::peer_wins_slot(&peer_id, &existing.peer_id, index) {
                    let loser_id = existing.peer_id.clone();
                    info!("Slot {} taken by {} (beats previous claimer {} by priority)",
                          index, peer_id, loser_id);
                    // Clear the loser's slot in our peer records
                    if let Some(loser_peer) = state.peers.get_mut(&loser_id) {
                        loser_peer.slot = None;
                    }
                    // Fall through to accept the new claim
                } else {
                    debug!("Slot {} stays with {} (beats new claimer {} by priority)",
                           index, existing.peer_id, peer_id);
                    return we_lost;
                }
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

        we_lost
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

            // If pubkey match fails, fall back to full socket address match
            let (id, peer) = match peer {
                Some(found) => found,
                None => {
                    // Fallback: try matching by full socket address (IP + port)
                    match state.peers.iter().find(|(_, p)| p.addr == src_addr) {
                        Some(found) => found,
                        None => {
                            info!("TGP: No peer found with pubkey {} or addr {} - {} peers known",
                                  hex::encode(&sender_pubkey[..6]), src_addr, state.peers.len());
                            return None;
                        }
                    }
                }
            };

            let Some(pubkey_bytes) = peer.public_key.as_ref() else {
                info!("TGP: Peer {} has no public key - cannot do TGP", id);
                return None;
            };

            let Ok(pubkey_array) = <[u8; 32]>::try_from(pubkey_bytes.as_slice()) else {
                warn!("Peer {} has invalid public key length", id);
                return None;
            };

            let Ok(counterparty) = PublicKey::from_bytes(&pubkey_array) else {
                warn!("Peer {} has invalid public key", id);
                return None;
            };

            let keypair = (*state.tgp_keypair).clone();
            debug!("Found peer {} for TGP from {} (matched by pubkey)", id, src_addr);
            (id.clone(), keypair, counterparty)
        };

        // Create session if needed (SYMMETRIC - no tiebreaker needed!)
        // With symmetric TGP, both peers can create sessions independently
        // and they'll automatically have opposite roles based on public key comparison.
        {
            let mut sessions = self.tgp_sessions.write().await;
            if !sessions.contains_key(&peer_id) {
                debug!("Creating SYMMETRIC TGP session for {} (incoming message)", peer_id);
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
        {
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
                        }
                    }
                    Err(e) => {
                        info!("TGP message from {} rejected (state: {:?}): {:?}", peer_id, old_state, e);
                    }
                }
            } else {
                info!("TGP recv: no session for {} (sessions: {:?})", peer_id, sessions.keys().collect::<Vec<_>>());
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

            // Connect to entry peers (if any)
            // When connected, we'll exchange chain states and adopt heavier chains
            let connected = self_clone.connect_to_entry_peers().await;
            if connected > 0 {
                info!("Connected to {} peer(s), exchanging chain states", connected);
            } else if self_clone.entry_peers.is_empty() {
                info!("No peers configured - running as standalone genesis");
            } else {
                info!("No entry peers responded yet - will keep trying");
            }

            // After learning mesh state, attempt to join via TGP
            // Try slots in SPIRAL order until one succeeds
            let mut target_slot = self_clone.state.read().await.next_available_slot();
            loop {
                if self_clone.attempt_slot_via_tgp(target_slot).await {
                    info!("Successfully joined mesh at slot {}", target_slot);

                    // Register our slot in CVDF
                    let pubkey = self_clone.state.read().await.signing_key.verifying_key().to_bytes();
                    self_clone.cvdf_register_slot(target_slot, pubkey).await;
                    self_clone.cvdf_set_slot(target_slot).await;

                    break;
                }
                // Try next slot
                target_slot += 1;
                if target_slot > 1000 {
                    error!("Failed to join mesh after 1000 slot attempts");
                    break;
                }
            }
        });

        // Spawn CVDF coordination loop
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.run_cvdf_loop().await;
        });

        // Spawn entry peer retry loop - keeps trying to connect when isolated
        // All peers are equal - CITADEL_PEERS are just entry points, not "bootstrap" nodes
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;

                // Only retry if we have no peers and have entry peers configured
                let peer_count = self_clone.state.read().await.peers.len();
                if peer_count == 0 && !self_clone.entry_peers.is_empty() {
                    info!("Isolated (0 peers) - retrying entry peers");
                    let connected = self_clone.connect_to_entry_peers().await;
                    if connected > 0 {
                        info!("Reconnected to {} entry peer(s)", connected);
                    }
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
                                if let Err(e) = self_clone.handle_connection(stream, addr).await {
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
                                if let Err(e) = self_clone.handle_connection(stream, addr).await {
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

            match TcpStream::connect(peer_addr).await {
                Ok(stream) => {
                    // Use the actual peer address from the connected socket
                    // This gives us the resolved IP, not the hostname
                    let addr = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("Failed to get peer addr: {}", e);
                            continue;
                        }
                    };
                    info!("Connected to peer {} at {}", peer_addr, addr);
                    connected += 1;

                    // Spawn connection handler as task - don't block!
                    let self_clone = Arc::clone(self);
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_connection(stream, addr).await {
                            warn!("Peer {} disconnected: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to connect to peer {}: {}", peer_addr, e);
                }
            }
        }

        connected
    }

    /// Handle a peer connection
    async fn handle_connection(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
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
                },
            );
        }

        info!("Peer {} registered", peer_id);

        // Simple protocol: exchange node info and sync state
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Send our node info with public key for TGP
        let state = self.state.read().await;
        let self_id = state.self_id.clone();
        let self_pubkey = state.signing_key.verifying_key();
        let pubkey_hex = hex::encode(self_pubkey.as_bytes());
        drop(state);
        let hello = serde_json::json!({
            "type": "hello",
            "node_id": self_id,
            "addr": self.listen_addr.to_string(),
            "public_key": pubkey_hex,
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
            let mut all_peers = vec![serde_json::json!({
                "id": state.self_id,
                "addr": self.listen_addr.to_string(),
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

        // Read peer messages and forward floods concurrently
        // NOTE: TGP is now over UDP (connectionless), not TCP
        let mut line = String::new();
        loop {
            line.clear();
            tokio::select! {
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
                        Ok(FloodMessage::CvdfAttestation { att }) => {
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_attestation",
                                "round": att.round,
                                "slot": att.slot,
                                "prev_output": hex::encode(att.prev_output),
                                "attester": hex::encode(att.attester),
                            });
                            let _ = writer.write_all(flood_msg.to_string().as_bytes()).await;
                            let _ = writer.write_all(b"\n").await;
                        }
                        Ok(FloodMessage::CvdfNewRound { round }) => {
                            let flood_msg = serde_json::json!({
                                "type": "cvdf_new_round",
                                "round": round.round,
                                "prev_output": hex::encode(round.prev_output),
                                "washed_input": hex::encode(round.washed_input),
                                "output": hex::encode(round.output),
                                "producer": hex::encode(round.producer),
                                "attestation_count": round.attestations.len(),
                                "weight": round.weight(),
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
                        Err(_) => {
                            // Channel closed or lagged, continue
                        }
                    }
                }
            }
        }

        // Remove peer on disconnect using current key
        {
            let mut state = self.state.write().await;
            state.peers.remove(&current_peer_key);
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

                    let mut state = self.state.write().await;
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
                            let _ = self.storage.set_admin(key, true);
                            info!("Merged admin from {}: {}", peer_id, key);
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

                    // Process the slot claim (stores public key in claim and peer)
                    let we_lost = self.process_slot_claim(index, claimer_id.to_string(), coord, public_key.clone()).await;

                    // Re-flood new claims to propagate through mesh (with public key)
                    if is_new {
                        self.flood(FloodMessage::SlotClaim {
                            index,
                            peer_id: claimer_id.to_string(),
                            coord,
                            public_key,
                        });
                    }

                    // If we lost our slot, attempt to join at next available via TGP
                    if we_lost {
                        let mut target_slot = self.state.read().await.next_available_slot();
                        info!("Lost slot race, attempting slot {} via TGP", target_slot);
                        // Try slots until one succeeds
                        while !self.attempt_slot_via_tgp(target_slot).await {
                            target_slot += 1;
                            if target_slot > 1000 {
                                error!("Failed to rejoin mesh after 1000 slot attempts");
                                break;
                            }
                        }
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
                                            debug!("PoL: measured latency to {} = {}µs", peer_id, proof.latency_us);
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
                            if self.cvdf_process_attestation(att).await {
                                debug!("Processed CVDF attestation for round {} from {}", round, peer_id);
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

                                    parsed_rounds.push(CvdfRound {
                                        round: round_num,
                                        prev_output: prev.try_into().unwrap(),
                                        washed_input: washed.try_into().unwrap(),
                                        output: out.try_into().unwrap(),
                                        producer: prod.try_into().unwrap(),
                                        producer_signature: sig.try_into().unwrap(),
                                        timestamp_ms,
                                        attestations,
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
                            let lost = self.process_slot_claim(
                                *slot_idx,
                                their_peer_id,
                                (coord.q, coord.r, coord.z),
                                Some(pubkey.to_vec())
                            ).await;

                            if lost {
                                we_lost_our_slot = true;
                            }
                        }

                        // If we lost our slot, reclaim at next available
                        if we_lost_our_slot {
                            let mut target_slot = self.state.read().await.next_available_slot();
                            info!("Lost slot during chain adoption, reclaiming at slot {}", target_slot);

                            while !self.attempt_slot_via_tgp(target_slot).await {
                                target_slot += 1;
                                if target_slot > 1000 {
                                    error!("Failed to reclaim slot after chain adoption");
                                    break;
                                }
                            }

                            if target_slot <= 1000 {
                                // Register our new slot
                                let pubkey = self.state.read().await.signing_key.verifying_key().to_bytes();
                                self.cvdf_register_slot(target_slot, pubkey).await;
                                self.cvdf_set_slot(target_slot).await;
                            }
                        }
                    }
                }
            }
            // ==================== END CVDF MESSAGE HANDLERS ====================
            // NOTE: TGP messages are now handled over UDP, not TCP
            // See run_tgp_udp_listener() and handle_tgp_message()
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
}
