//! Peer identity and authorization.
//!
//! This module handles:
//! - PeerID computation (double-BLAKE3 of ed25519 pubkey)
//! - Tombstone hashing for DoNotWantList
//! - MeshPeer state tracking
//! - TGP-authorized peer management

use citadel_protocols::QuadProof;
use citadel_spore::Spore;
use ed25519_dalek::VerifyingKey;
use std::net::SocketAddr;

use super::SlotClaim;

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

/// Mesh node identity and state
#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub id: String,
    pub addr: SocketAddr,
    pub yggdrasil_addr: Option<String>,
    pub underlay_uri: Option<String>,
    pub ygg_peer_uri: Option<String>,
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
