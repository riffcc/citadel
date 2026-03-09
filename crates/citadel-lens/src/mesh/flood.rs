//! Flood messages for continuous mesh propagation.
//!
//! ALL data transfer uses continuous flooding - no request/response patterns:
//! - Peer discovery floods on connection
//! - Slot announcements flood through mesh
//! - Admin lists flood on change
//! - XOR cancellation: sync_cost(A,B) = O(|A ⊕ B|) → 0 at convergence

use crate::cvdf::{CvdfRound, RoundAttestation};
use crate::liveness::MeshVouch;
use crate::vdf_race::{AnchoredSlotClaim, VdfLink};
use citadel_spore::Spore;

use super::peer_addr_store::PeerAddrRecord;

/// Broadcast message for continuous flooding
#[derive(Clone, Debug)]
pub enum FloodMessage {
    /// Peer discovery (id, addr, slot_index, public_key)
    Peers(Vec<(String, String, Option<u64>, Option<Vec<u8>>)>),
    /// Admin list sync
    Admins(Vec<String>),
    // NOTE: Unsigned SlotClaim was REMOVED - it had no signature so anyone could
    // forge claims for any peer, causing oscillation bugs. Use VdfSlotClaim only.
    /// SPORE HaveList - advertise what slots we know about (for targeted sync)
    SporeHaveList { peer_id: String, slots: Vec<u64> },
    /// VDF chain sync - broadcast chain links for collaborative VDF
    VdfChain { links: Vec<VdfLink> },
    /// VDF-anchored slot claim - deterministic priority ordering
    VdfSlotClaim { claim: AnchoredSlotClaim },
    /// Proof of Latency ping request (for measuring RTT)
    PoLPing {
        from: [u8; 32],
        nonce: u64,
        vdf_height: u64,
    },
    /// Proof of Latency pong response
    PoLPong {
        from: [u8; 32],
        nonce: u64,
        vdf_height: u64,
    },
    /// Proof of Latency swap proposal
    PoLSwapProposal {
        proposal: crate::proof_of_latency::SwapProposal,
    },
    /// Proof of Latency swap response
    PoLSwapResponse {
        response: crate::proof_of_latency::SwapResponse,
    },
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
        spore_proof: Spore,
    },
    /// CVDF chain sync request
    CvdfSyncRequest { from_node: String, from_height: u64 },
    /// CVDF chain sync response (all rounds)
    CvdfSyncResponse {
        rounds: Vec<CvdfRound>,
        slots: Vec<(u64, [u8; 32])>,
    },
    /// SPORE: Content HaveList - advertise release IDs we have (for content sync)
    ContentHaveList {
        peer_id: String,
        release_ids: Vec<String>,
    },
    /// SPORE: Release flood - propagate a release across the mesh
    Release { release_json: String },
    /// SPORE⁻¹: DoNotWantList - deletions as ranges in 256-bit hash space
    /// Uses Spore (range-based) representation for O(|diff|) → 0 convergence
    /// H(H(id)) hashes become point-ranges for privacy-preserving sync
    DoNotWantList {
        peer_id: String,
        /// Spore: ranges of deleted content (serialized as JSON for wire format)
        do_not_want: Spore,
    },
    /// SPORE⁻¹: ErasureConfirmation - bilateral proof that a node has deleted content
    /// Used for GDPR-compliant "right to erasure" with cryptographic proof
    /// Confirms that peer has processed these deletion ranges
    ErasureConfirmation {
        peer_id: String,
        /// Spore: ranges of content this peer confirms deleted
        confirmed: Spore,
    },
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
    /// SPORE-indexed peer address sync.
    PeerAddrSync { peer_id: String, have_list: Spore },
    /// SPORE: Delta transfer - actual content for the XOR difference
    /// Contains releases that match ranges in the XOR diff
    SporeDelta {
        releases: Vec<String>, // JSON-serialized releases
    },
    /// Peer address delta transfer.
    PeerAddrDelta { records: Vec<PeerAddrRecord> },
    /// SPORE: Featured releases sync - separate from regular releases
    /// These control homepage/hero display and have their own sync lifecycle
    FeaturedSync {
        peer_id: String,
        featured: Vec<String>, // JSON-serialized FeaturedRelease
    },
}
