//! Citadel Mesh Service
//!
//! # THE MESH IS THE SOURCE OF TRUTH
//!
//! There is no external oracle, coordinator, or database. The topology IS consensus.
//! Your slot = the connections you have. The mesh = the sum of all connections.
//!
//! # Architecture
//!
//! The mesh module is organized into submodules:
//! - `peer` - Peer identity (PeerID, AuthorizedPeer, MeshPeer)
//! - `slot` - SPIRAL slot management (SlotClaim, consensus threshold)
//! - `spore` - SPORE sync utilities (HaveList, WantList)
//! - `flood` - Flood message types for continuous propagation
//! - `tgp` - TGP session management
//! - `state` - MeshState (all node state)
//! - `service` - MeshService implementation
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
//! ```
//!
//! # SPORE Principles
//!
//! ALL data transfer uses continuous flooding - no request/response patterns:
//! - Peer discovery floods on connection
//! - Slot announcements flood through mesh
//! - Admin lists flood on change
//! - XOR cancellation: sync_cost(A,B) = O(|A ⊕ B|) → 0 at convergence

pub mod flood;
pub mod peer;
pub mod peer_addr_store;
pub mod service;
pub mod slot;
pub mod spore;
pub mod state;
pub mod tgp;

// Re-export core types at module level for convenience
pub use flood::FloodMessage;
pub use peer::{
    compute_peer_id, compute_peer_id_from_bytes, double_hash_id, matches_tombstone, AuthorizedPeer,
    MeshPeer,
};
pub use peer_addr_store::{PeerAddrRecord, PeerAddrStore};
pub use service::MeshService;
pub use slot::{consensus_threshold, LatencyHistory, LatencySample, SlotClaim};
pub use spore::{build_spore_havelist, build_spore_wantlist, release_id_to_u256};
pub use state::MeshState;
pub use tgp::TgpSession;
