//! Citadel Protocols - Reliable Bilateral Coordination and SPORE Sync
//!
//! This crate provides reliable coordination protocols for peer connections
//! in the Citadel mesh network, built on the Two Generals Protocol (TGP)
//! and SPORE (Succinct Proof of Range Exclusions) for optimal content sync.
//!
//! # Overview
//!
//! ## Peer Coordination
//!
//! The [`PeerCoordinator`] wraps TGP to provide bilateral coordination between
//! two peers with epistemic proof escalation (C → D → T → Q phases):
//!
//! - **Symmetric outcomes**: Both parties either ATTACK or ABORT together
//! - **No special messages**: Any copy of a proof suffices (flooding-friendly)
//! - **Bilateral construction**: If one party can construct Q, so can the other
//!
//! ## SPORE Sync
//!
//! The [`spore_sync`] module implements SPORE-based content replication:
//!
//! - **XOR Cancellation**: sync_cost(A,B) = O(|A ⊕ B|), not O(|A| + |B|)
//! - **Convergence**: At steady state, sync cost → 0 as XOR → ∅
//! - **Information-Theoretic Optimality**: Can't communicate less than boundaries
//! - **Bilateral Verification**: Both nodes can independently verify sync completion
//!
//! # Example
//!
//! ```rust,ignore
//! use citadel_protocols::{PeerCoordinator, CoordinatorConfig};
//! use citadel_protocols::spore_sync::{SporeSync, ContentBlock, ContentType};
//!
//! // Create coordinators for two peers
//! let mut alice = PeerCoordinator::new(
//!     alice_keypair,
//!     bob_public_key,
//!     CoordinatorConfig::default(),
//! );
//! let mut bob = PeerCoordinator::new(
//!     bob_keypair,
//!     alice_public_key,
//!     CoordinatorConfig::default(),
//! );
//!
//! // Exchange messages until coordination achieved
//! while !alice.is_coordinated() || !bob.is_coordinated() {
//!     for msg in alice.get_messages() {
//!         bob.receive(&msg)?;
//!     }
//!     for msg in bob.get_messages() {
//!         alice.receive(&msg)?;
//!     }
//! }
//!
//! // After coordination, use SPORE for content sync
//! let mut sync = SporeSync::new(my_peer_id);
//! sync.add_content(ContentBlock::new(ContentType::Release, data));
//! let spore_msg = sync.create_spore_message();
//! // Exchange with peer...
//! ```

pub mod coordinator;
pub mod error;
pub mod spore_sync;

pub use coordinator::{CoordinatorConfig, CoordinatorState, FloodRateConfig, PeerCoordinator};
pub use error::{Error, Result};
pub use spore_sync::{ContentBlock, ContentType, SporeSync, SporeSyncManager, SporeSyncStats};

// Re-export core TGP types for convenience
pub use two_generals::{
    crypto::{KeyPair, PublicKey, Signature},
    Commitment, Decision, DoubleProof, Message, MessagePayload, Party, ProtocolState as TgpState, QuadProof, TripleProof,
};
