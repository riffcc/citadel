//! TGP (Two Generals Protocol) session management.
//!
//! TGP provides bilateral consensus between peer pairs using the 6-packet model.
//! When two peers complete TGP (C→D→T), they have bilateral TripleProofs
//! ("The Knot") that serve as permanent authorization.

use citadel_protocols::PeerCoordinator;
use std::net::SocketAddr;
use tokio::sync::oneshot;

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
