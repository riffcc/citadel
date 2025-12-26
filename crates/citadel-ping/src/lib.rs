//! # Citadel Ping: Health and Presence
//!
//! This crate provides node health announcements and peer tracking for Citadel.
//!
//! ## Key Concepts
//!
//! ### Ping Messages
//!
//! Each node periodically broadcasts a Ping message containing:
//! - Node ID
//! - Current timestamp
//! - Capabilities (what services this node provides)
//! - Load metric (for work distribution)
//!
//! ### Peer Tracking
//!
//! The PeerTracker maintains a view of known peers:
//! - When was each peer last seen?
//! - What capabilities does it advertise?
//! - Is it currently considered "alive"?
//!
//! ### Failure Detection
//!
//! Peers are considered "stale" after a configurable timeout.
//! This is not Byzantine fault detection - just basic liveness.

use citadel_spore::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace, warn};

/// Errors that can occur in ping operations.
#[derive(Error, Debug)]
pub enum PingError {
    #[error("Peer not found: {0:?}")]
    PeerNotFound(U256),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, PingError>;

/// Capabilities a node can advertise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Can store documents (Citadel Docs)
    DocumentStorage,

    /// Can perform transcoding operations
    Transcode,

    /// Can perform content audits
    Audit,

    /// Can import from external sources
    Import,

    /// Has high-bandwidth connectivity
    HighBandwidth,

    /// Has substantial storage capacity
    LargeStorage,
}

/// A ping message announcing node presence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    /// Node identifier (256-bit)
    pub node_id: U256,

    /// Current timestamp (Unix epoch seconds)
    pub timestamp: u64,

    /// Advertised capabilities
    pub capabilities: Vec<Capability>,

    /// Current load (0.0 = idle, 1.0 = fully loaded)
    pub load: f32,

    /// Protocol version
    pub version: u32,
}

impl Ping {
    /// Create a new ping message.
    pub fn new(node_id: U256, capabilities: Vec<Capability>, load: f32) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            node_id,
            timestamp,
            capabilities,
            load,
            version: 1,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization cannot fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(PingError::Serialization)
    }
}

/// Information about a known peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Node identifier
    pub node_id: U256,

    /// When we last received a ping from this peer
    pub last_seen: Instant,

    /// Last known capabilities
    pub capabilities: Vec<Capability>,

    /// Last known load
    pub load: f32,

    /// Protocol version
    pub version: u32,
}

impl PeerInfo {
    /// Create from a ping message.
    fn from_ping(ping: &Ping) -> Self {
        Self {
            node_id: ping.node_id,
            last_seen: Instant::now(),
            capabilities: ping.capabilities.clone(),
            load: ping.load,
            version: ping.version,
        }
    }

    /// Update from a new ping.
    fn update(&mut self, ping: &Ping) {
        self.last_seen = Instant::now();
        self.capabilities = ping.capabilities.clone();
        self.load = ping.load;
        self.version = ping.version;
    }

    /// Check if this peer is considered stale.
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Check if this peer has a specific capability.
    pub fn has_capability(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// Tracks known peers and their status.
pub struct PeerTracker {
    /// Our node ID
    my_id: U256,

    /// Known peers
    peers: HashMap<U256, PeerInfo>,

    /// Timeout after which a peer is considered stale
    stale_timeout: Duration,

    /// Interval between ping broadcasts
    ping_interval: Duration,

    /// When we last broadcast a ping
    last_ping: Option<Instant>,
}

impl PeerTracker {
    /// Create a new peer tracker.
    pub fn new(my_id: U256) -> Self {
        Self {
            my_id,
            peers: HashMap::new(),
            stale_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(15),
            last_ping: None,
        }
    }

    /// Create with custom timeouts.
    pub fn with_timeouts(
        my_id: U256,
        stale_timeout: Duration,
        ping_interval: Duration,
    ) -> Self {
        Self {
            my_id,
            peers: HashMap::new(),
            stale_timeout,
            ping_interval,
            last_ping: None,
        }
    }

    /// Our node ID.
    pub fn my_id(&self) -> &U256 {
        &self.my_id
    }

    /// Process an incoming ping.
    pub fn receive_ping(&mut self, ping: &Ping) {
        // Ignore pings from ourselves
        if ping.node_id == self.my_id {
            return;
        }

        if let Some(peer) = self.peers.get_mut(&ping.node_id) {
            peer.update(ping);
            trace!(node_id = ?ping.node_id, "Updated peer info");
        } else {
            self.peers.insert(ping.node_id, PeerInfo::from_ping(ping));
            debug!(node_id = ?ping.node_id, "Discovered new peer");
        }
    }

    /// Check if it's time to send a ping.
    pub fn should_ping(&self) -> bool {
        match self.last_ping {
            None => true,
            Some(last) => last.elapsed() >= self.ping_interval,
        }
    }

    /// Create a ping message to broadcast.
    pub fn create_ping(&mut self, capabilities: Vec<Capability>, load: f32) -> Ping {
        self.last_ping = Some(Instant::now());
        Ping::new(self.my_id, capabilities, load)
    }

    /// Get info about a specific peer.
    pub fn get_peer(&self, node_id: &U256) -> Option<&PeerInfo> {
        self.peers.get(node_id)
    }

    /// Get all known peers.
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Get only alive (non-stale) peers.
    pub fn alive_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        let timeout = self.stale_timeout;
        self.peers.values().filter(move |p| !p.is_stale(timeout))
    }

    /// Get peers with a specific capability.
    pub fn peers_with_capability(&self, cap: Capability) -> impl Iterator<Item = &PeerInfo> {
        let timeout = self.stale_timeout;
        self.peers
            .values()
            .filter(move |p| !p.is_stale(timeout) && p.has_capability(cap))
    }

    /// Get the peer with lowest load that has a capability.
    pub fn best_peer_for(&self, cap: Capability) -> Option<&PeerInfo> {
        self.peers_with_capability(cap)
            .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Count of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Count of alive peers.
    pub fn alive_count(&self) -> usize {
        self.alive_peers().count()
    }

    /// Remove stale peers.
    pub fn gc(&mut self) {
        let timeout = self.stale_timeout;
        let before = self.peers.len();

        self.peers.retain(|id, peer| {
            let keep = !peer.is_stale(timeout);
            if !keep {
                debug!(node_id = ?id, "Removed stale peer");
            }
            keep
        });

        let removed = before - self.peers.len();
        if removed > 0 {
            debug!(removed, "Garbage collected stale peers");
        }
    }

    /// Remove a specific peer.
    pub fn remove_peer(&mut self, node_id: &U256) -> Option<PeerInfo> {
        self.peers.remove(node_id).map(|p| {
            warn!(node_id = ?node_id, "Manually removed peer");
            p
        })
    }
}

impl Default for PeerTracker {
    fn default() -> Self {
        Self::new(U256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(n: u64) -> U256 {
        U256::from_u64(n)
    }

    #[test]
    fn test_ping_creation() {
        let ping = Ping::new(
            make_node_id(1),
            vec![Capability::DocumentStorage, Capability::Transcode],
            0.5,
        );

        assert_eq!(ping.node_id, make_node_id(1));
        assert_eq!(ping.capabilities.len(), 2);
        assert_eq!(ping.load, 0.5);
        assert_eq!(ping.version, 1);
    }

    #[test]
    fn test_ping_serialization() {
        let ping = Ping::new(make_node_id(1), vec![Capability::Audit], 0.0);
        let bytes = ping.to_bytes();
        let restored = Ping::from_bytes(&bytes).unwrap();

        assert_eq!(restored.node_id, ping.node_id);
        assert_eq!(restored.capabilities, ping.capabilities);
    }

    #[test]
    fn test_peer_discovery() {
        let mut tracker = PeerTracker::new(make_node_id(1));

        let ping = Ping::new(make_node_id(2), vec![Capability::Transcode], 0.3);
        tracker.receive_ping(&ping);

        assert_eq!(tracker.peer_count(), 1);
        assert!(tracker.get_peer(&make_node_id(2)).is_some());
    }

    #[test]
    fn test_ignore_self() {
        let my_id = make_node_id(1);
        let mut tracker = PeerTracker::new(my_id);

        let ping = Ping::new(my_id, vec![], 0.0);
        tracker.receive_ping(&ping);

        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn test_peer_update() {
        let mut tracker = PeerTracker::new(make_node_id(1));
        let peer_id = make_node_id(2);

        // First ping
        let ping1 = Ping::new(peer_id, vec![Capability::Audit], 0.2);
        tracker.receive_ping(&ping1);

        // Second ping with updated load
        let ping2 = Ping::new(peer_id, vec![Capability::Audit, Capability::Transcode], 0.8);
        tracker.receive_ping(&ping2);

        let peer = tracker.get_peer(&peer_id).unwrap();
        assert_eq!(peer.capabilities.len(), 2);
        assert_eq!(peer.load, 0.8);
    }

    #[test]
    fn test_capability_filter() {
        let mut tracker = PeerTracker::new(make_node_id(1));

        // Peer 2 has Transcode
        let ping2 = Ping::new(make_node_id(2), vec![Capability::Transcode], 0.5);
        tracker.receive_ping(&ping2);

        // Peer 3 has Audit
        let ping3 = Ping::new(make_node_id(3), vec![Capability::Audit], 0.3);
        tracker.receive_ping(&ping3);

        // Peer 4 has both
        let ping4 = Ping::new(
            make_node_id(4),
            vec![Capability::Transcode, Capability::Audit],
            0.7,
        );
        tracker.receive_ping(&ping4);

        let transcoders: Vec<_> = tracker
            .peers_with_capability(Capability::Transcode)
            .collect();
        assert_eq!(transcoders.len(), 2);

        let auditors: Vec<_> = tracker.peers_with_capability(Capability::Audit).collect();
        assert_eq!(auditors.len(), 2);
    }

    #[test]
    fn test_best_peer_by_load() {
        let mut tracker = PeerTracker::new(make_node_id(1));

        // Peer 2 with high load
        let ping2 = Ping::new(make_node_id(2), vec![Capability::Transcode], 0.9);
        tracker.receive_ping(&ping2);

        // Peer 3 with low load
        let ping3 = Ping::new(make_node_id(3), vec![Capability::Transcode], 0.2);
        tracker.receive_ping(&ping3);

        let best = tracker.best_peer_for(Capability::Transcode).unwrap();
        assert_eq!(best.node_id, make_node_id(3));
        assert_eq!(best.load, 0.2);
    }

    #[test]
    fn test_stale_detection() {
        let mut tracker =
            PeerTracker::with_timeouts(make_node_id(1), Duration::from_millis(10), Duration::from_secs(1));

        let ping = Ping::new(make_node_id(2), vec![], 0.0);
        tracker.receive_ping(&ping);

        assert_eq!(tracker.alive_count(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(tracker.alive_count(), 0);

        // GC should remove it
        tracker.gc();
        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn test_should_ping() {
        let mut tracker =
            PeerTracker::with_timeouts(make_node_id(1), Duration::from_secs(60), Duration::from_millis(10));

        assert!(tracker.should_ping());

        let _ping = tracker.create_ping(vec![], 0.0);
        assert!(!tracker.should_ping());

        std::thread::sleep(Duration::from_millis(15));
        assert!(tracker.should_ping());
    }
}
