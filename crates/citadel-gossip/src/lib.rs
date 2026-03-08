//! # Citadel Gossip: Ephemeral Messages with TTL
//!
//! This crate provides ephemeral pub/sub messaging for real-time communication.
//! Messages have a Time-To-Live (TTL) and are deduplicated using SPORE.
//!
//! ## Key Concepts
//!
//! ### Ephemeral Messages
//!
//! Unlike documents which are persistent, gossip messages are:
//! - **Ephemeral**: They expire after TTL seconds
//! - **Deduplicated**: Each message is delivered at most once
//! - **Topic-based**: Messages are filtered by topic subscription
//!
//! ### SPORE Deduplication
//!
//! Message IDs are content-addressed (Blake3 hash). The "seen" set is tracked
//! via SPORE HaveList. This means:
//! - O(k) storage for k boundary transitions
//! - Efficient XOR-based diff for sync
//! - Provably no duplicate delivery
//!
//! ## Use Cases
//!
//! - Job progress updates
//! - Node heartbeats (via citadel-ping)
//! - Real-time notifications
//! - Admin alerts

use citadel_crdt::ContentId;
use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, trace};

/// Errors that can occur in gossip operations.
#[derive(Error, Debug)]
pub enum GossipError {
    #[error("Message expired")]
    Expired,

    #[error("Duplicate message")]
    Duplicate,

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Unknown topic: {0}")]
    UnknownTopic(String),
}

pub type Result<T> = std::result::Result<T, GossipError>;

/// A gossip message.
///
/// Messages are content-addressed by hashing (topic, payload, created_at).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    /// Topic for filtering (e.g., "job_progress", "node_status")
    pub topic: String,

    /// Message payload (opaque bytes, typically bincode-serialized)
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Time-to-live in seconds
    pub ttl: u64,

    /// Creation timestamp (Unix epoch seconds)
    pub created_at: u64,

    /// Sender node ID (256-bit)
    pub sender: U256,
}

impl GossipMessage {
    /// Create a new gossip message.
    pub fn new(topic: impl Into<String>, payload: Vec<u8>, ttl: u64, sender: U256) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            topic: topic.into(),
            payload,
            ttl,
            created_at: now,
            sender,
        }
    }

    /// Compute the content ID of this message.
    pub fn content_id(&self) -> ContentId {
        let bytes = bincode::serialize(self).expect("serialization cannot fail");
        ContentId::hash(&bytes)
    }

    /// Check if this message has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now > self.created_at + self.ttl
    }

    /// Remaining TTL in seconds.
    pub fn remaining_ttl(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let expires_at = self.created_at + self.ttl;
        if now >= expires_at {
            0
        } else {
            expires_at - now
        }
    }
}

/// Convert a ContentId to a U256 for SPORE tracking
fn content_id_to_u256(id: &ContentId) -> U256 {
    U256::from_be_bytes(id.as_bytes())
}

/// Create a point range for a single content ID
fn point_range(id: &ContentId) -> Range256 {
    let u = content_id_to_u256(id);
    if let Some(next) = u.checked_add(&U256::from_u64(1)) {
        Range256::new(u, next)
    } else {
        Range256::new(u, U256::MAX)
    }
}

/// Entry in the message queue with local timing info.
struct QueuedMessage {
    message: GossipMessage,
    #[allow(dead_code)]
    received_at: Instant,
}

/// Gossip message store with deduplication and expiry.
pub struct GossipStore {
    /// SPORE tracking of seen message IDs
    seen: Spore,

    /// Topic subscriptions: topic -> whether subscribed
    subscriptions: HashMap<String, bool>,

    /// Incoming message queue (for topics we're subscribed to)
    inbox: VecDeque<QueuedMessage>,

    /// Outgoing message queue (for broadcast)
    outbox: VecDeque<GossipMessage>,

    /// Maximum inbox size (oldest messages dropped when exceeded)
    max_inbox_size: usize,
}

impl GossipStore {
    /// Create a new gossip store.
    pub fn new() -> Self {
        Self {
            seen: Spore::empty(),
            subscriptions: HashMap::new(),
            inbox: VecDeque::new(),
            outbox: VecDeque::new(),
            max_inbox_size: 10000,
        }
    }

    /// Create with custom inbox size.
    pub fn with_inbox_size(max_size: usize) -> Self {
        Self {
            max_inbox_size: max_size,
            ..Self::new()
        }
    }

    /// Subscribe to a topic.
    pub fn subscribe(&mut self, topic: impl Into<String>) {
        self.subscriptions.insert(topic.into(), true);
    }

    /// Unsubscribe from a topic.
    pub fn unsubscribe(&mut self, topic: &str) {
        self.subscriptions.remove(topic);
    }

    /// Check if subscribed to a topic.
    pub fn is_subscribed(&self, topic: &str) -> bool {
        self.subscriptions.get(topic).copied().unwrap_or(false)
    }

    /// Get the SPORE HaveList of seen message IDs.
    pub fn seen_messages(&self) -> &Spore {
        &self.seen
    }

    /// Queue a message for broadcast.
    ///
    /// Returns the message's content ID.
    pub fn broadcast(&mut self, message: GossipMessage) -> ContentId {
        let id = message.content_id();

        // Mark as seen (we've processed it ourselves)
        let range = point_range(&id);
        self.seen = self.seen.union(&Spore::from_range(range));

        // Add to outbox
        self.outbox.push_back(message);

        trace!(id = %id, "Queued message for broadcast");
        id
    }

    /// Receive an incoming message.
    ///
    /// Returns Ok(true) if the message was accepted, Ok(false) if filtered,
    /// Err if duplicate or expired.
    pub fn receive(&mut self, message: GossipMessage) -> Result<bool> {
        // Check expiry
        if message.is_expired() {
            return Err(GossipError::Expired);
        }

        let id = message.content_id();
        let u256 = content_id_to_u256(&id);

        // Check duplicate
        if self.seen.covers(&u256) {
            return Err(GossipError::Duplicate);
        }

        // Mark as seen
        let range = point_range(&id);
        self.seen = self.seen.union(&Spore::from_range(range));

        // Check subscription
        if !self.is_subscribed(&message.topic) {
            trace!(topic = %message.topic, "Message filtered (not subscribed)");
            return Ok(false);
        }

        // Add to inbox
        self.inbox.push_back(QueuedMessage {
            message,
            received_at: Instant::now(),
        });

        // Trim if too large
        while self.inbox.len() > self.max_inbox_size {
            self.inbox.pop_front();
            debug!("Dropped oldest message (inbox full)");
        }

        Ok(true)
    }

    /// Take all messages from the outbox for sending.
    pub fn drain_outbox(&mut self) -> Vec<GossipMessage> {
        self.outbox.drain(..).collect()
    }

    /// Get the next message from the inbox.
    pub fn pop_inbox(&mut self) -> Option<GossipMessage> {
        // Skip expired messages
        while let Some(entry) = self.inbox.front() {
            if entry.message.is_expired() {
                self.inbox.pop_front();
            } else {
                break;
            }
        }

        self.inbox.pop_front().map(|e| e.message)
    }

    /// Check if inbox is empty.
    pub fn inbox_empty(&self) -> bool {
        self.inbox.is_empty()
    }

    /// Check if outbox is empty.
    pub fn outbox_empty(&self) -> bool {
        self.outbox.is_empty()
    }

    /// Number of messages in inbox.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Number of messages in outbox.
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Garbage collect expired entries from the seen set.
    ///
    /// Note: This is a no-op in the current implementation because we don't
    /// track expiry times for individual message IDs in the SPORE set.
    /// The seen set will grow unbounded over time. For production, consider:
    /// - Periodic full reset with re-sync
    /// - Bloom filter for older messages
    /// - Time-windowed SPORE sets
    pub fn gc(&mut self) {
        // Prune expired messages from inbox
        self.inbox.retain(|e| !e.message.is_expired());
    }

    /// Compute messages we've seen that a peer hasn't.
    pub fn diff(&self, peer_seen: &Spore) -> Spore {
        self.seen.subtract(peer_seen)
    }
}

impl Default for GossipStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Common gossip topics.
pub mod topics {
    /// Job progress updates
    pub const JOB_PROGRESS: &str = "job_progress";

    /// Node status/health
    pub const NODE_STATUS: &str = "node_status";

    /// Admin notifications
    pub const ADMIN_NOTIFY: &str = "admin_notify";

    /// Content announcements
    pub const CONTENT_ANNOUNCE: &str = "content_announce";
}

/// Helper to create typed gossip messages.
pub trait GossipPayload: Serialize + for<'de> Deserialize<'de> {
    /// The topic for this payload type.
    const TOPIC: &'static str;

    /// Create a gossip message from this payload.
    fn to_gossip(&self, ttl: u64, sender: U256) -> GossipMessage {
        let payload = bincode::serialize(self).expect("serialization cannot fail");
        GossipMessage::new(Self::TOPIC, payload, ttl, sender)
    }

    /// Parse a gossip message into this payload type.
    fn from_gossip(msg: &GossipMessage) -> Result<Self> {
        if msg.topic != Self::TOPIC {
            return Err(GossipError::UnknownTopic(msg.topic.clone()));
        }
        bincode::deserialize(&msg.payload).map_err(GossipError::Serialization)
    }
}

/// Job progress payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    /// Job ID
    pub job_id: ContentId,
    /// Progress percentage (0.0 - 1.0)
    pub progress: f32,
    /// Optional status message
    pub message: Option<String>,
}

impl GossipPayload for JobProgress {
    const TOPIC: &'static str = topics::JOB_PROGRESS;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sender() -> U256 {
        U256::from_u64(12345)
    }

    #[test]
    fn test_message_creation() {
        let msg = GossipMessage::new("test", vec![1, 2, 3], 60, make_sender());
        assert_eq!(msg.topic, "test");
        assert_eq!(msg.payload, vec![1, 2, 3]);
        assert_eq!(msg.ttl, 60);
        assert!(!msg.is_expired());
    }

    #[test]
    fn test_subscribe_receive() {
        let mut store = GossipStore::new();
        store.subscribe("test");

        let msg = GossipMessage::new("test", vec![1, 2, 3], 60, make_sender());
        let result = store.receive(msg);

        assert!(result.is_ok());
        assert!(result.unwrap()); // Was accepted
        assert_eq!(store.inbox_len(), 1);
    }

    #[test]
    fn test_unsubscribed_filtered() {
        let mut store = GossipStore::new();
        // Not subscribed to "test"

        let msg = GossipMessage::new("test", vec![1, 2, 3], 60, make_sender());
        let result = store.receive(msg);

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Was filtered
        assert_eq!(store.inbox_len(), 0);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut store = GossipStore::new();
        store.subscribe("test");

        let msg = GossipMessage::new("test", vec![1, 2, 3], 60, make_sender());
        let msg_clone = msg.clone();

        // First receive succeeds
        assert!(store.receive(msg).is_ok());

        // Second receive fails as duplicate
        let result = store.receive(msg_clone);
        assert!(matches!(result, Err(GossipError::Duplicate)));
    }

    #[test]
    fn test_broadcast_marks_seen() {
        let mut store = GossipStore::new();

        let msg = GossipMessage::new("test", vec![1, 2, 3], 60, make_sender());
        let id = store.broadcast(msg.clone());

        // Should be marked as seen
        let u256 = content_id_to_u256(&id);
        assert!(store.seen_messages().covers(&u256));

        // Receiving the same message should fail as duplicate
        assert!(matches!(store.receive(msg), Err(GossipError::Duplicate)));
    }

    #[test]
    fn test_outbox_drain() {
        let mut store = GossipStore::new();

        store.broadcast(GossipMessage::new("a", vec![], 60, make_sender()));
        store.broadcast(GossipMessage::new("b", vec![], 60, make_sender()));

        assert_eq!(store.outbox_len(), 2);

        let drained = store.drain_outbox();
        assert_eq!(drained.len(), 2);
        assert!(store.outbox_empty());
    }

    #[test]
    fn test_job_progress_payload() {
        let progress = JobProgress {
            job_id: ContentId::hash(b"job1"),
            progress: 0.5,
            message: Some("Halfway there".to_string()),
        };

        let msg = progress.to_gossip(60, make_sender());
        assert_eq!(msg.topic, topics::JOB_PROGRESS);

        let parsed = JobProgress::from_gossip(&msg).unwrap();
        assert_eq!(parsed.progress, 0.5);
        assert_eq!(parsed.message, Some("Halfway there".to_string()));
    }

    #[test]
    fn test_diff() {
        let mut store1 = GossipStore::new();
        let mut store2 = GossipStore::new();

        // Store1 broadcasts message A
        let msg_a = GossipMessage::new("test", b"a".to_vec(), 60, make_sender());
        store1.broadcast(msg_a.clone());

        // Store2 broadcasts message B
        let msg_b = GossipMessage::new("test", b"b".to_vec(), 60, make_sender());
        store2.broadcast(msg_b);

        // Diff should show store1 has A, store2 doesn't
        let diff = store1.diff(store2.seen_messages());
        assert!(!diff.is_empty());

        let a_u256 = content_id_to_u256(&msg_a.content_id());
        assert!(diff.covers(&a_u256));
    }
}
