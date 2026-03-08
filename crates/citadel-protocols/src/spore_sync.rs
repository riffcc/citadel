//! SPORE Sync - Information-theoretically optimal content replication
//!
//! This module implements SPORE-based sync for the Citadel mesh network.
//! SPORE (Succinct Proof of Range Exclusions) enables efficient synchronization
//! by encoding what data exists as ranges in 256-bit hash space.
//!
//! # Key Properties (Proven in proofs/CitadelProofs/Spore.lean)
//!
//! 1. **XOR Cancellation**: sync_cost(A,B) = O(|A ⊕ B|), not O(|A| + |B|)
//! 2. **Convergence**: At steady state, sync cost → 0 as XOR → ∅
//! 3. **Information-Theoretic Optimality**: Can't communicate less than boundaries
//! 4. **Bilateral Construction**: Both nodes can verify sync completion independently
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐      SPORE Messages      ┌─────────────┐
//! │   Node A    │ ─────────────────────────│   Node B    │
//! │             │                          │             │
//! │  ContentDB  │  XOR(A.have, B.have)     │  ContentDB  │
//! │     ↓       │  = what differs          │     ↓       │
//! │   Spore     │                          │   Spore     │
//! │ (HaveList)  │  Send: A.have ∩ B.want   │ (HaveList)  │
//! │ (WantList)  │  Recv: B.have ∩ A.want   │ (WantList)  │
//! └─────────────┘                          └─────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use citadel_protocols::spore_sync::{SporeSync, ContentBlock};
//!
//! // Create sync state for a peer
//! let mut sync = SporeSync::new(my_peer_id);
//!
//! // Register content I have
//! sync.add_content(content_hash, content_data)?;
//!
//! // Exchange SPORE messages with peer
//! let my_spore_msg = sync.create_spore_message();
//! sync.receive_spore_message(their_msg)?;
//!
//! // Get content to send
//! for block in sync.blocks_to_send() {
//!     send_to_peer(block);
//! }
//! ```

use citadel_spore::{Range256, Spore, SporeMessage, SyncState, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, trace};

/// A content block that can be synchronized via SPORE.
///
/// Content is identified by its hash in 256-bit space. The hash determines
/// which SPORE range the content belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBlock {
    /// Content hash (BLAKE3)
    pub hash: [u8; 32],
    /// Content type (for routing/filtering)
    pub content_type: ContentType,
    /// The actual content data
    pub data: Vec<u8>,
}

impl ContentBlock {
    /// Create a new content block from data.
    pub fn new(content_type: ContentType, data: Vec<u8>) -> Self {
        let hash = blake3::hash(&data);
        Self {
            hash: *hash.as_bytes(),
            content_type,
            data,
        }
    }

    /// Get the content hash as U256 for SPORE operations.
    pub fn hash_u256(&self) -> U256 {
        U256::from_be_bytes(&self.hash)
    }
}

/// Types of content that can be synchronized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Peer information (mesh topology)
    PeerInfo,
    /// Slot claim in SPIRAL topology
    SlotClaim,
    /// Release metadata
    Release,
    /// Content item (file, media)
    ContentItem,
    /// Admin authorization
    Admin,
}

/// SPORE-based synchronization state for a peer connection.
///
/// Tracks what content we have, what we want, and computes efficient
/// sync operations based on SPORE range encoding.
#[derive(Debug)]
pub struct SporeSync {
    /// Our peer ID
    peer_id: U256,
    /// Our content database (hash → block)
    content: HashMap<[u8; 32], ContentBlock>,
    /// SPORE sync state with peer
    sync_state: SyncState,
    /// Their content hashes (learned via SPORE exchange)
    their_content: HashMap<[u8; 32], ContentType>,
    /// Pending content to send (computed from SPORE intersection)
    pending_send: Vec<[u8; 32]>,
    /// Pending content to receive (computed from SPORE intersection)
    pending_receive: Vec<[u8; 32]>,
}

impl SporeSync {
    /// Create a new SPORE sync state.
    pub fn new(peer_id: U256) -> Self {
        Self {
            peer_id,
            content: HashMap::new(),
            sync_state: SyncState::new(),
            their_content: HashMap::new(),
            pending_send: Vec::new(),
            pending_receive: Vec::new(),
        }
    }

    /// Add content to our local store.
    ///
    /// Updates the HaveList SPORE to include this content's hash range,
    /// and removes it from the WantList (we no longer want what we have).
    pub fn add_content(&mut self, block: ContentBlock) {
        let hash = block.hash;
        let hash_u256 = block.hash_u256();

        // Add to content database
        self.content.insert(hash, block);

        // Create a single-value range for this hash
        let end = hash_u256
            .checked_add(&U256::from_u64(1))
            .unwrap_or(U256::MAX);
        let range = Range256::new(hash_u256, end);
        let range_spore = Spore::from_range(range);

        // Update HaveList SPORE - add this content
        self.sync_state.my_have = self.sync_state.my_have.union(&range_spore);

        // Update WantList SPORE - remove this content (we no longer want what we have)
        self.sync_state.my_want = self.sync_state.my_want.subtract(&range_spore);

        trace!(
            "Added content {}..., HaveList now has {} ranges, WantList has {} ranges",
            hex::encode(&hash[..8]),
            self.sync_state.my_have.range_count(),
            self.sync_state.my_want.range_count()
        );
    }

    /// Check if we have content with the given hash.
    pub fn has_content(&self, hash: &[u8; 32]) -> bool {
        self.content.contains_key(hash)
    }

    /// Get content by hash.
    pub fn get_content(&self, hash: &[u8; 32]) -> Option<&ContentBlock> {
        self.content.get(hash)
    }

    /// Create a SPORE message to send to peer.
    ///
    /// The message contains our HaveList and WantList as compact ranges.
    pub fn create_spore_message(&self) -> SporeMessage {
        SporeMessage::unsigned(
            self.peer_id,
            self.sync_state.my_have.clone(),
            self.sync_state.my_want.clone(),
        )
    }

    /// Receive a SPORE message from peer.
    ///
    /// Updates our view of their HaveList/WantList and computes what
    /// content needs to be transferred in each direction.
    pub fn receive_spore_message(&mut self, msg: SporeMessage) {
        // Update their state
        self.sync_state.their_have = msg.have_list;
        self.sync_state.their_want = msg.want_list;

        // Compute what we need to send: my_have ∩ their_want
        let to_send = self.sync_state.to_send();

        // Compute what we need to receive: their_have ∩ my_want
        let to_receive = self.sync_state.to_receive();

        debug!(
            "SPORE exchange: send {} ranges, receive {} ranges",
            to_send.range_count(),
            to_receive.range_count()
        );

        // Find content blocks that fall within the to_send ranges
        self.pending_send.clear();
        for (hash, _block) in &self.content {
            let hash_u256 = U256::from_be_bytes(hash);
            if to_send.covers(&hash_u256) {
                self.pending_send.push(*hash);
            }
        }

        trace!("Pending send: {} blocks", self.pending_send.len());
    }

    /// Get content blocks to send to peer.
    ///
    /// Returns an iterator over content that should be sent based on
    /// the SPORE intersection (my_have ∩ their_want).
    pub fn blocks_to_send(&self) -> impl Iterator<Item = &ContentBlock> {
        self.pending_send
            .iter()
            .filter_map(|hash| self.content.get(hash))
    }

    /// Take the next block to send, removing it from pending.
    pub fn take_next_to_send(&mut self) -> Option<ContentBlock> {
        while let Some(hash) = self.pending_send.pop() {
            if let Some(block) = self.content.get(&hash) {
                return Some(block.clone());
            }
        }
        None
    }

    /// Receive a content block from peer.
    ///
    /// Adds the content to our store and updates SPORE state.
    pub fn receive_content(&mut self, block: ContentBlock) {
        let hash = block.hash;

        // Verify the hash matches
        let computed = blake3::hash(&block.data);
        if computed.as_bytes() != &hash {
            tracing::warn!("Content hash mismatch, rejecting block");
            return;
        }

        // Store the content
        self.add_content(block);

        // Remove from their_content since we now have it
        self.their_content.remove(&hash);

        // Update WantList (we no longer want this)
        let hash_u256 = U256::from_be_bytes(&hash);
        let range = Range256::new(
            hash_u256,
            hash_u256
                .checked_add(&U256::from_u64(1))
                .unwrap_or(U256::MAX),
        );
        // Remove this range from our WantList
        self.sync_state.my_want = self.sync_state.my_want.subtract(&Spore::from_range(range));
    }

    /// Check if sync is complete (nothing more to transfer).
    ///
    /// Based on the bilateral construction theorem: both nodes can
    /// independently verify sync completion from the flooded state.
    pub fn is_sync_complete(&self) -> bool {
        self.sync_state.is_complete()
    }

    /// Get the XOR of our HaveList with their HaveList.
    ///
    /// This reveals what differs between us. By the XOR cancellation
    /// theorem, matching content produces empty XOR.
    pub fn compute_xor(&self) -> Spore {
        self.sync_state.my_have.xor(&self.sync_state.their_have)
    }

    /// Get statistics about the sync state.
    pub fn stats(&self) -> SporeSyncStats {
        let xor = self.compute_xor();
        SporeSyncStats {
            my_content_count: self.content.len(),
            my_have_ranges: self.sync_state.my_have.range_count(),
            my_want_ranges: self.sync_state.my_want.range_count(),
            their_have_ranges: self.sync_state.their_have.range_count(),
            their_want_ranges: self.sync_state.their_want.range_count(),
            xor_ranges: xor.range_count(),
            pending_send: self.pending_send.len(),
            sync_complete: self.is_sync_complete(),
        }
    }
}

/// Statistics about SPORE sync state.
#[derive(Debug, Clone)]
pub struct SporeSyncStats {
    /// Number of content blocks in local store
    pub my_content_count: usize,
    /// Number of ranges in my HaveList
    pub my_have_ranges: usize,
    /// Number of ranges in my WantList
    pub my_want_ranges: usize,
    /// Number of ranges in their HaveList
    pub their_have_ranges: usize,
    /// Number of ranges in their WantList
    pub their_want_ranges: usize,
    /// Number of ranges in XOR (differences)
    pub xor_ranges: usize,
    /// Number of blocks pending to send
    pub pending_send: usize,
    /// Whether sync is complete
    pub sync_complete: bool,
}

/// Manager for multiple SPORE sync sessions.
///
/// Handles sync with multiple peers simultaneously, implementing
/// the "Full" knowledge mode where every node syncs with every other node.
#[derive(Debug)]
pub struct SporeSyncManager {
    /// Our peer ID
    peer_id: U256,
    /// Per-peer sync state
    peers: HashMap<U256, SporeSync>,
    /// Global content store (shared across all peer syncs)
    content: HashMap<[u8; 32], ContentBlock>,
}

impl SporeSyncManager {
    /// Create a new sync manager.
    pub fn new(peer_id: U256) -> Self {
        Self {
            peer_id,
            peers: HashMap::new(),
            content: HashMap::new(),
        }
    }

    /// Add content to the global store.
    pub fn add_content(&mut self, block: ContentBlock) {
        let hash = block.hash;
        self.content.insert(hash, block.clone());

        // Update all peer sync states
        for sync in self.peers.values_mut() {
            sync.add_content(block.clone());
        }
    }

    /// Get or create sync state for a peer.
    pub fn get_or_create_peer(&mut self, peer_id: U256) -> &mut SporeSync {
        self.peers.entry(peer_id).or_insert_with(|| {
            let mut sync = SporeSync::new(self.peer_id);
            // Copy existing content to new peer sync
            for (_, block) in &self.content {
                sync.add_content(block.clone());
            }
            sync
        })
    }

    /// Process SPORE message from a peer.
    pub fn receive_spore_message(&mut self, peer_id: U256, msg: SporeMessage) {
        let sync = self.get_or_create_peer(peer_id);
        sync.receive_spore_message(msg);
    }

    /// Get SPORE message to send to a peer.
    pub fn create_spore_message(&self, peer_id: &U256) -> Option<SporeMessage> {
        self.peers
            .get(peer_id)
            .map(|sync| sync.create_spore_message())
    }

    /// Receive content block from a peer.
    pub fn receive_content(&mut self, peer_id: U256, block: ContentBlock) {
        let hash = block.hash;

        // Verify hash
        let computed = blake3::hash(&block.data);
        if computed.as_bytes() != &hash {
            tracing::warn!("Content hash mismatch from peer {:?}", peer_id);
            return;
        }

        // Add to global store
        self.content.insert(hash, block.clone());

        // Update all peer sync states
        for (pid, sync) in self.peers.iter_mut() {
            if *pid == peer_id {
                // Mark as received for this peer
                sync.receive_content(block.clone());
            } else {
                // Mark as having for other peers
                sync.add_content(block.clone());
            }
        }
    }

    /// Get content to send to a specific peer.
    pub fn blocks_to_send(&self, peer_id: &U256) -> Vec<ContentBlock> {
        self.peers
            .get(peer_id)
            .map(|sync| sync.blocks_to_send().cloned().collect())
            .unwrap_or_default()
    }

    /// Get aggregate statistics across all peers.
    pub fn stats(&self) -> ManagerStats {
        let peer_stats: Vec<_> = self
            .peers
            .iter()
            .map(|(id, sync)| (*id, sync.stats()))
            .collect();

        let total_xor: usize = peer_stats.iter().map(|(_, s)| s.xor_ranges).sum();
        let all_synced = peer_stats.iter().all(|(_, s)| s.sync_complete);

        ManagerStats {
            content_count: self.content.len(),
            peer_count: self.peers.len(),
            total_xor_ranges: total_xor,
            all_synced,
            peer_stats,
        }
    }
}

/// Aggregate statistics for the sync manager.
#[derive(Debug, Clone)]
pub struct ManagerStats {
    /// Total content blocks in store
    pub content_count: usize,
    /// Number of peers
    pub peer_count: usize,
    /// Total XOR ranges across all peers
    pub total_xor_ranges: usize,
    /// Whether all peers are fully synced
    pub all_synced: bool,
    /// Per-peer statistics
    pub peer_stats: Vec<(U256, SporeSyncStats)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id(n: u64) -> U256 {
        U256::from_u64(n)
    }

    #[test]
    fn test_content_block_creation() {
        let block = ContentBlock::new(ContentType::PeerInfo, b"test data".to_vec());
        assert!(!block.hash.iter().all(|&b| b == 0));
        assert_eq!(block.content_type, ContentType::PeerInfo);
    }

    #[test]
    fn test_spore_sync_add_content() {
        let mut sync = SporeSync::new(test_peer_id(1));

        let block = ContentBlock::new(ContentType::Release, b"release data".to_vec());
        let hash = block.hash;

        sync.add_content(block);

        assert!(sync.has_content(&hash));
        assert!(!sync.sync_state.my_have.is_empty());
    }

    #[test]
    fn test_spore_message_exchange() {
        let mut alice = SporeSync::new(test_peer_id(1));
        let mut bob = SporeSync::new(test_peer_id(2));

        // Alice has some content
        let block1 = ContentBlock::new(ContentType::Release, b"release 1".to_vec());
        let block2 = ContentBlock::new(ContentType::Release, b"release 2".to_vec());
        alice.add_content(block1.clone());
        alice.add_content(block2.clone());

        // Bob has different content
        let block3 = ContentBlock::new(ContentType::Release, b"release 3".to_vec());
        bob.add_content(block3.clone());

        // Exchange SPORE messages
        let alice_msg = alice.create_spore_message();
        let bob_msg = bob.create_spore_message();

        alice.receive_spore_message(bob_msg);
        bob.receive_spore_message(alice_msg);

        // Alice should send 2 blocks (block1, block2)
        let alice_to_send: Vec<_> = alice.blocks_to_send().collect();
        assert_eq!(alice_to_send.len(), 2);

        // Bob should send 1 block (block3)
        let bob_to_send: Vec<_> = bob.blocks_to_send().collect();
        assert_eq!(bob_to_send.len(), 1);
    }

    #[test]
    fn test_xor_cancellation() {
        let mut alice = SporeSync::new(test_peer_id(1));
        let mut bob = SporeSync::new(test_peer_id(2));

        // Both have the same content
        let block = ContentBlock::new(ContentType::PeerInfo, b"shared data".to_vec());
        alice.add_content(block.clone());
        bob.add_content(block);

        // Exchange SPORE messages
        let alice_msg = alice.create_spore_message();
        let bob_msg = bob.create_spore_message();

        alice.receive_spore_message(bob_msg);
        bob.receive_spore_message(alice_msg);

        // XOR should be empty (or nearly empty) - they have the same content
        // Nothing to send because intersection of what I have and what they want is empty
        let alice_to_send: Vec<_> = alice.blocks_to_send().collect();
        let bob_to_send: Vec<_> = bob.blocks_to_send().collect();

        assert_eq!(alice_to_send.len(), 0, "Alice should have nothing to send");
        assert_eq!(bob_to_send.len(), 0, "Bob should have nothing to send");
    }

    #[test]
    fn test_sync_manager() {
        let mut manager = SporeSyncManager::new(test_peer_id(1));

        // Add content
        let block = ContentBlock::new(ContentType::Release, b"test release".to_vec());
        manager.add_content(block);

        // Create peer sync
        let peer_id = test_peer_id(2);
        let _sync = manager.get_or_create_peer(peer_id);

        // Stats should reflect state
        let stats = manager.stats();
        assert_eq!(stats.content_count, 1);
        assert_eq!(stats.peer_count, 1);
    }

    #[test]
    fn test_convergence_to_zero_overhead() {
        // Simulate multiple rounds of sync until convergence
        let mut alice = SporeSync::new(test_peer_id(1));
        let mut bob = SporeSync::new(test_peer_id(2));

        // Alice starts with some content
        for i in 0..10 {
            let block =
                ContentBlock::new(ContentType::Release, format!("release {}", i).into_bytes());
            alice.add_content(block);
        }

        // Initial exchange
        let alice_msg = alice.create_spore_message();
        let bob_msg = bob.create_spore_message();
        alice.receive_spore_message(bob_msg);
        bob.receive_spore_message(alice_msg);

        // Transfer content
        while let Some(block) = alice.take_next_to_send() {
            bob.receive_content(block);
        }

        // After sync, XOR should approach empty
        let alice_msg = alice.create_spore_message();
        let bob_msg = bob.create_spore_message();
        alice.receive_spore_message(bob_msg);
        bob.receive_spore_message(alice_msg);

        // Nothing more to send
        assert!(alice.blocks_to_send().next().is_none());
        assert!(bob.blocks_to_send().next().is_none());
    }
}
