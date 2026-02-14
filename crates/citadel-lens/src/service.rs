//! CVDF Service — Citadel VDF as a framework service
//!
//! This module provides the transport-agnostic CVDF service that consumers
//! plug into. Citadel owns all the VDF logic (chain, attestation, duty rotation,
//! merge evaluation). Consumers just implement `CvdfTransport` and call
//! `tick()` + `receive()`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use citadel_lens::service::{CvdfService, CvdfTransport, CvdfServiceMessage};
//!
//! struct MyTransport { /* ... */ }
//!
//! impl CvdfTransport for MyTransport {
//!     fn send_to(&self, peer: &[u8; 32], msg: CvdfServiceMessage) { /* ... */ }
//!     fn broadcast(&self, msg: CvdfServiceMessage) { /* ... */ }
//! }
//!
//! let service = CvdfService::new_genesis(seed, signing_key, transport);
//! // On timer: service.tick()
//! // On message: service.receive(&from, msg)
//! ```

use crate::cvdf::{CvdfCoordinator, CvdfRound, RoundAttestation};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

// ============================================================================
// Transport trait — consumers implement this
// ============================================================================

/// Transport abstraction for CVDF message delivery.
///
/// Consumers implement this to wire CVDF into their networking layer.
/// Citadel calls these methods; the consumer routes the bytes.
pub trait CvdfTransport: Send + Sync {
    /// Send a message to a specific peer (identified by Ed25519 public key).
    fn send_to(&self, peer: &[u8; 32], msg: CvdfServiceMessage);

    /// Broadcast a message to all connected peers.
    fn broadcast(&self, msg: CvdfServiceMessage);
}

// ============================================================================
// Wire protocol
// ============================================================================

/// Messages exchanged between CVDF participants.
///
/// Consumers serialize/deserialize these over their transport.
/// Citadel produces and consumes them via `CvdfService`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CvdfServiceMessage {
    /// Attestation for the next round — "I vouch for this chain tip"
    Attest(RoundAttestation),

    /// A new round was produced — "Here's the next block"
    Round(CvdfRound),

    /// Request chain sync from a specific height
    SyncReq { from_height: u64 },

    /// Response with chain rounds
    SyncResp { rounds: Vec<CvdfRound> },
}

// ============================================================================
// Status snapshot — for HELLO payloads and API responses
// ============================================================================

/// Snapshot of CVDF chain state.
///
/// Included in HELLO payloads so peers can compare chains
/// and decide whether to request sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CvdfStatus {
    /// Chain height (round number)
    pub height: u64,
    /// Chain weight (sum of all round weights — attestation-based)
    pub weight: u64,
    /// Hex-encoded tip output hash
    pub tip_hex: String,
    /// Hex-encoded genesis seed
    pub genesis_hex: String,
    /// Number of active SPIRAL slots attesting to this chain
    pub active_slots: usize,
}

// ============================================================================
// Merge actions — what to do after comparing with a peer
// ============================================================================

/// Action to take after evaluating a peer's CVDF status.
///
/// Returned by `evaluate_hello()`. The consumer executes the action
/// (typically by sending the appropriate `CvdfServiceMessage`).
#[derive(Clone, Debug)]
pub enum MergeAction {
    /// Their chain is heavier — request full sync
    RequestSync {
        /// Height to sync from (0 = full chain)
        from_height: u64,
        /// Peer to request from
        peer: [u8; 32],
    },
    /// Same chain or ours is heavier — nothing to do
    NoAction,
}

// ============================================================================
// The service — Citadel's state machine, consumer's entry point
// ============================================================================

/// The CVDF service. Wraps the cooperative VDF coordinator and handles
/// all message routing. Consumers call `tick()` periodically and
/// `receive()` on incoming messages. Everything else is Citadel's job.
pub struct CvdfService<T: CvdfTransport> {
    /// The cooperative VDF coordinator (chain + attestations + duty + liveness)
    coordinator: CvdfCoordinator,
    /// Consumer-provided transport
    transport: T,
    /// Genesis seed (for chain verification)
    genesis_seed: [u8; 32],
}

impl<T: CvdfTransport> std::fmt::Debug for CvdfService<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CvdfService")
            .field("height", &self.coordinator.height())
            .field("weight", &self.coordinator.weight())
            .field("genesis", &hex::encode(self.genesis_seed))
            .finish()
    }
}

impl<T: CvdfTransport> CvdfService<T> {
    /// Create a new CVDF service as the genesis node.
    ///
    /// This starts a fresh cooperative VDF chain.
    pub fn new_genesis(genesis_seed: [u8; 32], signing_key: SigningKey, transport: T) -> Self {
        let coordinator = CvdfCoordinator::new_genesis(genesis_seed, signing_key);
        Self {
            coordinator,
            transport,
            genesis_seed,
        }
    }

    /// Join an existing CVDF chain.
    ///
    /// Verifies the provided rounds and adopts the chain if valid.
    /// Returns `None` if the chain fails verification.
    pub fn join(
        genesis_seed: [u8; 32],
        rounds: Vec<CvdfRound>,
        signing_key: SigningKey,
        transport: T,
    ) -> Option<Self> {
        let coordinator = CvdfCoordinator::join(genesis_seed, rounds, signing_key)?;
        Some(Self {
            coordinator,
            transport,
            genesis_seed,
        })
    }

    // ========================================================================
    // Core API — consumers call these
    // ========================================================================

    /// Process an incoming CVDF message from a peer.
    ///
    /// Citadel handles all logic: attestation validation, round verification,
    /// chain adoption, sync responses. The consumer just delivers bytes.
    pub fn receive(&mut self, from: &[u8; 32], msg: CvdfServiceMessage) {
        match msg {
            CvdfServiceMessage::Attest(att) => {
                self.coordinator.receive_attestation(att);
            }
            CvdfServiceMessage::Round(round) => {
                self.coordinator.process_round(round);
            }
            CvdfServiceMessage::SyncReq { from_height } => {
                let rounds = self.coordinator.chain().rounds_from(from_height).to_vec();
                self.transport.send_to(from, CvdfServiceMessage::SyncResp { rounds });
            }
            CvdfServiceMessage::SyncResp { rounds } => {
                if self.coordinator.should_adopt(&rounds) {
                    self.coordinator.adopt(rounds);
                }
            }
        }
    }

    /// Called periodically by the consumer (e.g. every 5 seconds).
    ///
    /// Citadel handles:
    /// 1. Creating our attestation and broadcasting it
    /// 2. Checking if it's our turn to produce a round
    /// 3. If so, producing the round and broadcasting it
    ///
    /// The consumer just calls this on a timer.
    pub fn tick(&mut self) {
        // 1. Attest to current chain tip
        let att = self.coordinator.attest();
        self.coordinator.receive_attestation(att.clone());
        self.transport.broadcast(CvdfServiceMessage::Attest(att));

        // 2. If it's our turn, produce the next round
        if let Some(round) = self.coordinator.try_produce() {
            self.transport.broadcast(CvdfServiceMessage::Round(round));
        }
    }

    /// Evaluate a peer's CVDF status (from their HELLO payload).
    ///
    /// Returns an action the consumer should take. If the peer's chain
    /// is heavier, returns `RequestSync` — consumer should send a
    /// `CvdfServiceMessage::SyncReq` to that peer.
    pub fn evaluate_hello(&self, from: &[u8; 32], peer_status: &CvdfStatus) -> MergeAction {
        // Different genesis = incompatible chains
        if peer_status.genesis_hex != hex::encode(self.genesis_seed) {
            return MergeAction::NoAction;
        }

        // Their chain is heavier — we should sync
        if peer_status.weight > self.coordinator.weight() {
            // Find common ancestry height for incremental sync
            let from_height = if peer_status.height > self.coordinator.height() + 100 {
                // Way behind — request full chain
                0
            } else {
                // Close — request from our tip (incremental)
                self.coordinator.height()
            };

            return MergeAction::RequestSync {
                from_height,
                peer: *from,
            };
        }

        MergeAction::NoAction
    }

    /// Execute a merge action returned by `evaluate_hello()`.
    ///
    /// Convenience method that sends the appropriate message via transport.
    pub fn execute_action(&self, action: &MergeAction) {
        match action {
            MergeAction::RequestSync { from_height, peer } => {
                self.transport.send_to(
                    peer,
                    CvdfServiceMessage::SyncReq { from_height: *from_height },
                );
            }
            MergeAction::NoAction => {}
        }
    }

    // ========================================================================
    // Status queries
    // ========================================================================

    /// Get current CVDF status (for HELLO payloads, API responses, etc.)
    pub fn status(&self) -> CvdfStatus {
        CvdfStatus {
            height: self.coordinator.height(),
            weight: self.coordinator.weight(),
            tip_hex: hex::encode(self.coordinator.chain().tip_output()),
            genesis_hex: hex::encode(self.genesis_seed),
            active_slots: self.coordinator.registered_slots().len(),
        }
    }

    /// Chain weight — THE clump weight for merge comparison.
    ///
    /// Weight = sum of all round weights, where each round's weight =
    /// 1 + (attestation_count * ATTESTATION_WEIGHT). More attesters per
    /// round = heavier chain = dominant swarm. Collaboration wins.
    pub fn weight(&self) -> u64 {
        self.coordinator.weight()
    }

    /// Chain height (round number)
    pub fn height(&self) -> u64 {
        self.coordinator.height()
    }

    /// Register a peer's SPIRAL slot (from HELLO or slot claim message).
    pub fn register_peer_slot(&mut self, slot: u64, pubkey: [u8; 32]) {
        self.coordinator.register_slot(slot, pubkey);
    }

    /// Set our own SPIRAL slot.
    pub fn set_our_slot(&mut self, slot: u64) {
        self.coordinator.set_slot(slot);
    }

    /// Check if a specific slot is still live (attested recently).
    pub fn is_slot_live(&self, slot: u64) -> bool {
        self.coordinator.is_slot_live(slot)
    }

    /// Get stale slots that haven't attested recently.
    pub fn stale_slots(&self) -> Vec<u64> {
        self.coordinator.stale_slots()
    }

    /// Prune stale slots and return the pruned slot numbers.
    pub fn prune_stale_slots(&mut self) -> Vec<u64> {
        self.coordinator.prune_stale_slots()
    }

    /// Get all rounds for syncing to a new peer.
    pub fn all_rounds(&self) -> &[CvdfRound] {
        self.coordinator.chain().all_rounds()
    }

    /// Get the underlying coordinator (for advanced use).
    pub fn coordinator(&self) -> &CvdfCoordinator {
        &self.coordinator
    }

    /// Get the underlying coordinator mutably (for advanced use).
    pub fn coordinator_mut(&mut self) -> &mut CvdfCoordinator {
        &mut self.coordinator
    }

    /// Is it currently our turn to produce a round?
    pub fn is_our_turn(&self) -> bool {
        self.coordinator.is_our_turn()
    }

    /// Network health: record a fork detection (increases difficulty).
    pub fn record_fork(&mut self) {
        self.coordinator.record_fork();
    }

    /// Network health: record spam claim attempt (increases difficulty).
    pub fn record_spam(&mut self) {
        self.coordinator.record_spam();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex};

    /// Test transport that records all sent messages
    struct TestTransport {
        sent: Arc<Mutex<Vec<(Option<[u8; 32]>, CvdfServiceMessage)>>>,
    }

    impl TestTransport {
        fn new() -> (Self, Arc<Mutex<Vec<(Option<[u8; 32]>, CvdfServiceMessage)>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (Self { sent: sent.clone() }, sent)
        }
    }

    impl CvdfTransport for TestTransport {
        fn send_to(&self, peer: &[u8; 32], msg: CvdfServiceMessage) {
            self.sent.lock().unwrap().push((Some(*peer), msg));
        }
        fn broadcast(&self, msg: CvdfServiceMessage) {
            self.sent.lock().unwrap().push((None, msg));
        }
    }

    #[test]
    fn test_cvdf_service_genesis_and_status() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let (transport, _sent) = TestTransport::new();

        let service = CvdfService::new_genesis(genesis_seed, signing_key, transport);

        let status = service.status();
        assert_eq!(status.height, 0);
        assert_eq!(status.weight, 1); // genesis round weight
        assert_eq!(status.genesis_hex, hex::encode(genesis_seed));
        assert_eq!(status.active_slots, 0);
    }

    #[test]
    fn test_cvdf_service_tick_produces_round() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let (transport, sent) = TestTransport::new();

        let mut service = CvdfService::new_genesis(genesis_seed, signing_key, transport);

        // Register our slot so we have duty
        service.set_our_slot(0);
        service.register_peer_slot(0, pubkey);

        // Tick should produce attestation + round
        service.tick();

        let messages = sent.lock().unwrap();
        let has_attest = messages.iter().any(|(_, m)| matches!(m, CvdfServiceMessage::Attest(_)));
        let has_round = messages.iter().any(|(_, m)| matches!(m, CvdfServiceMessage::Round(_)));

        assert!(has_attest, "Should broadcast attestation");
        assert!(has_round, "Should broadcast round (our turn, have attestation)");
        assert_eq!(service.height(), 1);
    }

    #[test]
    fn test_cvdf_service_multi_node_cooperation() {
        let genesis_seed = [42u8; 32];
        let num_nodes = 5;

        let keys: Vec<SigningKey> = (0..num_nodes)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();
        let pubkeys: Vec<[u8; 32]> = keys.iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();

        // Build services
        let mut services: Vec<CvdfService<TestTransport>> = Vec::new();
        let mut sents: Vec<Arc<Mutex<Vec<(Option<[u8; 32]>, CvdfServiceMessage)>>>> = Vec::new();

        // Node 0 = genesis
        let (transport, sent) = TestTransport::new();
        let mut svc = CvdfService::new_genesis(genesis_seed, keys[0].clone(), transport);
        svc.set_our_slot(0);
        for (i, pk) in pubkeys.iter().enumerate() {
            svc.register_peer_slot(i as u64, *pk);
        }
        services.push(svc);
        sents.push(sent);

        // Nodes 1..4 join from genesis chain
        for (i, key) in keys.iter().enumerate().skip(1) {
            let rounds = services[0].all_rounds().to_vec();
            let (transport, sent) = TestTransport::new();
            let mut svc = CvdfService::join(genesis_seed, rounds, key.clone(), transport)
                .expect("Should join");
            svc.set_our_slot(i as u64);
            for (j, pk) in pubkeys.iter().enumerate() {
                svc.register_peer_slot(j as u64, *pk);
            }
            services.push(svc);
            sents.push(sent);
        }

        // Cooperatively produce 20 rounds.
        //
        // Simulates realistic distributed message flow:
        //   Phase 1: Non-duty nodes tick → create attestation, broadcast
        //   Phase 2: Attestations delivered to all nodes (including duty holder)
        //   Phase 3: Duty holder ticks → creates own attestation + produces
        //            round with all accumulated attestations
        //   Phase 4: Produced round delivered to all non-duty nodes
        let dummy_peer = [0u8; 32];

        for round_num in 0..20 {
            // Determine duty holder for this round
            let next_height = services[0].height() + 1;
            let duty_idx = (next_height as usize) % num_nodes;

            // Phase 1: Non-duty nodes tick (attest only, won't produce)
            for (i, sent) in sents.iter().enumerate() {
                sent.lock().unwrap().clear();
                // Skip clearing is already done above
            }
            for i in 0..num_nodes {
                if i != duty_idx {
                    sents[i].lock().unwrap().clear();
                    services[i].tick();
                }
            }

            // Phase 2: Collect attestations from non-duty nodes, deliver to ALL
            let mut attestations: Vec<RoundAttestation> = Vec::new();
            for i in 0..num_nodes {
                if i != duty_idx {
                    for (_, msg) in sents[i].lock().unwrap().iter() {
                        if let CvdfServiceMessage::Attest(att) = msg {
                            attestations.push(att.clone());
                        }
                    }
                }
            }
            for service in &mut services {
                for att in &attestations {
                    service.receive(&dummy_peer, CvdfServiceMessage::Attest(att.clone()));
                }
            }

            // Phase 3: Duty holder ticks — creates its own attestation,
            // receives it, then produces with all 5 attestations
            sents[duty_idx].lock().unwrap().clear();
            services[duty_idx].tick();

            // Phase 4: Collect produced round, deliver to all non-duty nodes
            let mut produced_round: Option<CvdfRound> = None;
            for (_, msg) in sents[duty_idx].lock().unwrap().iter() {
                if let CvdfServiceMessage::Round(round) = msg {
                    produced_round = Some(round.clone());
                }
            }

            let round = produced_round.unwrap_or_else(|| {
                panic!("Duty holder {} should have produced round {} (height {})",
                    duty_idx, round_num, next_height);
            });

            // Verify round has all 5 attesters
            assert_eq!(round.attester_count(), num_nodes,
                "Round {} should have {} attesters, got {}",
                round_num, num_nodes, round.attester_count());

            // Deliver to non-duty nodes
            for i in 0..num_nodes {
                if i != duty_idx {
                    services[i].receive(&dummy_peer, CvdfServiceMessage::Round(round.clone()));
                }
            }
        }

        // All nodes should be at same height with same weight
        let height = services[0].height();
        let weight = services[0].weight();

        for (i, service) in services.iter().enumerate() {
            assert_eq!(service.height(), height,
                "Node {} height mismatch: {} vs {}", i, service.height(), height);
            assert_eq!(service.weight(), weight,
                "Node {} weight mismatch: {} vs {}", i, service.weight(), weight);
        }

        assert_eq!(height, 20, "Should have produced exactly 20 rounds");
        // Weight = genesis(1) + 20 rounds * (1 base + 5 attesters) = 1 + 120 = 121
        assert_eq!(weight, 1 + 20 * (1 + num_nodes as u64),
            "Weight should be genesis + 20 * (1 + 5 attesters)");
    }

    #[test]
    fn test_cvdf_service_evaluate_hello_triggers_sync() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let (transport, _sent) = TestTransport::new();

        let service = CvdfService::new_genesis(genesis_seed, signing_key, transport);

        // Peer claims heavier chain
        let peer_id = [99u8; 32];
        let peer_status = CvdfStatus {
            height: 100,
            weight: 1000,
            tip_hex: "deadbeef".to_string(),
            genesis_hex: hex::encode(genesis_seed),
            active_slots: 10,
        };

        let action = service.evaluate_hello(&peer_id, &peer_status);
        match action {
            MergeAction::RequestSync { from_height, peer } => {
                assert_eq!(peer, peer_id);
                assert_eq!(from_height, 0); // Way behind, request full chain
            }
            _ => panic!("Should request sync from heavier peer"),
        }
    }

    #[test]
    fn test_cvdf_service_evaluate_hello_ignores_lighter() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let (transport, _sent) = TestTransport::new();

        let service = CvdfService::new_genesis(genesis_seed, signing_key, transport);

        // Peer has lighter chain
        let peer_id = [99u8; 32];
        let peer_status = CvdfStatus {
            height: 0,
            weight: 0,
            tip_hex: "deadbeef".to_string(),
            genesis_hex: hex::encode(genesis_seed),
            active_slots: 0,
        };

        let action = service.evaluate_hello(&peer_id, &peer_status);
        assert!(matches!(action, MergeAction::NoAction));
    }

    #[test]
    fn test_cvdf_service_evaluate_hello_ignores_different_genesis() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let (transport, _sent) = TestTransport::new();

        let service = CvdfService::new_genesis(genesis_seed, signing_key, transport);

        // Peer from different genesis (different network)
        let peer_id = [99u8; 32];
        let peer_status = CvdfStatus {
            height: 9999,
            weight: 999999,
            tip_hex: "deadbeef".to_string(),
            genesis_hex: hex::encode([0u8; 32]),
            active_slots: 100,
        };

        let action = service.evaluate_hello(&peer_id, &peer_status);
        assert!(matches!(action, MergeAction::NoAction));
    }

    #[test]
    fn test_cvdf_service_sync_response() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let (transport, sent) = TestTransport::new();

        let mut service = CvdfService::new_genesis(genesis_seed, signing_key, transport);
        service.set_our_slot(0);
        service.register_peer_slot(0, pubkey);

        // Produce a few rounds
        for _ in 0..5 {
            service.tick();
        }

        // Clear sent
        sent.lock().unwrap().clear();

        // Receive a sync request
        let requester = [88u8; 32];
        service.receive(&requester, CvdfServiceMessage::SyncReq { from_height: 0 });

        // Should have sent a SyncResp to the requester
        let messages = sent.lock().unwrap();
        let sync_resp = messages.iter().find(|(peer, msg)| {
            *peer == Some(requester) && matches!(msg, CvdfServiceMessage::SyncResp { .. })
        });

        assert!(sync_resp.is_some(), "Should respond with SyncResp");
        if let Some((_, CvdfServiceMessage::SyncResp { rounds })) = sync_resp {
            assert!(!rounds.is_empty(), "Should include rounds");
        }
    }
}
