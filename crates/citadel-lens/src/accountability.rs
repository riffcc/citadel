//! Mesh Accountability: Unified vouching, latency proofs, and failure detection
//!
//! # The Key Insight
//!
//! Neighbors vouch for neighbors. The SPIRAL topology IS the accountability system.
//!
//! ```text
//!      Your 20 SPIRAL neighbors are watching you
//!                   ↓
//!     [N1]  [N2]  [N3]  [N4]  ...  [N20]
//!        \    |    |    /
//!         \   |    |   /
//!          → [YOU] ←
//!               ↓
//!     Misbehave? Lie? Fail to coordinate?
//!               ↓
//!     Neighbors disconnect + witness your failure
//!               ↓
//!     No vouchers = slot invalid
//! ```
//!
//! # Symmetric Protocol: Join = Reverse(Leave)
//!
//! ```text
//! JOIN:  Empty slot → TGP with neighbors → Accumulate vouches → Threshold met → VALID
//! LEAVE: Valid slot → TGP reverse → Vouches expire/withdrawn → Below threshold → INVALID
//! ```
//!
//! Same protocol, same proofs, same guarantees. Just reversed.
//!
//! Dead node detection is NOT a separate mechanism - it's vouches expiring naturally
//! when neighbors stop receiving latency responses.
//!
//! # Vouch Rotation (O(n) traffic)
//!
//! Instead of flooding vouches for all 20 neighbors every round:
//! - Rotate: vouch for 1 neighbor per round
//! - After 20 rounds, all neighbors have fresh vouches
//! - Network trends to zero traffic at steady state
//!
//! # Bilateral Vouch Construction
//!
//! Node X collects vouches FROM neighbors and propagates them:
//! 1. X exchanges latency with neighbor Y
//! 2. Y signs "X is alive at height H"
//! 3. X collects this vouch and propagates it once
//! 4. Everyone can verify Y's signature
//!
//! This is TGP applied to liveness!
//!
//! # Components
//!
//! 1. **LatencyProof** - Challenge/response proving round-trip time
//! 2. **FailureProof** - Witnesses (neighbors) attesting to failure
//! 3. **SlotVouch** - Neighbor vouching that a slot holder is behaving
//! 4. **SlotAction** - Symmetric Claim/Release operations
//!
//! # Consensus Tiers (scales with neighbor count)
//!
//! - 1 node: Genesis (no consensus needed)
//! - 2 nodes: Two-party TGP
//! - 3 nodes: Three-party TGP
//! - 4+ nodes: Full TGP-BFT

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::vdf_race::signature_serde;

/// Latency proof: cryptographic proof of round-trip time to a neighbor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyProof {
    /// Random challenge sent to neighbor
    pub challenge: [u8; 32],
    /// Response = H(challenge || responder_pubkey)
    pub response: [u8; 32],
    /// Timestamp when challenge was sent (local, not trusted)
    pub sent_at_ms: u64,
    /// Timestamp when response was received (local, not trusted)
    pub received_at_ms: u64,
    /// Responder's public key
    pub responder: [u8; 32],
    /// Responder's signature over (challenge || response)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl LatencyProof {
    /// Generate a new challenge for latency measurement
    pub fn new_challenge() -> [u8; 32] {
        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge).expect("RNG failed");
        challenge
    }

    /// Create response to a latency challenge
    pub fn respond(challenge: &[u8; 32], signing_key: &SigningKey) -> ([u8; 32], [u8; 64]) {
        let responder = signing_key.verifying_key().to_bytes();

        // Response = H(challenge || responder_pubkey)
        let mut hasher = blake3::Hasher::new();
        hasher.update(challenge);
        hasher.update(&responder);
        let response = *hasher.finalize().as_bytes();

        // Sign (challenge || response)
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(challenge);
        msg.extend_from_slice(&response);
        let signature = signing_key.sign(&msg);

        (response, signature.to_bytes())
    }

    /// Complete a latency proof after receiving response
    pub fn complete(
        challenge: [u8; 32],
        response: [u8; 32],
        responder: [u8; 32],
        signature: [u8; 64],
        sent_at_ms: u64,
        received_at_ms: u64,
    ) -> Option<Self> {
        let proof = Self {
            challenge,
            response,
            sent_at_ms,
            received_at_ms,
            responder,
            signature,
        };

        if proof.verify() {
            Some(proof)
        } else {
            None
        }
    }

    /// Verify the latency proof
    pub fn verify(&self) -> bool {
        // Verify response is correct
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.challenge);
        hasher.update(&self.responder);
        let expected_response = *hasher.finalize().as_bytes();

        if self.response != expected_response {
            return false;
        }

        // Verify signature
        let verifying_key = match VerifyingKey::from_bytes(&self.responder) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(&self.challenge);
        msg.extend_from_slice(&self.response);

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Get measured latency in milliseconds
    pub fn latency_ms(&self) -> u64 {
        self.received_at_ms.saturating_sub(self.sent_at_ms)
    }
}

/// Failure proof: witnesses attesting that a node failed to coordinate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureProof {
    /// The failed node's public key
    pub failed_node: [u8; 32],
    /// The failed node's slot (if known)
    pub failed_slot: Option<u64>,
    /// Last successful coordination timestamp
    pub last_seen_ms: u64,
    /// Type of failure detected
    pub failure_type: FailureType,
    /// Witnesses (neighbors who observed the failure)
    pub witnesses: Vec<FailureWitness>,
}

/// Type of failure detected
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureType {
    /// Node stopped responding to challenges
    Unresponsive,
    /// Node provided invalid/lying responses
    InvalidResponse,
    /// Node failed BFT coordination
    BftFailure,
    /// Node claimed wrong position in mesh
    PositionLie,
    /// Node failed to relay messages properly
    RelayFailure,
}

/// A witness attestation to a failure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureWitness {
    /// Witness public key (a neighbor of the failed node)
    pub witness: [u8; 32],
    /// Witness's slot in the mesh
    pub witness_slot: u64,
    /// Timestamp of observation
    pub observed_at_ms: u64,
    /// Last latency proof the witness has for the failed node
    pub last_latency_proof: Option<LatencyProof>,
    /// Signature over failure attestation
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl FailureWitness {
    /// Create a failure witness attestation
    pub fn new(
        failed_node: [u8; 32],
        failure_type: &FailureType,
        witness_slot: u64,
        last_latency_proof: Option<LatencyProof>,
        signing_key: &SigningKey,
    ) -> Self {
        let witness = signing_key.verifying_key().to_bytes();
        let observed_at_ms = now_ms();

        // Sign (failed_node || failure_type || observed_at)
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(&failed_node);
        msg.push(failure_type_to_u8(failure_type));
        msg.extend_from_slice(&observed_at_ms.to_le_bytes());

        let signature = signing_key.sign(&msg);

        Self {
            witness,
            witness_slot,
            observed_at_ms,
            last_latency_proof,
            signature: signature.to_bytes(),
        }
    }

    /// Verify witness signature
    pub fn verify(&self, failed_node: &[u8; 32], failure_type: &FailureType) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.witness) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(failed_node);
        msg.push(failure_type_to_u8(failure_type));
        msg.extend_from_slice(&self.observed_at_ms.to_le_bytes());

        verifying_key.verify(&msg, &signature).is_ok()
    }
}

impl FailureProof {
    /// Create a new failure proof with initial witness
    pub fn new(
        failed_node: [u8; 32],
        failed_slot: Option<u64>,
        last_seen_ms: u64,
        failure_type: FailureType,
        initial_witness: FailureWitness,
    ) -> Self {
        Self {
            failed_node,
            failed_slot,
            last_seen_ms,
            failure_type,
            witnesses: vec![initial_witness],
        }
    }

    /// Add a witness to the failure proof
    pub fn add_witness(&mut self, witness: FailureWitness) -> bool {
        // Verify the witness
        if !witness.verify(&self.failed_node, &self.failure_type) {
            return false;
        }

        // Don't add duplicate witnesses
        if self.witnesses.iter().any(|w| w.witness == witness.witness) {
            return false;
        }

        self.witnesses.push(witness);
        true
    }

    /// Check if failure proof has sufficient witnesses for the given neighbor count
    pub fn is_sufficient(&self, total_neighbors: usize) -> bool {
        // Consensus tier determines required witnesses
        match total_neighbors {
            0 | 1 => true, // Genesis/solo - any witness counts
            2 => self.witnesses.len() >= 1, // Two-party - 1 witness
            3 => self.witnesses.len() >= 2, // Three-party - 2 witnesses
            _ => self.witnesses.len() >= (total_neighbors / 2) + 1, // BFT majority
        }
    }

    /// Verify all witnesses
    pub fn verify(&self) -> bool {
        self.witnesses.iter().all(|w| w.verify(&self.failed_node, &self.failure_type))
    }
}

/// Slot vouch: a neighbor vouching that a slot holder is behaving correctly
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotVouch {
    /// The slot being vouched for
    pub slot: u64,
    /// The slot holder's public key
    pub holder: [u8; 32],
    /// The voucher's public key (must be a SPIRAL neighbor)
    pub voucher: [u8; 32],
    /// The voucher's slot
    pub voucher_slot: u64,
    /// Most recent latency proof to the holder
    pub latency_proof: LatencyProof,
    /// VDF height when vouch was made
    pub vdf_height: u64,
    /// Signature over vouch
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl SlotVouch {
    /// Create a new vouch for a slot holder
    pub fn new(
        slot: u64,
        holder: [u8; 32],
        voucher_slot: u64,
        latency_proof: LatencyProof,
        vdf_height: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let voucher = signing_key.verifying_key().to_bytes();

        // Sign (slot || holder || voucher_slot || vdf_height)
        let mut msg = Vec::with_capacity(56);
        msg.extend_from_slice(&slot.to_le_bytes());
        msg.extend_from_slice(&holder);
        msg.extend_from_slice(&voucher_slot.to_le_bytes());
        msg.extend_from_slice(&vdf_height.to_le_bytes());

        let signature = signing_key.sign(&msg);

        Self {
            slot,
            holder,
            voucher,
            voucher_slot,
            latency_proof,
            vdf_height,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the vouch signature and latency proof
    pub fn verify(&self) -> bool {
        // Verify latency proof first
        if !self.latency_proof.verify() {
            return false;
        }

        // Latency proof must be to the holder
        if self.latency_proof.responder != self.holder {
            return false;
        }

        // Verify vouch signature
        let verifying_key = match VerifyingKey::from_bytes(&self.voucher) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(56);
        msg.extend_from_slice(&self.slot.to_le_bytes());
        msg.extend_from_slice(&self.holder);
        msg.extend_from_slice(&self.voucher_slot.to_le_bytes());
        msg.extend_from_slice(&self.vdf_height.to_le_bytes());

        verifying_key.verify(&msg, &signature).is_ok()
    }
}

/// Slot validity state - tracks vouches for a slot
#[derive(Clone, Debug, Default)]
pub struct SlotValidity {
    /// Vouches for this slot (voucher_pubkey -> vouch)
    vouches: HashMap<[u8; 32], SlotVouch>,
    /// Expected neighbor count for this slot position
    expected_neighbors: usize,
}

impl SlotValidity {
    pub fn new(expected_neighbors: usize) -> Self {
        Self {
            vouches: HashMap::new(),
            expected_neighbors,
        }
    }

    /// Add or update a vouch
    pub fn add_vouch(&mut self, vouch: SlotVouch) -> bool {
        if !vouch.verify() {
            return false;
        }

        // Update if newer VDF height or first vouch from this voucher
        let dominated = if let Some(existing) = self.vouches.get(&vouch.voucher) {
            vouch.vdf_height > existing.vdf_height
        } else {
            true
        };

        if dominated {
            self.vouches.insert(vouch.voucher, vouch);
            true
        } else {
            false
        }
    }

    /// Remove a vouch (neighbor disconnected/failed)
    pub fn remove_vouch(&mut self, voucher: &[u8; 32]) {
        self.vouches.remove(voucher);
    }

    /// Check if slot has sufficient vouches to be valid
    pub fn is_valid(&self) -> bool {
        // Scales with expected neighbor count (consensus tier)
        match self.expected_neighbors {
            0 => true, // Genesis
            1 => !self.vouches.is_empty(), // 1 vouch needed
            2 => self.vouches.len() >= 1, // 1 of 2
            3 => self.vouches.len() >= 2, // 2 of 3
            n => self.vouches.len() >= (n / 2) + 1, // BFT majority
        }
    }

    /// Get vouch count
    pub fn vouch_count(&self) -> usize {
        self.vouches.len()
    }

    /// Get average latency from vouches
    pub fn avg_latency_ms(&self) -> Option<u64> {
        if self.vouches.is_empty() {
            return None;
        }
        let total: u64 = self.vouches.values()
            .map(|v| v.latency_proof.latency_ms())
            .sum();
        Some(total / self.vouches.len() as u64)
    }

    /// Prune stale vouches (older than max_vdf_age)
    pub fn prune_stale(&mut self, current_vdf_height: u64, max_age: u64) {
        self.vouches.retain(|_, v| {
            current_vdf_height.saturating_sub(v.vdf_height) <= max_age
        });
    }
}

/// Pending latency challenge being measured
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub challenge: [u8; 32],
    pub target: [u8; 32],
    pub sent_at: Instant,
    pub sent_at_ms: u64,
}

/// Neighbor accountability tracker
#[derive(Debug)]
pub struct AccountabilityTracker {
    /// Our signing key
    signing_key: SigningKey,
    /// Our slot
    our_slot: Option<u64>,
    /// Pending latency challenges we've sent
    pending_challenges: HashMap<[u8; 32], PendingChallenge>, // challenge -> pending
    /// Latest latency proofs for each neighbor
    latency_proofs: HashMap<[u8; 32], LatencyProof>, // neighbor_pubkey -> proof
    /// Slot validity state for all known slots
    slot_validity: HashMap<u64, SlotValidity>, // slot -> validity
    /// Active failure proofs we're building
    active_failures: HashMap<[u8; 32], FailureProof>, // failed_node -> proof
    /// Current VDF height (for vouch age tracking)
    vdf_height: u64,
}

impl AccountabilityTracker {
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            our_slot: None,
            pending_challenges: HashMap::new(),
            latency_proofs: HashMap::new(),
            slot_validity: HashMap::new(),
            active_failures: HashMap::new(),
            vdf_height: 0,
        }
    }

    /// Set our slot
    pub fn set_slot(&mut self, slot: u64) {
        self.our_slot = Some(slot);
    }

    /// Update VDF height
    pub fn set_vdf_height(&mut self, height: u64) {
        self.vdf_height = height;
    }

    /// Start a latency challenge to a neighbor
    pub fn start_challenge(&mut self, target: [u8; 32]) -> [u8; 32] {
        let challenge = LatencyProof::new_challenge();
        let now = Instant::now();

        self.pending_challenges.insert(challenge, PendingChallenge {
            challenge,
            target,
            sent_at: now,
            sent_at_ms: now_ms(),
        });

        challenge
    }

    /// Respond to a latency challenge from a neighbor
    pub fn respond_to_challenge(&self, challenge: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        LatencyProof::respond(challenge, &self.signing_key)
    }

    /// Complete a latency proof when we receive a response
    pub fn complete_challenge(
        &mut self,
        challenge: [u8; 32],
        response: [u8; 32],
        signature: [u8; 64],
    ) -> Option<LatencyProof> {
        let pending = self.pending_challenges.remove(&challenge)?;
        let received_at_ms = now_ms();

        let proof = LatencyProof::complete(
            challenge,
            response,
            pending.target,
            signature,
            pending.sent_at_ms,
            received_at_ms,
        )?;

        self.latency_proofs.insert(pending.target, proof.clone());
        Some(proof)
    }

    /// Create a vouch for a neighbor's slot
    pub fn create_vouch(&self, slot: u64, holder: [u8; 32]) -> Option<SlotVouch> {
        let latency_proof = self.latency_proofs.get(&holder)?.clone();
        let voucher_slot = self.our_slot?;

        Some(SlotVouch::new(
            slot,
            holder,
            voucher_slot,
            latency_proof,
            self.vdf_height,
            &self.signing_key,
        ))
    }

    /// Process an incoming vouch
    pub fn process_vouch(&mut self, vouch: SlotVouch, expected_neighbors: usize) -> bool {
        let validity = self.slot_validity
            .entry(vouch.slot)
            .or_insert_with(|| SlotValidity::new(expected_neighbors));

        validity.add_vouch(vouch)
    }

    /// Start tracking a failure
    pub fn start_failure_tracking(
        &mut self,
        failed_node: [u8; 32],
        failed_slot: Option<u64>,
        failure_type: FailureType,
    ) -> FailureWitness {
        let last_latency = self.latency_proofs.get(&failed_node).cloned();
        let last_seen_ms = last_latency.as_ref()
            .map(|p| p.received_at_ms)
            .unwrap_or(0);

        let witness = FailureWitness::new(
            failed_node,
            &failure_type,
            self.our_slot.unwrap_or(0),
            last_latency,
            &self.signing_key,
        );

        let proof = FailureProof::new(
            failed_node,
            failed_slot,
            last_seen_ms,
            failure_type,
            witness.clone(),
        );

        self.active_failures.insert(failed_node, proof);
        witness
    }

    /// Add external witness to a failure proof
    pub fn add_failure_witness(&mut self, failed_node: [u8; 32], witness: FailureWitness) -> bool {
        if let Some(proof) = self.active_failures.get_mut(&failed_node) {
            proof.add_witness(witness)
        } else {
            false
        }
    }

    /// Get failure proof if sufficient witnesses
    pub fn get_failure_proof(&self, failed_node: &[u8; 32], total_neighbors: usize) -> Option<&FailureProof> {
        self.active_failures.get(failed_node)
            .filter(|p| p.is_sufficient(total_neighbors))
    }

    /// Check if a slot is currently valid (has sufficient vouches)
    pub fn is_slot_valid(&self, slot: u64) -> bool {
        self.slot_validity.get(&slot)
            .map(|v| v.is_valid())
            .unwrap_or(false)
    }

    /// Remove vouches from a failed/disconnected neighbor
    pub fn remove_voucher(&mut self, voucher: &[u8; 32]) {
        for validity in self.slot_validity.values_mut() {
            validity.remove_vouch(voucher);
        }
        self.latency_proofs.remove(voucher);
    }

    /// Get latency to a neighbor
    pub fn get_latency(&self, neighbor: &[u8; 32]) -> Option<u64> {
        self.latency_proofs.get(neighbor).map(|p| p.latency_ms())
    }

    /// Prune stale data
    pub fn prune_stale(&mut self, max_vouch_age: u64, challenge_timeout: Duration) {
        // Prune stale vouches
        for validity in self.slot_validity.values_mut() {
            validity.prune_stale(self.vdf_height, max_vouch_age);
        }

        // Prune timed-out challenges
        self.pending_challenges.retain(|_, p| {
            p.sent_at.elapsed() < challenge_timeout
        });
    }

    /// Get all slots that have become invalid
    pub fn invalid_slots(&self) -> Vec<u64> {
        self.slot_validity.iter()
            .filter(|(_, v)| !v.is_valid())
            .map(|(slot, _)| *slot)
            .collect()
    }
}

// Helper functions

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn failure_type_to_u8(ft: &FailureType) -> u8 {
    match ft {
        FailureType::Unresponsive => 0,
        FailureType::InvalidResponse => 1,
        FailureType::BftFailure => 2,
        FailureType::PositionLie => 3,
        FailureType::RelayFailure => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_latency_proof_roundtrip() {
        let responder_key = SigningKey::generate(&mut OsRng);
        let challenge = LatencyProof::new_challenge();

        let (response, signature) = LatencyProof::respond(&challenge, &responder_key);

        let proof = LatencyProof::complete(
            challenge,
            response,
            responder_key.verifying_key().to_bytes(),
            signature,
            1000,
            1050,
        );

        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert!(proof.verify());
        assert_eq!(proof.latency_ms(), 50);
    }

    #[test]
    fn test_failure_witness() {
        let witness_key = SigningKey::generate(&mut OsRng);
        let failed_node = [42u8; 32];

        let witness = FailureWitness::new(
            failed_node,
            &FailureType::Unresponsive,
            5,
            None,
            &witness_key,
        );

        assert!(witness.verify(&failed_node, &FailureType::Unresponsive));
        assert!(!witness.verify(&failed_node, &FailureType::BftFailure));
    }

    #[test]
    fn test_slot_vouch() {
        let holder_key = SigningKey::generate(&mut OsRng);
        let voucher_key = SigningKey::generate(&mut OsRng);

        // Create latency proof first
        let challenge = LatencyProof::new_challenge();
        let (response, sig) = LatencyProof::respond(&challenge, &holder_key);
        let latency_proof = LatencyProof::complete(
            challenge,
            response,
            holder_key.verifying_key().to_bytes(),
            sig,
            1000,
            1020,
        ).unwrap();

        // Create vouch
        let vouch = SlotVouch::new(
            0,
            holder_key.verifying_key().to_bytes(),
            1,
            latency_proof,
            100,
            &voucher_key,
        );

        assert!(vouch.verify());
    }

    #[test]
    fn test_slot_validity_consensus_tiers() {
        // Genesis - always valid
        let mut validity = SlotValidity::new(0);
        assert!(validity.is_valid());

        // 2 nodes - need 1 vouch
        let mut validity = SlotValidity::new(2);
        assert!(!validity.is_valid());

        // Add a vouch
        let holder_key = SigningKey::generate(&mut OsRng);
        let voucher_key = SigningKey::generate(&mut OsRng);
        let challenge = LatencyProof::new_challenge();
        let (response, sig) = LatencyProof::respond(&challenge, &holder_key);
        let latency_proof = LatencyProof::complete(
            challenge, response,
            holder_key.verifying_key().to_bytes(),
            sig, 1000, 1020,
        ).unwrap();

        let vouch = SlotVouch::new(
            0, holder_key.verifying_key().to_bytes(),
            1, latency_proof, 100, &voucher_key,
        );
        validity.add_vouch(vouch);
        assert!(validity.is_valid());

        // 4 nodes - need 3 vouches (majority)
        let validity = SlotValidity::new(4);
        assert!(!validity.is_valid()); // No vouches yet
    }

    #[test]
    fn test_accountability_tracker_flow() {
        let our_key = SigningKey::generate(&mut OsRng);
        let neighbor_key = SigningKey::generate(&mut OsRng);

        let mut tracker = AccountabilityTracker::new(our_key);
        tracker.set_slot(0);
        tracker.set_vdf_height(100);

        // Start challenge
        let challenge = tracker.start_challenge(neighbor_key.verifying_key().to_bytes());

        // Neighbor responds
        let (response, sig) = LatencyProof::respond(&challenge, &neighbor_key);

        // Complete challenge
        let proof = tracker.complete_challenge(challenge, response, sig);
        assert!(proof.is_some());

        // Create vouch for neighbor
        let vouch = tracker.create_vouch(1, neighbor_key.verifying_key().to_bytes());
        assert!(vouch.is_some());
    }
}
