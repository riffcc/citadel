//! Proof of Latency (PoL) - VDF-Backed Mesh Optimization
//!
//! # The Key Insight
//!
//! ```text
//! VDF ≠ PoW
//!
//! PoW:  "I burned energy"  → parallelizable → wasteful arms race
//! VDF:  "Time passed"      → SEQUENTIAL    → proves you WAITED
//!
//! You can't fake waiting. You can't parallelize sequential computation.
//! Proof of Latency is proof that time passed between you and your neighbors.
//! ```
//!
//! # Atomic Slot Swapping
//!
//! If swapping positions with another node would reduce BOTH nodes' average
//! latency to their neighbors, they can:
//!
//! 1. **PROPOSE**: Attach VDF proof of latency measurements
//! 2. **HALFLOCK**: Both nodes enter tentative swap state
//! 3. **CONSENSUS**: Establish TGP with new neighbor sets
//! 4. **ATTACK/RETREAT**: Finalize swap or abort (TGP-style bilateral decision)
//!
//! No sync interruptions. UDP/TGP is sessionless - "connections" are just
//! who you're currently talking to.
//!
//! # Properties (Proven in Lean)
//!
//! - **Pareto Improvement**: Swap only happens if BOTH parties benefit
//! - **Atomic Transition**: No intermediate invalid states
//! - **Zero Sync Interruption**: Old connections work until new ones ready
//! - **Deterministic Resolution**: ATTACK/RETREAT has unique outcome

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Freshness threshold for latency proofs (in VDF blocks)
pub const FRESHNESS_THRESHOLD: u64 = 100;

/// Minimum latency improvement required for swap (microseconds)
pub const MIN_IMPROVEMENT_US: u64 = 1000; // 1ms

/// A VDF-backed proof of latency between two nodes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyProof {
    /// Source node public key
    pub from_node: [u8; 32],
    /// Target node public key
    pub to_node: [u8; 32],
    /// Measured round-trip latency (microseconds)
    pub latency_us: u64,
    /// VDF height when measurement was taken
    pub vdf_height: u64,
    /// VDF output at measurement time (for verification)
    pub vdf_output: [u8; 32],
    /// Timestamp of measurement (informational)
    pub timestamp_ms: u64,
    /// Signature over (from_node || to_node || latency_us || vdf_height || vdf_output)
    #[serde(with = "crate::vdf_race::signature_serde")]
    pub signature: [u8; 64],
}

impl LatencyProof {
    /// Create a new latency proof
    pub fn new(
        from_node: [u8; 32],
        to_node: [u8; 32],
        latency_us: u64,
        vdf_height: u64,
        vdf_output: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let mut msg = Vec::with_capacity(104);
        msg.extend_from_slice(&from_node);
        msg.extend_from_slice(&to_node);
        msg.extend_from_slice(&latency_us.to_le_bytes());
        msg.extend_from_slice(&vdf_height.to_le_bytes());
        msg.extend_from_slice(&vdf_output);

        let signature = signing_key.sign(&msg);

        Self {
            from_node,
            to_node,
            latency_us,
            vdf_height,
            vdf_output,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the proof signature
    pub fn verify_signature(&self) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.from_node) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(104);
        msg.extend_from_slice(&self.from_node);
        msg.extend_from_slice(&self.to_node);
        msg.extend_from_slice(&self.latency_us.to_le_bytes());
        msg.extend_from_slice(&self.vdf_height.to_le_bytes());
        msg.extend_from_slice(&self.vdf_output);

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Check if proof is fresh (within threshold of current VDF height)
    pub fn is_fresh(&self, current_vdf_height: u64) -> bool {
        current_vdf_height.saturating_sub(self.vdf_height) <= FRESHNESS_THRESHOLD
    }
}

/// State of a slot in the swap protocol
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotState {
    /// Normal operation
    Active,
    /// Tentatively swapping with another slot
    HalfLock {
        /// Target slot we're swapping with
        target_slot: u64,
        /// Target node's public key
        target_node: [u8; 32],
        /// Proposal that initiated this
        proposal_height: u64,
    },
    /// Finalizing swap (ATTACK committed)
    Swapping {
        /// Target slot we're swapping with
        target_slot: u64,
        /// Target node's public key
        target_node: [u8; 32],
    },
}

impl SlotState {
    /// Check if we're in active state
    pub fn is_active(&self) -> bool {
        matches!(self, SlotState::Active)
    }

    /// Check if we're halflocked with a specific node
    pub fn is_halflocked_with(&self, node: &[u8; 32]) -> bool {
        matches!(self, SlotState::HalfLock { target_node, .. } if target_node == node)
    }

    /// Get the target slot if in halflock or swapping state
    pub fn target_slot(&self) -> Option<u64> {
        match self {
            SlotState::Active => None,
            SlotState::HalfLock { target_slot, .. } => Some(*target_slot),
            SlotState::Swapping { target_slot, .. } => Some(*target_slot),
        }
    }
}

/// A proposal to swap slots between two nodes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapProposal {
    /// Initiating node's public key
    pub initiator: [u8; 32],
    /// Target node's public key
    pub target: [u8; 32],
    /// Initiator's current slot
    pub initiator_slot: u64,
    /// Target's current slot
    pub target_slot: u64,
    /// Latency proofs showing initiator's current position
    pub initiator_proofs: Vec<LatencyProof>,
    /// Latency proofs showing what initiator would have at target's position
    pub initiator_at_target_proofs: Vec<LatencyProof>,
    /// VDF height of proposal
    pub proposal_height: u64,
    /// VDF output at proposal time
    pub proposal_vdf_output: [u8; 32],
    /// Signature over proposal
    #[serde(with = "crate::vdf_race::signature_serde")]
    pub signature: [u8; 64],
}

impl SwapProposal {
    /// Create a new swap proposal
    pub fn new(
        initiator_slot: u64,
        target_slot: u64,
        target: [u8; 32],
        initiator_proofs: Vec<LatencyProof>,
        initiator_at_target_proofs: Vec<LatencyProof>,
        vdf_height: u64,
        vdf_output: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let initiator = signing_key.verifying_key().to_bytes();

        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&initiator);
        msg.extend_from_slice(&target);
        msg.extend_from_slice(&initiator_slot.to_le_bytes());
        msg.extend_from_slice(&target_slot.to_le_bytes());
        msg.extend_from_slice(&vdf_height.to_le_bytes());
        msg.extend_from_slice(&vdf_output);

        let signature = signing_key.sign(&msg);

        Self {
            initiator,
            target,
            initiator_slot,
            target_slot,
            initiator_proofs,
            initiator_at_target_proofs,
            proposal_height: vdf_height,
            proposal_vdf_output: vdf_output,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the proposal signature
    pub fn verify_signature(&self) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.initiator) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&self.initiator);
        msg.extend_from_slice(&self.target);
        msg.extend_from_slice(&self.initiator_slot.to_le_bytes());
        msg.extend_from_slice(&self.target_slot.to_le_bytes());
        msg.extend_from_slice(&self.proposal_height.to_le_bytes());
        msg.extend_from_slice(&self.proposal_vdf_output);

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Calculate average latency from proofs
    fn average_latency(proofs: &[LatencyProof]) -> u64 {
        if proofs.is_empty() {
            return u64::MAX;
        }
        let sum: u64 = proofs.iter().map(|p| p.latency_us).sum();
        sum / proofs.len() as u64
    }

    /// Check if this swap is a Pareto improvement for the initiator
    pub fn initiator_improves(&self) -> bool {
        let current = Self::average_latency(&self.initiator_proofs);
        let projected = Self::average_latency(&self.initiator_at_target_proofs);
        projected + MIN_IMPROVEMENT_US < current
    }
}

/// Swap decision (TGP-style ATTACK/RETREAT)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapDecision {
    /// Commit to finalize swap
    Attack,
    /// Abort swap
    Retreat,
}

impl SwapDecision {
    /// Bilateral decision - both must ATTACK for swap to proceed
    pub fn bilateral(self, other: SwapDecision) -> SwapDecision {
        match (self, other) {
            (SwapDecision::Attack, SwapDecision::Attack) => SwapDecision::Attack,
            _ => SwapDecision::Retreat,
        }
    }
}

/// Response to a swap proposal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapResponse {
    /// Responding node's public key
    pub responder: [u8; 32],
    /// Original proposal height (for matching)
    pub proposal_height: u64,
    /// Decision: accept or reject
    pub decision: SwapDecision,
    /// If accepting, target's latency proofs at their current position
    pub target_proofs: Vec<LatencyProof>,
    /// If accepting, target's projected latency at initiator's position
    pub target_at_initiator_proofs: Vec<LatencyProof>,
    /// VDF height of response
    pub response_height: u64,
    /// Signature
    #[serde(with = "crate::vdf_race::signature_serde")]
    pub signature: [u8; 64],
}

impl SwapResponse {
    /// Create a new swap response
    pub fn new(
        proposal_height: u64,
        decision: SwapDecision,
        target_proofs: Vec<LatencyProof>,
        target_at_initiator_proofs: Vec<LatencyProof>,
        response_height: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let responder = signing_key.verifying_key().to_bytes();

        let mut msg = Vec::with_capacity(80);
        msg.extend_from_slice(&responder);
        msg.extend_from_slice(&proposal_height.to_le_bytes());
        msg.push(match decision {
            SwapDecision::Attack => 1,
            SwapDecision::Retreat => 0,
        });
        msg.extend_from_slice(&response_height.to_le_bytes());

        let signature = signing_key.sign(&msg);

        Self {
            responder,
            proposal_height,
            decision,
            target_proofs,
            target_at_initiator_proofs,
            response_height,
            signature: signature.to_bytes(),
        }
    }

    /// Check if target improves from the swap
    pub fn target_improves(&self) -> bool {
        let current = SwapProposal::average_latency(&self.target_proofs);
        let projected = SwapProposal::average_latency(&self.target_at_initiator_proofs);
        projected + MIN_IMPROVEMENT_US < current
    }
}

/// Proof of Latency manager for a node
pub struct PoLManager {
    /// Our signing key
    signing_key: SigningKey,
    /// Our public key
    pub_key: [u8; 32],
    /// Current slot state
    state: SlotState,
    /// Our current slot
    our_slot: Option<u64>,
    /// Pending swap proposals we've sent
    pending_proposals: HashMap<[u8; 32], SwapProposal>,
    /// Latency measurements to neighbors (neighbor pubkey -> latest proof)
    latency_cache: HashMap<[u8; 32], LatencyProof>,
    /// Ping requests in flight (target -> send time)
    pending_pings: HashMap<[u8; 32], Instant>,
}

impl PoLManager {
    /// Create a new PoL manager
    pub fn new(signing_key: SigningKey) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            pub_key,
            state: SlotState::Active,
            our_slot: None,
            pending_proposals: HashMap::new(),
            latency_cache: HashMap::new(),
            pending_pings: HashMap::new(),
        }
    }

    /// Set our current slot
    pub fn set_slot(&mut self, slot: u64) {
        self.our_slot = Some(slot);
    }

    /// Get current state
    pub fn state(&self) -> &SlotState {
        &self.state
    }

    /// Start a ping measurement to a neighbor
    pub fn start_ping(&mut self, target: [u8; 32]) {
        self.pending_pings.insert(target, Instant::now());
    }

    /// Complete a ping measurement and create latency proof
    pub fn complete_ping(
        &mut self,
        target: [u8; 32],
        vdf_height: u64,
        vdf_output: [u8; 32],
    ) -> Option<LatencyProof> {
        let start = self.pending_pings.remove(&target)?;
        let latency_us = start.elapsed().as_micros() as u64;

        let proof = LatencyProof::new(
            self.pub_key,
            target,
            latency_us,
            vdf_height,
            vdf_output,
            &self.signing_key,
        );

        self.latency_cache.insert(target, proof.clone());
        Some(proof)
    }

    /// Get cached latency proofs for our neighbors
    pub fn get_neighbor_proofs(&self) -> Vec<LatencyProof> {
        self.latency_cache.values().cloned().collect()
    }

    /// Create a swap proposal
    pub fn propose_swap(
        &mut self,
        target_slot: u64,
        target_node: [u8; 32],
        target_neighbor_proofs: Vec<LatencyProof>,
        vdf_height: u64,
        vdf_output: [u8; 32],
    ) -> Option<SwapProposal> {
        // Must be in active state
        if !self.state.is_active() {
            return None;
        }

        let our_slot = self.our_slot?;
        let our_proofs = self.get_neighbor_proofs();

        let proposal = SwapProposal::new(
            our_slot,
            target_slot,
            target_node,
            our_proofs,
            target_neighbor_proofs,
            vdf_height,
            vdf_output,
            &self.signing_key,
        );

        // Only propose if we would improve
        if !proposal.initiator_improves() {
            return None;
        }

        // Enter halflock state
        self.state = SlotState::HalfLock {
            target_slot,
            target_node,
            proposal_height: vdf_height,
        };

        self.pending_proposals.insert(target_node, proposal.clone());
        Some(proposal)
    }

    /// Process an incoming swap proposal
    pub fn process_proposal(
        &mut self,
        proposal: &SwapProposal,
        initiator_neighbor_proofs: Vec<LatencyProof>,
        vdf_height: u64,
    ) -> Option<SwapResponse> {
        // Verify proposal signature
        if !proposal.verify_signature() {
            return Some(SwapResponse::new(
                proposal.proposal_height,
                SwapDecision::Retreat,
                vec![],
                vec![],
                vdf_height,
                &self.signing_key,
            ));
        }

        // Must be in active state and target must be us
        if !self.state.is_active() || proposal.target != self.pub_key {
            return Some(SwapResponse::new(
                proposal.proposal_height,
                SwapDecision::Retreat,
                vec![],
                vec![],
                vdf_height,
                &self.signing_key,
            ));
        }

        let our_proofs = self.get_neighbor_proofs();

        // Create response with our proofs
        let response = SwapResponse::new(
            proposal.proposal_height,
            SwapDecision::Attack, // Tentative - will check if we improve
            our_proofs.clone(),
            initiator_neighbor_proofs.clone(),
            vdf_height,
            &self.signing_key,
        );

        // Check if we would improve
        if !response.target_improves() {
            return Some(SwapResponse::new(
                proposal.proposal_height,
                SwapDecision::Retreat,
                our_proofs,
                initiator_neighbor_proofs,
                vdf_height,
                &self.signing_key,
            ));
        }

        // Enter halflock state
        self.state = SlotState::HalfLock {
            target_slot: proposal.initiator_slot,
            target_node: proposal.initiator,
            proposal_height: proposal.proposal_height,
        };

        Some(response)
    }

    /// Process response to our proposal
    pub fn process_response(&mut self, response: &SwapResponse) -> SwapDecision {
        // Must be halflocked with this responder
        if !self.state.is_halflocked_with(&response.responder) {
            return SwapDecision::Retreat;
        }

        match response.decision {
            SwapDecision::Attack => {
                // Both agree - transition to swapping
                if let SlotState::HalfLock {
                    target_slot,
                    target_node,
                    ..
                } = self.state
                {
                    self.state = SlotState::Swapping {
                        target_slot,
                        target_node,
                    };
                    SwapDecision::Attack
                } else {
                    SwapDecision::Retreat
                }
            }
            SwapDecision::Retreat => {
                // Target rejected - go back to active
                self.state = SlotState::Active;
                self.pending_proposals.remove(&response.responder);
                SwapDecision::Retreat
            }
        }
    }

    /// Commit to ATTACK (finalize swap)
    pub fn commit_attack(&mut self) -> bool {
        if let SlotState::HalfLock {
            target_slot,
            target_node,
            ..
        } = self.state
        {
            self.state = SlotState::Swapping {
                target_slot,
                target_node,
            };
            true
        } else {
            false
        }
    }

    /// RETREAT (abort swap)
    pub fn retreat(&mut self) {
        if let SlotState::HalfLock { target_node, .. } | SlotState::Swapping { target_node, .. } =
            self.state
        {
            self.pending_proposals.remove(&target_node);
        }
        self.state = SlotState::Active;
    }

    /// Complete the swap (after both parties have ATTACKed)
    pub fn complete_swap(&mut self, new_slot: u64) {
        if matches!(self.state, SlotState::Swapping { .. }) {
            self.our_slot = Some(new_slot);
            self.state = SlotState::Active;
            // Clear latency cache - we have new neighbors now
            self.latency_cache.clear();
        }
    }

    /// Check if a swap should be proposed based on latency measurements
    pub fn should_propose_swap(
        &self,
        _potential_target_slot: u64,
        _potential_target_node: [u8; 32],
        target_neighbors_latency: &[LatencyProof],
    ) -> bool {
        if !self.state.is_active() {
            return false;
        }

        // Calculate our current average
        let our_avg = SwapProposal::average_latency(&self.get_neighbor_proofs());

        // Calculate what we'd have at target position
        let projected_avg = SwapProposal::average_latency(target_neighbors_latency);

        // Only propose if significant improvement
        projected_avg + MIN_IMPROVEMENT_US < our_avg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_latency_proof_creation_and_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let target_key = SigningKey::generate(&mut OsRng);

        let proof = LatencyProof::new(
            key.verifying_key().to_bytes(),
            target_key.verifying_key().to_bytes(),
            5000, // 5ms
            100,
            [42u8; 32],
            &key,
        );

        assert!(proof.verify_signature());
        assert!(proof.is_fresh(150));
        assert!(!proof.is_fresh(250)); // Too old
    }

    #[test]
    fn test_slot_state_transitions() {
        let mut manager = PoLManager::new(SigningKey::generate(&mut OsRng));
        manager.set_slot(5);

        assert!(manager.state().is_active());

        // Simulate entering halflock
        let target = [1u8; 32];
        manager.state = SlotState::HalfLock {
            target_slot: 10,
            target_node: target,
            proposal_height: 100,
        };

        assert!(manager.state().is_halflocked_with(&target));
        assert_eq!(manager.state().target_slot(), Some(10));

        // Retreat
        manager.retreat();
        assert!(manager.state().is_active());
    }

    #[test]
    fn test_swap_decision_bilateral() {
        // Both attack -> attack
        assert_eq!(
            SwapDecision::Attack.bilateral(SwapDecision::Attack),
            SwapDecision::Attack
        );

        // Any retreat -> retreat
        assert_eq!(
            SwapDecision::Attack.bilateral(SwapDecision::Retreat),
            SwapDecision::Retreat
        );
        assert_eq!(
            SwapDecision::Retreat.bilateral(SwapDecision::Attack),
            SwapDecision::Retreat
        );
        assert_eq!(
            SwapDecision::Retreat.bilateral(SwapDecision::Retreat),
            SwapDecision::Retreat
        );
    }

    #[test]
    fn test_pareto_improvement_check() {
        let key = SigningKey::generate(&mut OsRng);
        let target = [1u8; 32];

        // Current position: 10ms average
        let current_proofs: Vec<LatencyProof> = (0..5)
            .map(|i| {
                LatencyProof::new(
                    key.verifying_key().to_bytes(),
                    [i as u8; 32],
                    10000, // 10ms
                    100,
                    [42u8; 32],
                    &key,
                )
            })
            .collect();

        // Target position: 5ms average (improvement!)
        let target_proofs: Vec<LatencyProof> = (0..5)
            .map(|i| {
                LatencyProof::new(
                    key.verifying_key().to_bytes(),
                    [i as u8 + 10; 32],
                    5000, // 5ms
                    100,
                    [42u8; 32],
                    &key,
                )
            })
            .collect();

        let proposal = SwapProposal::new(
            5,
            10,
            target,
            current_proofs,
            target_proofs,
            100,
            [42u8; 32],
            &key,
        );

        assert!(proposal.initiator_improves());
        assert!(proposal.verify_signature());
    }

    #[test]
    fn test_swap_proposal_rejected_no_improvement() {
        let key = SigningKey::generate(&mut OsRng);
        let target = [1u8; 32];

        // Current position: 5ms average
        let current_proofs: Vec<LatencyProof> = (0..5)
            .map(|i| {
                LatencyProof::new(
                    key.verifying_key().to_bytes(),
                    [i as u8; 32],
                    5000, // 5ms
                    100,
                    [42u8; 32],
                    &key,
                )
            })
            .collect();

        // Target position: 10ms average (WORSE!)
        let target_proofs: Vec<LatencyProof> = (0..5)
            .map(|i| {
                LatencyProof::new(
                    key.verifying_key().to_bytes(),
                    [i as u8 + 10; 32],
                    10000, // 10ms
                    100,
                    [42u8; 32],
                    &key,
                )
            })
            .collect();

        let proposal = SwapProposal::new(
            5,
            10,
            target,
            current_proofs,
            target_proofs,
            100,
            [42u8; 32],
            &key,
        );

        assert!(!proposal.initiator_improves());
    }
}
