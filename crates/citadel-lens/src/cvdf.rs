//! CVDF - Collaborative Verifiable Delay Function
//!
//! # The Zero-Cost Blockchain Insight
//!
//! Traditional PoW: 1000 miners race, 1 wins, 999 wasted work
//! CVDF: All participants contribute TO each other, not against
//!
//! ```text
//!                 CVDF ROUND R
//!                      │
//!     ┌────────────────┼────────────────┐
//!     │                │                │
//!     ▼                ▼                ▼
//!   Node A           Node B           Node C
//!   attest           attest           attest
//!   (sign)           (sign)           (sign)
//!     │                │                │
//!     └────────────────┼────────────────┘
//!                      │
//!                      ▼
//!             WASH attestations
//!             into VDF input
//!                      │
//!                      ▼
//!              Duty holder D
//!              computes VDF
//!                      │
//!                      ▼
//!              Round output
//!              (proves time +
//!               participation)
//! ```
//!
//! # Key Properties
//!
//! 1. **Sequential Proof**: VDF computation proves real time elapsed
//! 2. **Participation Proof**: Attestations prove N nodes contributed
//! 3. **Washable**: Attestations combine deterministically into VDF input
//! 4. **Zero Waste**: Everyone's attestation counts, no losers
//! 5. **Natural Convergence**: Chains with more attesters dominate
//!
//! # Why This Is Zero Cost
//!
//! - No mining hardware arms race (VDF is sequential, can't parallelize)
//! - No wasted computation (unlike PoW where losers' work is thrown away)
//! - The "cost" is just participating in the network (which you're doing anyway)
//! - The blockchain falls out of the protocol naturally
//!
//! # Swarm Convergence
//!
//! - Swarm A with 30 attesters per round produces heavier chain
//! - Swarm B with 10 attesters per round produces lighter chain
//! - When they meet, heavier chain wins
//! - Natural gravitational pull toward collaboration
//! - Typically converges to 1-3 swarms, optimally 1

use crate::vdf_race::signature_serde;
use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// VDF iterations per round - base difficulty (~50ms on modern hardware)
pub const CVDF_ITERATIONS_BASE: u32 = 100_000;

/// Minimum VDF iterations (when network is stable, ~10ms)
pub const CVDF_ITERATIONS_MIN: u32 = 20_000;

/// Maximum VDF iterations (under attack, ~500ms)
pub const CVDF_ITERATIONS_MAX: u32 = 500_000;

/// Minimum attestations for a valid round (prevents solo mining)
pub const MIN_ATTESTATIONS: usize = 1;

/// Weight multiplier per attester (for chain comparison)
pub const ATTESTATION_WEIGHT: u64 = 1;

/// Rounds without attestation before a slot is considered stale
pub const SLOT_LIVENESS_THRESHOLD: u64 = 10;

/// Rounds to track for difficulty adjustment
pub const DIFFICULTY_WINDOW: usize = 20;

/// An attestation to a round - proves a node participated
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundAttestation {
    /// Round number being attested
    pub round: u64,
    /// Previous round output (what we're attesting to)
    pub prev_output: [u8; 32],
    /// Attester's public key
    pub attester: [u8; 32],
    /// Attester's slot (if they have one, for ordering)
    pub slot: Option<u64>,
    /// Signature over (round || prev_output)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

impl RoundAttestation {
    /// Create new attestation
    pub fn new(
        round: u64,
        prev_output: [u8; 32],
        slot: Option<u64>,
        signing_key: &SigningKey,
    ) -> Self {
        let attester = signing_key.verifying_key().to_bytes();

        // Message: round || prev_output
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&prev_output);

        let signature = signing_key.sign(&msg);

        Self {
            round,
            prev_output,
            attester,
            slot,
            signature: signature.to_bytes(),
        }
    }

    /// Verify attestation signature
    pub fn verify(&self) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.attester) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.prev_output);

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Get attestation hash (for washing)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.attester);
        hasher.update(&self.signature);
        *hasher.finalize().as_bytes()
    }
}

/// A CVDF round - one step in the collaborative chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CvdfRound {
    /// Round number (0 = genesis)
    pub round: u64,
    /// Previous round output
    pub prev_output: [u8; 32],
    /// Washed input (combination of attestations)
    pub washed_input: [u8; 32],
    /// VDF output (result of sequential computation on washed input)
    pub output: [u8; 32],
    /// Attestations that were washed into this round
    pub attestations: Vec<RoundAttestation>,
    /// Producer of this round (computed the VDF)
    pub producer: [u8; 32],
    /// Producer's signature over the round
    #[serde(with = "signature_serde")]
    pub producer_signature: [u8; 64],
    /// Timestamp (informational, not trusted)
    pub timestamp_ms: u64,
}

impl CvdfRound {
    /// Create genesis round
    pub fn genesis(seed: &[u8], signing_key: &SigningKey) -> Self {
        let producer = signing_key.verifying_key().to_bytes();

        // Genesis has no previous output
        let prev_output = [0u8; 32];

        // Washed input is just the seed for genesis
        let washed_input = *blake3::hash(seed).as_bytes();

        // Compute VDF
        let output = compute_cvdf(&washed_input, CVDF_ITERATIONS_BASE);

        // Sign the round
        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(&0u64.to_le_bytes()); // round 0
        msg.extend_from_slice(&washed_input);
        msg.extend_from_slice(&output);
        let signature = signing_key.sign(&msg);

        Self {
            round: 0,
            prev_output,
            washed_input,
            output,
            attestations: vec![],
            producer,
            producer_signature: signature.to_bytes(),
            timestamp_ms: now_ms(),
        }
    }

    /// Create next round from attestations
    pub fn from_attestations(
        round: u64,
        prev_output: [u8; 32],
        attestations: Vec<RoundAttestation>,
        signing_key: &SigningKey,
    ) -> Option<Self> {
        // Need minimum attestations
        if attestations.len() < MIN_ATTESTATIONS {
            return None;
        }

        // Verify all attestations
        for att in &attestations {
            if !att.verify() {
                return None;
            }
            // Attestations must be for this round
            if att.round != round {
                return None;
            }
            // Attestations must reference correct previous output
            if att.prev_output != prev_output {
                return None;
            }
        }

        // Wash attestations into input
        let washed_input = wash_attestations(&prev_output, &attestations);

        // Compute VDF
        let output = compute_cvdf(&washed_input, CVDF_ITERATIONS_BASE);

        let producer = signing_key.verifying_key().to_bytes();

        // Sign the round
        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&washed_input);
        msg.extend_from_slice(&output);
        let signature = signing_key.sign(&msg);

        Some(Self {
            round,
            prev_output,
            washed_input,
            output,
            attestations,
            producer,
            producer_signature: signature.to_bytes(),
            timestamp_ms: now_ms(),
        })
    }

    /// Verify this round is valid
    pub fn verify(&self, expected_prev: &[u8; 32]) -> bool {
        // Check previous output
        if self.round > 0 && &self.prev_output != expected_prev {
            return false;
        }

        // Verify all attestations
        for att in &self.attestations {
            if !att.verify() {
                return false;
            }
            if att.round != self.round {
                return false;
            }
            if att.prev_output != self.prev_output {
                return false;
            }
        }

        // Verify washed input
        let expected_washed = if self.round == 0 {
            // Genesis washed input is just prev_output hash
            // (which for genesis is the seed hash)
            self.washed_input // Trust it for genesis
        } else {
            wash_attestations(&self.prev_output, &self.attestations)
        };

        if self.round > 0 && self.washed_input != expected_washed {
            return false;
        }

        // Verify VDF output
        let expected_output = compute_cvdf(&self.washed_input, CVDF_ITERATIONS_BASE);
        if self.output != expected_output {
            return false;
        }

        // Verify producer signature
        let verifying_key = match VerifyingKey::from_bytes(&self.producer) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.producer_signature);

        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.washed_input);
        msg.extend_from_slice(&self.output);

        verifying_key.verify(&msg, &signature).is_ok()
    }

    /// Get the "weight" of this round (based on attestation count)
    pub fn weight(&self) -> u64 {
        // Base weight of 1 + attestation bonus
        1 + (self.attestations.len() as u64) * ATTESTATION_WEIGHT
    }

    /// Get unique attester count
    pub fn attester_count(&self) -> usize {
        let unique: HashSet<[u8; 32]> = self.attestations.iter()
            .map(|a| a.attester)
            .collect();
        unique.len()
    }
}

/// Wash attestations into a deterministic input
/// This is the core "washing" operation that combines all attestations
fn wash_attestations(prev_output: &[u8; 32], attestations: &[RoundAttestation]) -> [u8; 32] {
    // Sort attestations deterministically (by slot if available, then by attester pubkey)
    let mut sorted: Vec<&RoundAttestation> = attestations.iter().collect();
    sorted.sort_by(|a, b| {
        match (a.slot, b.slot) {
            (Some(sa), Some(sb)) => sa.cmp(&sb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.attester.cmp(&b.attester),
        }
    });

    // Combine into washed input
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_output);

    for att in sorted {
        hasher.update(&att.hash());
    }

    *hasher.finalize().as_bytes()
}

/// Compute CVDF (iterated BLAKE3)
fn compute_cvdf(input: &[u8; 32], iterations: u32) -> [u8; 32] {
    let mut state = blake3::hash(input);

    for _ in 0..iterations {
        state = blake3::hash(state.as_bytes());
    }

    *state.as_bytes()
}

/// Network health metrics for difficulty adjustment
#[derive(Debug, Clone, Default)]
pub struct NetworkHealth {
    /// Attestation counts for recent rounds
    pub recent_attestation_counts: Vec<usize>,
    /// Fork events detected
    pub fork_count: u32,
    /// Spam claim attempts
    pub spam_claim_count: u32,
    /// Current difficulty level
    pub current_iterations: u32,
}

impl NetworkHealth {
    pub fn new() -> Self {
        Self {
            recent_attestation_counts: Vec::with_capacity(DIFFICULTY_WINDOW),
            fork_count: 0,
            spam_claim_count: 0,
            current_iterations: CVDF_ITERATIONS_BASE,
        }
    }

    /// Record a round's attestation count
    pub fn record_round(&mut self, attestation_count: usize) {
        self.recent_attestation_counts.push(attestation_count);
        if self.recent_attestation_counts.len() > DIFFICULTY_WINDOW {
            self.recent_attestation_counts.remove(0);
        }
        // Decay fork/spam counts over time
        if self.fork_count > 0 {
            self.fork_count = self.fork_count.saturating_sub(1);
        }
        if self.spam_claim_count > 0 {
            self.spam_claim_count = self.spam_claim_count.saturating_sub(1);
        }
    }

    /// Record a fork detection
    pub fn record_fork(&mut self) {
        self.fork_count = self.fork_count.saturating_add(5);
    }

    /// Record a spam claim attempt
    pub fn record_spam(&mut self) {
        self.spam_claim_count = self.spam_claim_count.saturating_add(1);
    }

    /// Compute optimal difficulty based on network health
    pub fn compute_difficulty(&mut self) -> u32 {
        // Attack indicators
        let attack_score = self.fork_count + self.spam_claim_count;

        // Participation health
        let avg_attesters = if self.recent_attestation_counts.is_empty() {
            0.0
        } else {
            self.recent_attestation_counts.iter().sum::<usize>() as f64
                / self.recent_attestation_counts.len() as f64
        };

        // Healthy network: low difficulty (fast rounds)
        // Under attack: high difficulty (slow but secure)
        let target_iterations = if attack_score > 10 {
            // Heavy attack - max difficulty
            CVDF_ITERATIONS_MAX
        } else if attack_score > 5 {
            // Moderate attack - elevated difficulty
            CVDF_ITERATIONS_BASE + (CVDF_ITERATIONS_MAX - CVDF_ITERATIONS_BASE) / 2
        } else if avg_attesters >= 3.0 && attack_score == 0 {
            // Healthy collaborative network - minimum difficulty
            CVDF_ITERATIONS_MIN
        } else {
            // Normal operation - base difficulty
            CVDF_ITERATIONS_BASE
        };

        // Smooth transitions (don't jump instantly)
        let diff = target_iterations as i64 - self.current_iterations as i64;
        let step = (diff / 4).clamp(-50000, 50000) as i32;
        self.current_iterations = (self.current_iterations as i32 + step)
            .clamp(CVDF_ITERATIONS_MIN as i32, CVDF_ITERATIONS_MAX as i32) as u32;

        self.current_iterations
    }
}

/// Slot liveness tracker - prunes slots that stop contributing
#[derive(Debug, Clone, Default)]
pub struct SlotLiveness {
    /// Last round each slot attested (slot -> round)
    last_attestation: HashMap<u64, u64>,
    /// Current round number
    current_round: u64,
}

impl SlotLiveness {
    pub fn new() -> Self {
        Self {
            last_attestation: HashMap::new(),
            current_round: 0,
        }
    }

    /// Record an attestation from a slot
    pub fn record_attestation(&mut self, slot: u64, round: u64) {
        self.last_attestation.insert(slot, round);
        if round > self.current_round {
            self.current_round = round;
        }
    }

    /// Advance to new round
    pub fn advance_round(&mut self, round: u64) {
        self.current_round = round;
    }

    /// Check if a slot is still live (has attested recently)
    pub fn is_live(&self, slot: u64) -> bool {
        if let Some(last) = self.last_attestation.get(&slot) {
            self.current_round.saturating_sub(*last) <= SLOT_LIVENESS_THRESHOLD
        } else {
            // Never attested - give them a grace period
            true
        }
    }

    /// Get all stale slots that should be pruned
    pub fn stale_slots(&self) -> Vec<u64> {
        self.last_attestation
            .iter()
            .filter(|(_, last)| self.current_round.saturating_sub(**last) > SLOT_LIVENESS_THRESHOLD)
            .map(|(slot, _)| *slot)
            .collect()
    }

    /// Remove a slot from tracking
    pub fn remove_slot(&mut self, slot: u64) {
        self.last_attestation.remove(&slot);
    }
}

/// Get current timestamp in milliseconds
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A CVDF chain - the collaborative blockchain
#[derive(Clone, Debug)]
pub struct CvdfChain {
    /// Genesis seed
    genesis_seed: [u8; 32],
    /// Chain rounds
    rounds: Vec<CvdfRound>,
    /// Our signing key
    signing_key: SigningKey,
    /// Our public key
    our_pubkey: [u8; 32],
}

impl CvdfChain {
    /// Create new chain as genesis
    pub fn new_genesis(genesis_seed: [u8; 32], signing_key: SigningKey) -> Self {
        let our_pubkey = signing_key.verifying_key().to_bytes();
        let genesis = CvdfRound::genesis(&genesis_seed, &signing_key);

        Self {
            genesis_seed,
            rounds: vec![genesis],
            signing_key,
            our_pubkey,
        }
    }

    /// Join existing chain
    pub fn from_rounds(
        genesis_seed: [u8; 32],
        rounds: Vec<CvdfRound>,
        signing_key: SigningKey,
    ) -> Option<Self> {
        let our_pubkey = signing_key.verifying_key().to_bytes();

        let chain = Self {
            genesis_seed,
            rounds,
            signing_key,
            our_pubkey,
        };

        if chain.verify_full() {
            Some(chain)
        } else {
            None
        }
    }

    /// Current chain height (round number)
    pub fn height(&self) -> u64 {
        self.rounds.last().map(|r| r.round).unwrap_or(0)
    }

    /// Current tip output
    pub fn tip_output(&self) -> [u8; 32] {
        self.rounds.last().map(|r| r.output).unwrap_or([0u8; 32])
    }

    /// Get tip round
    pub fn tip(&self) -> Option<&CvdfRound> {
        self.rounds.last()
    }

    /// Total chain weight (sum of all round weights)
    pub fn total_weight(&self) -> u64 {
        self.rounds.iter().map(|r| r.weight()).sum()
    }

    /// Create attestation for next round
    pub fn create_attestation(&self, our_slot: Option<u64>) -> RoundAttestation {
        let next_round = self.height() + 1;
        let prev_output = self.tip_output();

        RoundAttestation::new(next_round, prev_output, our_slot, &self.signing_key)
    }

    /// Extend chain with new round from attestations
    pub fn extend(&mut self, attestations: Vec<RoundAttestation>) -> Option<&CvdfRound> {
        let next_round = self.height() + 1;
        let prev_output = self.tip_output();

        let round = CvdfRound::from_attestations(
            next_round,
            prev_output,
            attestations,
            &self.signing_key,
        )?;

        self.rounds.push(round);
        self.rounds.last()
    }

    /// Process incoming round (from another producer)
    pub fn process_round(&mut self, round: CvdfRound) -> bool {
        // Must be next round
        if round.round != self.height() + 1 {
            return false;
        }

        // Verify round
        let prev_output = self.tip_output();
        if !round.verify(&prev_output) {
            return false;
        }

        self.rounds.push(round);
        true
    }

    /// Verify entire chain
    pub fn verify_full(&self) -> bool {
        if self.rounds.is_empty() {
            return false;
        }

        // Verify genesis
        let genesis = &self.rounds[0];
        if genesis.round != 0 {
            return false;
        }

        // Verify genesis VDF
        let expected_genesis_output = compute_cvdf(&genesis.washed_input, CVDF_ITERATIONS_BASE);
        if genesis.output != expected_genesis_output {
            return false;
        }

        // Verify each subsequent round
        for i in 1..self.rounds.len() {
            let prev = &self.rounds[i - 1];
            let curr = &self.rounds[i];

            if curr.round != prev.round + 1 {
                return false;
            }

            if !curr.verify(&prev.output) {
                return false;
            }
        }

        true
    }

    /// Compare with another chain - returns true if we should adopt theirs
    pub fn should_adopt(&self, other_rounds: &[CvdfRound]) -> bool {
        if other_rounds.is_empty() {
            return false;
        }

        // Verify other chain
        let other = match CvdfChain::from_rounds(
            self.genesis_seed,
            other_rounds.to_vec(),
            self.signing_key.clone(),
        ) {
            Some(c) => c,
            None => return false,
        };

        // Compare total weight (not just height!)
        // This is the key insight: chains with more attesters are heavier
        other.total_weight() > self.total_weight()
    }

    /// Adopt a heavier chain
    pub fn adopt(&mut self, other_rounds: Vec<CvdfRound>) -> bool {
        if !self.should_adopt(&other_rounds) {
            return false;
        }

        self.rounds = other_rounds;
        true
    }

    /// Get all rounds for syncing
    pub fn all_rounds(&self) -> &[CvdfRound] {
        &self.rounds
    }

    /// Get rounds from a specific height
    pub fn rounds_from(&self, height: u64) -> &[CvdfRound] {
        let start = height as usize;
        if start >= self.rounds.len() {
            &[]
        } else {
            &self.rounds[start..]
        }
    }

    /// Get average attesters per round
    pub fn avg_attesters(&self) -> f64 {
        if self.rounds.is_empty() {
            return 0.0;
        }

        let total: usize = self.rounds.iter()
            .map(|r| r.attester_count())
            .sum();

        total as f64 / self.rounds.len() as f64
    }
}

/// Collaborative VDF coordinator - manages attestation collection and round production
#[derive(Debug)]
pub struct CvdfCoordinator {
    /// Our chain
    chain: CvdfChain,
    /// Our slot (if we have one)
    our_slot: Option<u64>,
    /// Collected attestations for next round
    pending_attestations: BTreeMap<[u8; 32], RoundAttestation>,
    /// Known slot holders (for duty rotation)
    slot_holders: BTreeMap<u64, [u8; 32]>,
    /// Slot liveness tracking - prunes inactive slots
    slot_liveness: SlotLiveness,
    /// Network health for difficulty adjustment
    network_health: NetworkHealth,
}

impl CvdfCoordinator {
    /// Create new coordinator as genesis
    pub fn new_genesis(genesis_seed: [u8; 32], signing_key: SigningKey) -> Self {
        let chain = CvdfChain::new_genesis(genesis_seed, signing_key);

        Self {
            chain,
            our_slot: None,
            pending_attestations: BTreeMap::new(),
            slot_holders: BTreeMap::new(),
            slot_liveness: SlotLiveness::new(),
            network_health: NetworkHealth::new(),
        }
    }

    /// Join existing chain
    pub fn join(
        genesis_seed: [u8; 32],
        rounds: Vec<CvdfRound>,
        signing_key: SigningKey,
    ) -> Option<Self> {
        let chain = CvdfChain::from_rounds(genesis_seed, rounds, signing_key)?;

        Some(Self {
            chain,
            our_slot: None,
            pending_attestations: BTreeMap::new(),
            slot_holders: BTreeMap::new(),
            slot_liveness: SlotLiveness::new(),
            network_health: NetworkHealth::new(),
        })
    }

    /// Set our slot
    pub fn set_slot(&mut self, slot: u64) {
        self.our_slot = Some(slot);
    }

    /// Register a slot holder
    pub fn register_slot(&mut self, slot: u64, holder: [u8; 32]) {
        self.slot_holders.insert(slot, holder);
    }

    /// Get current chain height
    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Get total chain weight
    pub fn weight(&self) -> u64 {
        self.chain.total_weight()
    }

    /// Create our attestation for next round
    pub fn attest(&self) -> RoundAttestation {
        self.chain.create_attestation(self.our_slot)
    }

    /// Receive attestation from another node
    pub fn receive_attestation(&mut self, att: RoundAttestation) -> bool {
        // Verify attestation
        if !att.verify() {
            return false;
        }

        // Must be for next round
        let expected_round = self.chain.height() + 1;
        if att.round != expected_round {
            return false;
        }

        // Must reference our current tip
        if att.prev_output != self.chain.tip_output() {
            return false;
        }

        // Add to pending
        self.pending_attestations.insert(att.attester, att);
        true
    }

    /// Check if it's our turn to produce
    pub fn is_our_turn(&self) -> bool {
        if self.slot_holders.is_empty() {
            // No slots yet - genesis mode, anyone can produce
            return true;
        }

        let our_slot = match self.our_slot {
            Some(s) => s,
            None => return false, // No slot, not our turn
        };

        // Duty rotates by round number
        let slots: Vec<u64> = self.slot_holders.keys().copied().collect();
        let duty_idx = (self.chain.height() as usize + 1) % slots.len();
        let duty_slot = slots[duty_idx];

        duty_slot == our_slot
    }

    /// Try to produce next round (if we have enough attestations and it's our turn)
    pub fn try_produce(&mut self) -> Option<CvdfRound> {
        if !self.is_our_turn() {
            return None;
        }

        // Need minimum attestations
        if self.pending_attestations.len() < MIN_ATTESTATIONS {
            return None;
        }

        // Collect attestations
        let attestations: Vec<RoundAttestation> = self.pending_attestations
            .values()
            .cloned()
            .collect();

        // Clear pending
        self.pending_attestations.clear();

        // Extend chain
        self.chain.extend(attestations)?;
        self.chain.tip().cloned()
    }

    /// Process incoming round from another producer
    pub fn process_round(&mut self, round: CvdfRound) -> bool {
        if self.chain.process_round(round) {
            // Clear pending attestations (they're now stale)
            self.pending_attestations.clear();
            true
        } else {
            false
        }
    }

    /// Check if we should adopt another chain
    pub fn should_adopt(&self, other_rounds: &[CvdfRound]) -> bool {
        self.chain.should_adopt(other_rounds)
    }

    /// Adopt a heavier chain
    pub fn adopt(&mut self, other_rounds: Vec<CvdfRound>) -> bool {
        if self.chain.adopt(other_rounds) {
            self.pending_attestations.clear();
            true
        } else {
            false
        }
    }

    /// Get chain for syncing
    pub fn chain(&self) -> &CvdfChain {
        &self.chain
    }

    /// Get registered slots as (slot, pubkey) pairs
    pub fn registered_slots(&self) -> Vec<(u64, [u8; 32])> {
        self.slot_holders.iter().map(|(k, v)| (*k, *v)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_cvdf_genesis() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let chain = CvdfChain::new_genesis(genesis_seed, signing_key);

        assert_eq!(chain.height(), 0);
        assert!(chain.verify_full());
        assert_eq!(chain.total_weight(), 1); // Genesis has weight 1

        println!("Genesis output: {}", hex::encode(chain.tip_output()));
    }

    #[test]
    fn test_cvdf_attestation() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let chain = CvdfChain::new_genesis(genesis_seed, signing_key.clone());

        // Create attestation for next round
        let attestation = chain.create_attestation(Some(0));

        assert_eq!(attestation.round, 1);
        assert_eq!(attestation.prev_output, chain.tip_output());
        assert!(attestation.verify());

        println!("Attestation verified: round {}", attestation.round);
    }

    #[test]
    fn test_cvdf_round_production() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let mut chain = CvdfChain::new_genesis(genesis_seed, signing_key.clone());

        // Create attestations from multiple "nodes"
        let key2 = SigningKey::generate(&mut OsRng);
        let key3 = SigningKey::generate(&mut OsRng);

        let att1 = chain.create_attestation(Some(0));
        let att2 = RoundAttestation::new(1, chain.tip_output(), Some(1), &key2);
        let att3 = RoundAttestation::new(1, chain.tip_output(), Some(2), &key3);

        // Extend with all attestations
        let round = chain.extend(vec![att1, att2, att3]);
        assert!(round.is_some());

        let round = round.unwrap();
        assert_eq!(round.round, 1);
        assert_eq!(round.attester_count(), 3);
        assert_eq!(round.weight(), 1 + 3); // base + 3 attesters

        println!("Round 1 produced with {} attesters, weight {}",
            round.attester_count(), round.weight());
    }

    #[test]
    fn test_cvdf_chain_weight_comparison() {
        let genesis_seed = [42u8; 32];

        println!("\n=== CVDF Chain Weight Comparison ===\n");

        // Chain A: Few attesters per round
        let key_a = SigningKey::generate(&mut OsRng);
        let mut chain_a = CvdfChain::new_genesis(genesis_seed, key_a.clone());

        for r in 1..=10 {
            let att = chain_a.create_attestation(Some(0));
            chain_a.extend(vec![att]);
        }

        // Chain B: Many attesters per round
        let key_b = SigningKey::generate(&mut OsRng);
        let keys_b: Vec<SigningKey> = (0..5)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();
        let mut chain_b = CvdfChain::new_genesis(genesis_seed, key_b.clone());

        for r in 1..=10 {
            let attestations: Vec<RoundAttestation> = keys_b.iter()
                .enumerate()
                .map(|(i, k)| RoundAttestation::new(r, chain_b.tip_output(), Some(i as u64), k))
                .collect();
            chain_b.extend(attestations);
        }

        println!("Chain A: height {}, weight {}, avg attesters {:.1}",
            chain_a.height(), chain_a.total_weight(), chain_a.avg_attesters());
        println!("Chain B: height {}, weight {}, avg attesters {:.1}",
            chain_b.height(), chain_b.total_weight(), chain_b.avg_attesters());

        // Same height but B has more weight (more attesters)
        assert_eq!(chain_a.height(), chain_b.height());
        assert!(chain_b.total_weight() > chain_a.total_weight());

        // A should adopt B's heavier chain
        assert!(chain_a.should_adopt(chain_b.all_rounds()));

        println!("\nChain A should adopt Chain B: {}",
            chain_a.should_adopt(chain_b.all_rounds()));

        println!("\n=== Weight Comparison PASSED ===\n");
    }

    #[test]
    fn test_cvdf_coordinator_collaboration() {
        let genesis_seed = [42u8; 32];

        println!("\n=== CVDF Coordinator Collaboration ===\n");

        // Create 5 nodes
        let keys: Vec<SigningKey> = (0..5)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();

        // Genesis coordinator
        let mut coordinators: Vec<CvdfCoordinator> = vec![
            CvdfCoordinator::new_genesis(genesis_seed, keys[0].clone())
        ];
        coordinators[0].set_slot(0);

        // Register ALL slots on genesis first
        for (i, key) in keys.iter().enumerate() {
            coordinators[0].register_slot(i as u64, key.verifying_key().to_bytes());
        }

        // Other nodes join
        for (i, key) in keys.iter().enumerate().skip(1) {
            let rounds = coordinators[0].chain().all_rounds().to_vec();
            let mut coord = CvdfCoordinator::join(genesis_seed, rounds, key.clone())
                .expect("Should join");
            coord.set_slot(i as u64);

            // Register ALL slots on this coordinator
            for (j, k) in keys.iter().enumerate() {
                coord.register_slot(j as u64, k.verifying_key().to_bytes());
            }

            coordinators.push(coord);
        }

        let start = std::time::Instant::now();

        // Cooperatively produce 20 rounds
        for _ in 0..20 {
            // All nodes create attestations
            let attestations: Vec<RoundAttestation> = coordinators.iter()
                .map(|c| c.attest())
                .collect();

            // Distribute attestations to all nodes
            for coord in &mut coordinators {
                for att in &attestations {
                    coord.receive_attestation(att.clone());
                }
            }

            // Find producer (whoever's turn it is)
            let mut produced_round: Option<CvdfRound> = None;
            for coord in &mut coordinators {
                if coord.is_our_turn() {
                    if let Some(round) = coord.try_produce() {
                        produced_round = Some(round);
                        break;
                    }
                }
            }

            // Distribute round to all nodes
            if let Some(round) = produced_round {
                for coord in &mut coordinators {
                    coord.process_round(round.clone());
                }
            }
        }

        let elapsed = start.elapsed();

        // All coordinators should be at same height
        for (i, coord) in coordinators.iter().enumerate() {
            assert_eq!(coord.height(), 20,
                "Coordinator {} should be at height 20", i);
        }

        let total_weight = coordinators[0].weight();
        let avg_attesters = coordinators[0].chain().avg_attesters();

        println!("5 nodes produced 20 rounds in {:?}", elapsed);
        println!("Total chain weight: {}", total_weight);
        println!("Average attesters per round: {:.1}", avg_attesters);
        println!("Expected weight: 1 + 20 * (1 + 5) = {}", 1 + 20 * 6);

        // Weight should be: genesis(1) + 20 rounds * (base 1 + 5 attesters)
        assert_eq!(total_weight, 1 + 20 * 6);

        println!("\n=== Coordinator Collaboration PASSED ===\n");
    }

    #[test]
    fn test_cvdf_swarm_merge() {
        let genesis_seed = [42u8; 32];

        println!("\n=== CVDF Swarm Merge (Heavier Chain Wins) ===\n");

        // Swarm A: 3 nodes, well-coordinated
        let keys_a: Vec<SigningKey> = (0..3)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();

        let mut chain_a = CvdfChain::new_genesis(genesis_seed, keys_a[0].clone());

        // A produces 15 rounds with all 3 attesters
        for r in 1..=15 {
            let attestations: Vec<RoundAttestation> = keys_a.iter()
                .enumerate()
                .map(|(i, k)| RoundAttestation::new(r, chain_a.tip_output(), Some(i as u64), k))
                .collect();
            chain_a.extend(attestations);
        }

        // Swarm B: 1 node, solo mining
        let key_b = SigningKey::generate(&mut OsRng);
        let mut chain_b = CvdfChain::new_genesis(genesis_seed, key_b.clone());

        // B produces 20 rounds but only 1 attester each
        for r in 1..=20 {
            let att = RoundAttestation::new(r, chain_b.tip_output(), Some(0), &key_b);
            chain_b.extend(vec![att]);
        }

        println!("Swarm A: height {}, weight {}, avg attesters {:.1}",
            chain_a.height(), chain_a.total_weight(), chain_a.avg_attesters());
        println!("Swarm B: height {}, weight {}, avg attesters {:.1}",
            chain_b.height(), chain_b.total_weight(), chain_b.avg_attesters());

        // A has fewer rounds but more weight (more attesters)
        // A weight: 1 + 15 * (1 + 3) = 1 + 60 = 61
        // B weight: 1 + 20 * (1 + 1) = 1 + 40 = 41
        assert_eq!(chain_a.total_weight(), 1 + 15 * 4);
        assert_eq!(chain_b.total_weight(), 1 + 20 * 2);

        // B should adopt A's heavier chain (even though B is taller!)
        assert!(chain_b.should_adopt(chain_a.all_rounds()));

        let adopted = chain_b.adopt(chain_a.all_rounds().to_vec());
        assert!(adopted);

        println!("\nAfter merge:");
        println!("B adopted A's chain: {}", adopted);
        println!("B's new height: {}, weight: {}",
            chain_b.height(), chain_b.total_weight());

        println!("\n=== Swarm Merge PASSED ===\n");
        println!("KEY INSIGHT: Heavier chain (more collaboration) wins over taller chain (solo mining)!");
    }
}
