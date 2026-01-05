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
use citadel_spore::Spore;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// VDF iterations per round - base difficulty (~50ms on modern hardware)
/// This is the default for genesis; actual difficulty comes from heaviest chain
pub const CVDF_ITERATIONS_BASE: u32 = 100_000;

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
    /// Difficulty (iterations) used for this round - network-agreed
    #[serde(default = "default_iterations")]
    pub iterations: u32,
}

/// Default iterations for backwards compatibility with old rounds
fn default_iterations() -> u32 {
    CVDF_ITERATIONS_BASE
}

impl CvdfRound {
    /// Create genesis round with specified difficulty
    pub fn genesis(seed: &[u8], signing_key: &SigningKey) -> Self {
        Self::genesis_with_difficulty(seed, signing_key, CVDF_ITERATIONS_BASE)
    }

    /// Create genesis round with specific difficulty (for testing/network consensus)
    pub fn genesis_with_difficulty(seed: &[u8], signing_key: &SigningKey, iterations: u32) -> Self {
        let producer = signing_key.verifying_key().to_bytes();

        // Genesis has no previous output
        let prev_output = [0u8; 32];

        // Washed input is just the seed for genesis
        let washed_input = *blake3::hash(seed).as_bytes();

        // Compute VDF with specified difficulty
        let output = compute_cvdf(&washed_input, iterations);

        // Sign the round (include iterations in signature)
        let mut msg = Vec::with_capacity(100);
        msg.extend_from_slice(&0u64.to_le_bytes()); // round 0
        msg.extend_from_slice(&washed_input);
        msg.extend_from_slice(&output);
        msg.extend_from_slice(&iterations.to_le_bytes());
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
            iterations,
        }
    }

    /// Create next round from attestations with network-agreed difficulty
    pub fn from_attestations(
        round: u64,
        prev_output: [u8; 32],
        attestations: Vec<RoundAttestation>,
        signing_key: &SigningKey,
        iterations: u32,
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

        // Compute VDF with network-agreed difficulty
        let output = compute_cvdf(&washed_input, iterations);

        let producer = signing_key.verifying_key().to_bytes();

        // Sign the round (include iterations in signature)
        let mut msg = Vec::with_capacity(100);
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&washed_input);
        msg.extend_from_slice(&output);
        msg.extend_from_slice(&iterations.to_le_bytes());
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
            iterations,
        })
    }

    /// Verify this round is valid (uses stored iterations)
    pub fn verify(&self, expected_prev: &[u8; 32]) -> bool {
        self.verify_with_expected_difficulty(expected_prev, self.iterations)
    }

    /// Verify this round is valid with expected difficulty (for network consensus)
    pub fn verify_with_expected_difficulty(&self, expected_prev: &[u8; 32], expected_iterations: u32) -> bool {
        // Check difficulty matches expected (from heaviest chain - TGP consensus)
        if self.iterations != expected_iterations {
            return false;
        }

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

        // Verify VDF output using the stored iterations
        let expected_output = compute_cvdf(&self.washed_input, self.iterations);
        if self.output != expected_output {
            return false;
        }

        // Verify producer signature (must include iterations)
        let verifying_key = match VerifyingKey::from_bytes(&self.producer) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.producer_signature);

        // Try new signature format (with iterations)
        let mut msg = Vec::with_capacity(100);
        msg.extend_from_slice(&self.round.to_le_bytes());
        msg.extend_from_slice(&self.washed_input);
        msg.extend_from_slice(&self.output);
        msg.extend_from_slice(&self.iterations.to_le_bytes());

        if verifying_key.verify(&msg, &signature).is_ok() {
            return true;
        }

        // Backwards compatibility: try old signature format (without iterations)
        // Only accept if iterations == base (old default)
        if self.iterations == CVDF_ITERATIONS_BASE {
            let mut old_msg = Vec::with_capacity(96);
            old_msg.extend_from_slice(&self.round.to_le_bytes());
            old_msg.extend_from_slice(&self.washed_input);
            old_msg.extend_from_slice(&self.output);
            return verifying_key.verify(&old_msg, &signature).is_ok();
        }

        false
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

/// Minimum difficulty - the cooperative equilibrium
/// Network runs on essentially nothing when everyone cooperates
pub const CVDF_ITERATIONS_MIN: u32 = 1_000;

/// Network health metrics for difficulty adjustment
///
/// INVERTED ECONOMICS: Unlike PoW where waste is the default,
/// SPIRAL defaults to MINIMUM energy. Difficulty only ramps
/// when attacks are detected - making cooperation the Nash equilibrium.
#[derive(Debug, Clone, Default)]
pub struct NetworkHealth {
    /// Attestation counts for recent rounds
    pub recent_attestation_counts: Vec<usize>,
    /// Fork events detected (attack indicator)
    pub fork_count: u32,
    /// Spam claim attempts (attack indicator)
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
            // Start at minimum - cooperation is the default
            current_iterations: CVDF_ITERATIONS_MIN,
        }
    }

    /// Record a round's attestation count
    pub fn record_round(&mut self, attestation_count: usize) {
        self.recent_attestation_counts.push(attestation_count);
        if self.recent_attestation_counts.len() > DIFFICULTY_WINDOW {
            self.recent_attestation_counts.remove(0);
        }
        // Decay attack indicators over time - network heals
        if self.fork_count > 0 {
            self.fork_count = self.fork_count.saturating_sub(1);
        }
        if self.spam_claim_count > 0 {
            self.spam_claim_count = self.spam_claim_count.saturating_sub(1);
        }
    }

    /// Record a fork detection - triggers difficulty ramp
    pub fn record_fork(&mut self) {
        // Forks are serious - ramp difficulty significantly
        self.fork_count = self.fork_count.saturating_add(5);
    }

    /// Record a spam claim attempt - triggers difficulty ramp
    pub fn record_spam(&mut self) {
        self.spam_claim_count = self.spam_claim_count.saturating_add(1);
    }

    /// Compute difficulty based on network health
    ///
    /// INVERTED FROM POW:
    /// - Default: minimum difficulty (cooperation = cheap)
    /// - Attack detected: difficulty MULTIPLIES (defection = expensive)
    /// - Recovery: decay back to minimum (network heals)
    ///
    /// This makes cooperation the rational selfish choice.
    pub fn compute_difficulty(&mut self) -> u32 {
        // Attack score determines difficulty multiplier
        let attack_score = self.fork_count + self.spam_claim_count;

        // Target difficulty = minimum * (1 + attack_multiplier)
        // No upper bound - difficulty scales with attack intensity
        let multiplier = 1 + attack_score;
        let target = CVDF_ITERATIONS_MIN.saturating_mul(multiplier);

        // Smooth transitions - ramp up fast on attack, decay slowly on recovery
        if target > self.current_iterations {
            // Under attack - ramp up quickly (50% toward target)
            let diff = target - self.current_iterations;
            self.current_iterations = self.current_iterations.saturating_add(diff / 2);
        } else {
            // Recovering - decay slowly (10% toward target)
            let diff = self.current_iterations - target;
            self.current_iterations = self.current_iterations.saturating_sub(diff / 10);
        }

        // Never go below minimum
        self.current_iterations = self.current_iterations.max(CVDF_ITERATIONS_MIN);

        self.current_iterations
    }

    /// Check if network is under attack
    pub fn is_under_attack(&self) -> bool {
        self.fork_count > 0 || self.spam_claim_count > 0
    }

    /// Get attack severity (0 = peaceful, higher = worse)
    pub fn attack_severity(&self) -> u32 {
        self.fork_count + self.spam_claim_count
    }
}

/// Slot liveness tracker - prunes slots that stop contributing
#[derive(Debug, Clone, Default)]
pub struct SlotLiveness {
    /// Last round each slot attested (slot -> round)
    pub last_attestation: HashMap<u64, u64>,
    /// Current round number
    pub current_round: u64,
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

    /// Get difficulty from chain tip (network-agreed difficulty)
    pub fn tip_difficulty(&self) -> u32 {
        self.rounds.last().map(|r| r.iterations).unwrap_or(CVDF_ITERATIONS_BASE)
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

    /// Extend chain with new round from attestations (uses tip difficulty)
    pub fn extend(&mut self, attestations: Vec<RoundAttestation>) -> Option<&CvdfRound> {
        self.extend_with_difficulty(attestations, self.tip_difficulty())
    }

    /// Extend chain with new round from attestations with explicit difficulty
    pub fn extend_with_difficulty(&mut self, attestations: Vec<RoundAttestation>, iterations: u32) -> Option<&CvdfRound> {
        let next_round = self.height() + 1;
        let prev_output = self.tip_output();

        let round = CvdfRound::from_attestations(
            next_round,
            prev_output,
            attestations,
            &self.signing_key,
            iterations,
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

    /// Verify entire chain (uses stored iterations for each round)
    pub fn verify_full(&self) -> bool {
        if self.rounds.is_empty() {
            return false;
        }

        // Verify genesis
        let genesis = &self.rounds[0];
        if genesis.round != 0 {
            return false;
        }

        // Verify genesis VDF using stored iterations
        let expected_genesis_output = compute_cvdf(&genesis.washed_input, genesis.iterations);
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

            // Each round is verified with its own stored iterations
            if !curr.verify(&prev.output) {
                return false;
            }
        }

        true
    }

    /// Verify only NEW rounds incrementally (cooperative model)
    ///
    /// This is the key optimization for CVDF: we don't re-verify history.
    /// Only verify rounds from `from_height` onwards, assuming prior rounds
    /// are already validated (they're in our chain).
    ///
    /// Used for normal sync where we share common ancestry.
    pub fn verify_incremental(&self, new_rounds: &[CvdfRound], from_height: u64) -> bool {
        if new_rounds.is_empty() {
            return true;
        }

        // Get our tip output at the fork point
        let fork_output = if from_height == 0 {
            // Genesis case - check genesis seed
            [0u8; 32]
        } else {
            // Find our round at from_height - 1
            let fork_idx = (from_height - 1) as usize;
            if fork_idx >= self.rounds.len() {
                return false; // Can't verify - we don't have the fork point
            }
            self.rounds[fork_idx].output
        };

        // Verify chain of new rounds
        let mut prev_output = fork_output;
        for round in new_rounds {
            // Each round must chain correctly
            if round.round > 0 && round.prev_output != prev_output {
                return false;
            }
            // Verify the round itself (attestations, VDF output)
            if !round.verify(&prev_output) {
                return false;
            }
            prev_output = round.output;
        }

        true
    }

    /// Compare with another chain - returns true if we should adopt theirs
    ///
    /// COOPERATIVE MODEL: Use incremental verification when possible.
    /// Only falls back to full verification for bootstrap/fork scenarios.
    pub fn should_adopt(&self, other_rounds: &[CvdfRound]) -> bool {
        if other_rounds.is_empty() {
            return false;
        }

        // Calculate their weight without full verification first
        let their_weight: u64 = other_rounds.iter().map(|r| r.weight()).sum();
        let our_weight = self.total_weight();

        // Quick rejection: if not heavier, don't bother verifying
        if their_weight <= our_weight {
            return false;
        }

        // Find common ancestry for incremental verification
        // Look for where our chains diverge

        // Find fork point: highest round where outputs match
        let mut fork_height: u64 = 0;
        for our_round in &self.rounds {
            // Find corresponding round in their chain
            let their_idx = our_round.round as usize;
            if their_idx < other_rounds.len() {
                let their_round = &other_rounds[their_idx];
                if their_round.output == our_round.output {
                    fork_height = our_round.round + 1;
                } else {
                    break; // Divergence found
                }
            }
        }

        if fork_height > 0 {
            // INCREMENTAL: We share ancestry, only verify new rounds
            let new_rounds = &other_rounds[fork_height as usize..];
            if !self.verify_incremental(new_rounds, fork_height) {
                return false;
            }
        } else {
            // FULL: No common ancestry (bootstrap/partition recovery)
            // This is the expensive path - only for joining or major forks
            let other = match CvdfChain::from_rounds(
                self.genesis_seed,
                other_rounds.to_vec(),
                self.signing_key.clone(),
            ) {
                Some(c) => c,
                None => return false,
            };
            // Sanity check weight matches
            if other.total_weight() != their_weight {
                return false;
            }
        }

        // Heavier chain wins (per CVDF.lean theorem: collaboration_wins)
        true
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

    /// Get current network difficulty from heaviest chain tip
    pub fn current_difficulty(&self) -> u32 {
        self.chain.tip_difficulty()
    }

    /// Get and update computed difficulty based on network health
    pub fn compute_and_update_difficulty(&mut self) -> u32 {
        self.network_health.compute_difficulty()
    }

    /// Record network health event (for difficulty adjustment)
    pub fn record_round_health(&mut self, attestation_count: usize) {
        self.network_health.record_round(attestation_count);
    }

    /// Record a fork detection (increases difficulty)
    pub fn record_fork(&mut self) {
        self.network_health.record_fork();
    }

    /// Record spam claim attempt (increases difficulty)
    pub fn record_spam(&mut self) {
        self.network_health.record_spam();
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

        // Track liveness for this slot (if attestation has one)
        if let Some(slot) = att.slot {
            self.slot_liveness.record_attestation(slot, att.round);
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
    /// Uses difficulty from heaviest chain tip (network consensus)
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

        // Record health metrics for this round
        self.network_health.record_round(attestations.len());

        // Get difficulty from heaviest chain tip (network consensus)
        // This is the key fix: use tip difficulty, not hardcoded constant
        let iterations = self.chain.tip_difficulty();

        // Clear pending
        self.pending_attestations.clear();

        // Extend chain with network-agreed difficulty
        self.chain.extend_with_difficulty(attestations, iterations)?;
        self.chain.tip().cloned()
    }

    /// Try to produce with explicit difficulty (for testing or consensus override)
    pub fn try_produce_with_difficulty(&mut self, iterations: u32) -> Option<CvdfRound> {
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

        // Record health metrics
        self.network_health.record_round(attestations.len());

        // Clear pending
        self.pending_attestations.clear();

        // Extend chain with specified difficulty
        self.chain.extend_with_difficulty(attestations, iterations)?;
        self.chain.tip().cloned()
    }

    /// Process incoming round from another producer
    /// Validates difficulty matches our chain tip (network consensus)
    pub fn process_round(&mut self, round: CvdfRound) -> bool {
        // Verify round difficulty matches network consensus
        let expected_difficulty = self.chain.tip_difficulty();
        if round.iterations != expected_difficulty {
            // Difficulty mismatch - could be attack or fork
            // Allow some tolerance for transition periods
            let diff = if round.iterations > expected_difficulty {
                round.iterations - expected_difficulty
            } else {
                expected_difficulty - round.iterations
            };
            // Allow up to 25% difference during transitions
            if diff > expected_difficulty / 4 {
                self.network_health.record_fork();
                return false;
            }
        }

        // Record health metrics
        self.network_health.record_round(round.attestations.len());

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

    // =========================================================================
    // Neighbour Liveness Monitoring
    // =========================================================================
    //
    // Track which slots are actively participating in VDF rounds.
    // Slots that don't attest within SLOT_LIVENESS_THRESHOLD rounds are stale.

    /// Check if a specific slot is live (attested recently)
    pub fn is_slot_live(&self, slot: u64) -> bool {
        self.slot_liveness.is_live(slot)
    }

    /// Get all stale slots (haven't attested in SLOT_LIVENESS_THRESHOLD rounds)
    pub fn stale_slots(&self) -> Vec<u64> {
        self.slot_liveness.stale_slots()
    }

    /// Get liveness status for all registered slots
    /// Returns Vec<(slot, is_live, last_attestation_round)>
    pub fn slot_liveness_status(&self) -> Vec<(u64, bool, Option<u64>)> {
        self.slot_holders.keys().map(|&slot| {
            let is_live = self.slot_liveness.is_live(slot);
            let last_round = self.slot_liveness.last_attestation.get(&slot).copied();
            (slot, is_live, last_round)
        }).collect()
    }

    /// Get current round number (from chain tip)
    pub fn current_round(&self) -> u64 {
        self.chain.height()
    }

    /// Advance liveness tracking to new round
    pub fn advance_liveness(&mut self, round: u64) {
        self.slot_liveness.advance_round(round);
    }

    /// Prune stale slots from slot_holders
    /// Returns list of pruned slots
    pub fn prune_stale_slots(&mut self) -> Vec<u64> {
        let stale = self.slot_liveness.stale_slots();
        for &slot in &stale {
            self.slot_holders.remove(&slot);
            self.slot_liveness.remove_slot(slot);
        }
        stale
    }
}

// ============================================================================
// SPORE STAPLING: Zero-overhead sync proofs attached to VDF heartbeats
// ============================================================================

/// VDF heartbeat with stapled SPORE XOR proof.
///
/// The SPORE proof shows what content this node has that peers might not.
/// At convergence (all nodes synced), the proof is empty - zero overhead.
///
/// This is how we achieve event-driven mesh: the only activity at idle
/// is the VDF heartbeat, and when synced, SPORE adds nothing to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VdfHeartbeat {
    /// The VDF round (contains difficulty, attestations, output)
    pub round: CvdfRound,
    /// Stapled SPORE XOR proof - empty at convergence
    /// Represents: "what I have that you might not"
    pub spore_proof: Spore,
}

impl VdfHeartbeat {
    /// Create a heartbeat with SPORE proof.
    ///
    /// The proof is the XOR of our HaveList against the peer's known HaveList.
    /// - If peer's list is unknown, use our full HaveList
    /// - If synced, result is empty (zero bytes)
    pub fn new(round: CvdfRound, our_have: &Spore, their_have: Option<&Spore>) -> Self {
        let spore_proof = match their_have {
            Some(theirs) => our_have.xor(theirs),
            None => our_have.clone(), // First contact - send full list
        };

        Self { round, spore_proof }
    }

    /// Create a heartbeat with empty proof (for nodes known to be synced)
    pub fn synced(round: CvdfRound) -> Self {
        Self {
            round,
            spore_proof: Spore::empty(),
        }
    }

    /// Check if this heartbeat indicates we're synced (empty proof)
    pub fn is_synced(&self) -> bool {
        self.spore_proof.range_count() == 0
    }

    /// Get the overhead of the SPORE proof in bytes.
    /// At convergence: 0 bytes (zero overhead)
    pub fn spore_overhead(&self) -> usize {
        self.spore_proof.encoding_size()
    }
}

/// Sync state tracker for SPORE stapling.
///
/// Tracks what each peer has so we can compute minimal XOR proofs.
/// As peers sync, the proofs shrink to zero.
#[derive(Debug, Clone, Default)]
pub struct SporeSyncState {
    /// Our HaveList (content we possess)
    our_have: Spore,
    /// Each peer's known HaveList
    peer_have: HashMap<[u8; 32], Spore>,
}

impl SporeSyncState {
    pub fn new() -> Self {
        Self {
            our_have: Spore::empty(),
            peer_have: HashMap::new(),
        }
    }

    /// Update our HaveList
    pub fn set_our_have(&mut self, have: Spore) {
        self.our_have = have;
    }

    /// Get our HaveList
    pub fn our_have(&self) -> &Spore {
        &self.our_have
    }

    /// Update a peer's known HaveList
    pub fn update_peer_have(&mut self, peer_id: [u8; 32], have: Spore) {
        self.peer_have.insert(peer_id, have);
    }

    /// Get a peer's known HaveList
    pub fn peer_have(&self, peer_id: &[u8; 32]) -> Option<&Spore> {
        self.peer_have.get(peer_id)
    }

    /// Create a heartbeat for a specific peer.
    /// XOR proof will be minimal based on what they already have.
    pub fn create_heartbeat(&self, round: CvdfRound, peer_id: &[u8; 32]) -> VdfHeartbeat {
        VdfHeartbeat::new(round, &self.our_have, self.peer_have.get(peer_id))
    }

    /// Process an incoming heartbeat from a peer.
    /// Updates our knowledge of what they have.
    pub fn process_heartbeat(&mut self, peer_id: [u8; 32], heartbeat: &VdfHeartbeat) {
        // The XOR proof tells us what they have that differs from us
        // Combine with our existing knowledge
        if let Some(existing) = self.peer_have.get(&peer_id) {
            // Update: their new state = existing XOR (their XOR proof)
            // This is approximate - in practice we'd merge properly
            let updated = existing.union(&heartbeat.spore_proof);
            self.peer_have.insert(peer_id, updated);
        } else {
            // First contact - the proof IS their HaveList
            self.peer_have.insert(peer_id, heartbeat.spore_proof.clone());
        }
    }

    /// Check if we're synced with a peer (XOR is empty)
    pub fn is_synced_with(&self, peer_id: &[u8; 32]) -> bool {
        match self.peer_have.get(peer_id) {
            Some(theirs) => self.our_have.xor(theirs).range_count() == 0,
            None => false, // Unknown peer = not synced
        }
    }

    /// Get total sync overhead across all peers (for monitoring)
    pub fn total_overhead(&self) -> usize {
        self.peer_have
            .values()
            .map(|have| self.our_have.xor(have).encoding_size())
            .sum()
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

    #[cfg(feature = "heavy_tests")]
    #[test]
    fn test_cvdf_coordinator_collaboration_heavy() {

        println!("\n=== CVDF Coordinator Collaboration Heavy===\n");
        run_test_cvdf_coordinator_collaboration(5, 20);

        println!("\n=== Coordinator Collaboration Heavy PASSED ===\n");
    }
    #[cfg(not(feature = "heavy_tests"))]
    #[test]
    fn test_cvdf_coordinator_collaboration_light() {

        println!("\n=== CVDF Coordinator Collaboration Light===\n");
        run_test_cvdf_coordinator_collaboration(3, 5);

        println!("\n=== Coordinator Collaboration Light PASSED ===\n");
    }
    fn run_test_cvdf_coordinator_collaboration(nodes: u64, rounds: u64) {
        let genesis_seed = [42u8; 32];

        println!("\n=== CVDF Coordinator Collaboration ===\n");

        // Create the nodes
        let keys: Vec<SigningKey> = (0..nodes)
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

        // Cooperatively produce the rounds
        for _ in 0..rounds {
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
            assert_eq!(coord.height(), rounds,
                "Coordinator {} should be at height {}", i, rounds);
        }

        let total_weight = coordinators[0].weight();
        let avg_attesters = coordinators[0].chain().avg_attesters();

        println!("{} nodes produced {} rounds in {:?}", nodes, rounds, elapsed);
        println!("Total chain weight: {}", total_weight);
        println!("Average attesters per round: {:.1}", avg_attesters);
        println!("Expected weight: 1 + {} * (1 + {}) = {}", rounds, nodes, 1 + rounds * (1 + nodes));

        // Weight should be: genesis(1) + 20 rounds * (base 1 + 5 attesters)
        assert_eq!(total_weight, 1 + rounds * (nodes + 1));

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

    #[test]
    fn test_spore_stapling_convergence() {
        use citadel_spore::{Range256, U256};

        println!("\n=== SPORE Stapling Convergence ===\n");

        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let chain = CvdfChain::new_genesis(genesis_seed, signing_key);
        let round = chain.tip().unwrap().clone();

        // Create two nodes with different content
        let mut node_a = SporeSyncState::new();
        let mut node_b = SporeSyncState::new();

        // Node A has content [0, 1000)
        let have_a = Spore::from_range(Range256::new(U256::ZERO, U256::from_u64(1000)));
        node_a.set_our_have(have_a);

        // Node B has content [500, 1500)
        let have_b = Spore::from_range(Range256::new(U256::from_u64(500), U256::from_u64(1500)));
        node_b.set_our_have(have_b);

        // Before sync: XOR is non-empty
        let peer_a_id = [1u8; 32];
        let peer_b_id = [2u8; 32];

        // A creates heartbeat for B (doesn't know B's state yet)
        let hb_a_to_b = node_a.create_heartbeat(round.clone(), &peer_b_id);
        println!("Initial heartbeat A→B: {} ranges, {} bytes overhead",
            hb_a_to_b.spore_proof.range_count(),
            hb_a_to_b.spore_overhead());

        // B receives A's heartbeat
        node_b.process_heartbeat(peer_a_id, &hb_a_to_b);

        // B creates heartbeat for A (now knows A's state)
        let hb_b_to_a = node_b.create_heartbeat(round.clone(), &peer_a_id);
        println!("Response heartbeat B→A: {} ranges, {} bytes overhead",
            hb_b_to_a.spore_proof.range_count(),
            hb_b_to_a.spore_overhead());

        // Simulate sync: both nodes converge to same content
        let synced_have = Spore::from_range(Range256::new(U256::ZERO, U256::from_u64(1500)));
        node_a.set_our_have(synced_have.clone());
        node_b.set_our_have(synced_have.clone());
        node_a.update_peer_have(peer_b_id, synced_have.clone());
        node_b.update_peer_have(peer_a_id, synced_have);

        // After sync: XOR is empty (zero overhead)
        assert!(node_a.is_synced_with(&peer_b_id), "A should be synced with B");
        assert!(node_b.is_synced_with(&peer_a_id), "B should be synced with A");

        let hb_synced = node_a.create_heartbeat(round.clone(), &peer_b_id);
        println!("Synced heartbeat: {} ranges, {} bytes overhead",
            hb_synced.spore_proof.range_count(),
            hb_synced.spore_overhead());

        assert!(hb_synced.is_synced(), "Synced heartbeat should have empty proof");
        assert_eq!(hb_synced.spore_overhead(), 0, "Synced = zero SPORE overhead");

        println!("\n=== SPORE Stapling PASSED ===\n");
        println!("KEY INSIGHT: At convergence, heartbeat overhead is ZERO.");
        println!("The only activity is the VDF round itself - pure event-driven mesh.");
    }
}
