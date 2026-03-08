//! PVDF - Parallel VDF for Swarm Consensus
//!
//! # The Key Insight
//!
//! ```text
//! NOT: N nodes each with independent VDF
//! BUT: Y swarms, each cooperatively advancing ONE VDF chain
//!
//! ┌─────────────────────────────────────┐
//! │           SWARM A (30 nodes)        │
//! │                                     │
//! │  [v0]─►[v1]─►[v2]─►...─►[v1000]    │
//! │   │     │     │     │              │
//! │  n1    n2    n3    n4  (delegate)  │
//! │                                     │
//! │  All 30 nodes see the SAME chain   │
//! │  VDF duty rotates by slot index    │
//! └─────────────────────────────────────┘
//!
//!        ↓ PARTITION HAPPENS ↓
//!
//! ┌────────────────────┐   ┌────────────────────┐
//! │   SWARM A (20)     │   │   SWARM B (10)     │
//! │                    │   │                    │
//! │  [v0]─►..─►[v1500] │   │  [v0]─►..─►[v800] │
//! │  More nodes = fast │   │  Fewer = slower   │
//! └────────────────────┘   └────────────────────┘
//!
//!        ↓ RECONNECTION ↓
//!
//! ┌─────────────────────────────────────┐
//! │           MERGED SWARM (30)         │
//! │                                     │
//! │  A wins (height 1500 > 800)         │
//! │  B nodes adopt A's chain            │
//! │  B's slot claims re-evaluated       │
//! │  Clean merge, no fork               │
//! └─────────────────────────────────────┘
//! ```
//!
//! # Cooperative VDF Delegation
//!
//! Within a swarm, nodes take turns computing VDF:
//! 1. VDF duty assigned by: `chain_height % active_slots`
//! 2. Current duty holder computes next VDF step
//! 3. Broadcasts result, all nodes adopt
//! 4. Duty rotates to next slot
//!
//! This means:
//! - More nodes = faster VDF growth
//! - Chain length proves swarm SIZE * TIME
//! - Natural "longest chain wins" semantics
//!
//! # Swarm Identity
//!
//! A swarm is identified by:
//! - Genesis seed (shared globally)
//! - Set of reachable peers (connectivity)
//! - VDF chain tip (consensus state)
//!
//! Nodes in same swarm have same VDF chain tip (or converging to it).

use crate::vdf_race::{claim_has_priority, AnchoredSlotClaim, VdfChain, VdfLink, REORG_THRESHOLD};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Swarm state - tracks our current swarm and VDF chain
#[derive(Debug)]
pub struct SwarmState {
    /// Our signing key
    signing_key: SigningKey,
    /// Our public key (cached)
    our_pubkey: [u8; 32],
    /// Our claimed slot in the swarm (if any)
    our_slot: Option<u64>,
    /// Genesis seed (shared across all swarms from same origin)
    genesis_seed: [u8; 32],
    /// Our swarm's VDF chain
    vdf_chain: VdfChain,
    /// Known peers in our swarm (pubkey -> last seen height)
    swarm_peers: HashMap<[u8; 32], u64>,
    /// Slot claims we've seen (slot -> best claim)
    slot_claims: HashMap<u64, AnchoredSlotClaim>,
    /// Last time we computed VDF (to avoid double-duty)
    last_vdf_compute: Option<Instant>,
    /// Pending merge candidates (swarm_tip_hash -> SwarmMergeCandidate)
    merge_candidates: HashMap<[u8; 32], SwarmMergeCandidate>,
}

/// Information about a potential swarm merge
#[derive(Debug, Clone)]
pub struct SwarmMergeCandidate {
    /// Their VDF chain links
    pub chain_links: Vec<VdfLink>,
    /// Their slot claims
    pub slot_claims: HashMap<u64, AnchoredSlotClaim>,
    /// Discovery time
    pub discovered_at: Instant,
    /// Source peer
    pub source_peer: [u8; 32],
}

/// Result of a swarm merge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergeResult {
    /// We won - other swarm should adopt our chain
    WeWon { our_height: u64, their_height: u64 },
    /// They won - we adopt their chain
    TheyWon {
        our_height: u64,
        their_height: u64,
        claims_to_revalidate: Vec<u64>,
    },
    /// Tie - use deterministic tiebreaker (lower tip hash wins)
    Tie {
        height: u64,
        our_tip: [u8; 32],
        their_tip: [u8; 32],
        we_win: bool,
    },
    /// Same swarm - no merge needed
    SameSwarm,
}

/// VDF duty assignment for cooperative computation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdfDuty {
    /// It's our turn to compute
    OurTurn,
    /// Another node's turn (slot index)
    TheirTurn(u64),
    /// No slots claimed yet - genesis mode
    Genesis,
}

/// Message types for swarm coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmMessage {
    /// Announce our swarm identity (periodic heartbeat)
    SwarmHeartbeat {
        sender: [u8; 32],
        vdf_height: u64,
        vdf_tip: [u8; 32],
        slot_count: usize,
    },
    /// Request full chain sync
    ChainSyncRequest { sender: [u8; 32], from_height: u64 },
    /// Chain sync response
    ChainSyncResponse {
        sender: [u8; 32],
        links: Vec<VdfLink>,
    },
    /// New VDF link computed
    VdfLinkBroadcast { link: VdfLink },
    /// Merge proposal (we detected a foreign swarm)
    MergeProposal {
        sender: [u8; 32],
        our_height: u64,
        our_tip: [u8; 32],
        their_height: u64,
        their_tip: [u8; 32],
    },
    /// Merge acceptance (lower chain agrees to adopt)
    MergeAccept {
        sender: [u8; 32],
        adopted_height: u64,
    },
}

impl SwarmState {
    /// Create new swarm as genesis (we are the founding node)
    pub fn new_genesis(genesis_seed: [u8; 32], signing_key: SigningKey) -> Self {
        let our_pubkey = signing_key.verifying_key().to_bytes();
        let vdf_chain = VdfChain::new_genesis(genesis_seed, our_pubkey);

        Self {
            signing_key,
            our_pubkey,
            our_slot: None,
            genesis_seed,
            vdf_chain,
            swarm_peers: HashMap::new(),
            slot_claims: HashMap::new(),
            last_vdf_compute: None,
            merge_candidates: HashMap::new(),
        }
    }

    /// Join existing swarm with their chain
    pub fn join_swarm(
        genesis_seed: [u8; 32],
        signing_key: SigningKey,
        existing_chain: Vec<VdfLink>,
    ) -> Option<Self> {
        let our_pubkey = signing_key.verifying_key().to_bytes();
        let vdf_chain = VdfChain::from_links(genesis_seed, existing_chain, our_pubkey)?;

        Some(Self {
            signing_key,
            our_pubkey,
            our_slot: None,
            genesis_seed,
            vdf_chain,
            swarm_peers: HashMap::new(),
            slot_claims: HashMap::new(),
            last_vdf_compute: None,
            merge_candidates: HashMap::new(),
        })
    }

    /// Get current VDF chain height
    pub fn height(&self) -> u64 {
        self.vdf_chain.height()
    }

    /// Get current VDF tip output
    pub fn tip_output(&self) -> [u8; 32] {
        self.vdf_chain.tip().map(|l| l.output).unwrap_or([0u8; 32])
    }

    /// Get our public key
    pub fn our_pubkey(&self) -> [u8; 32] {
        self.our_pubkey
    }

    /// Get our claimed slot
    pub fn our_slot(&self) -> Option<u64> {
        self.our_slot
    }

    /// Get number of active slots in swarm
    pub fn active_slot_count(&self) -> usize {
        self.slot_claims.len()
    }

    /// Determine whose turn it is to compute VDF
    pub fn vdf_duty(&self) -> VdfDuty {
        if self.slot_claims.is_empty() {
            return VdfDuty::Genesis;
        }

        // Sort claimed slots
        let mut slots: Vec<u64> = self.slot_claims.keys().copied().collect();
        slots.sort();

        // Current duty slot based on chain height
        let duty_index = (self.vdf_chain.height() as usize) % slots.len();
        let duty_slot = slots[duty_index];

        // Check if it's our turn
        if let Some(our_slot) = self.our_slot {
            if our_slot == duty_slot {
                return VdfDuty::OurTurn;
            }
        }

        VdfDuty::TheirTurn(duty_slot)
    }

    /// Compute next VDF link (only if it's our turn!)
    pub fn compute_vdf_step(&mut self) -> Option<VdfLink> {
        match self.vdf_duty() {
            VdfDuty::OurTurn | VdfDuty::Genesis => {
                // Record compute time to prevent double-duty
                self.last_vdf_compute = Some(Instant::now());

                // Extend the chain
                let link = self.vdf_chain.extend().clone();
                Some(link)
            }
            VdfDuty::TheirTurn(_) => None,
        }
    }

    /// Process incoming VDF link from another node
    pub fn process_vdf_link(&mut self, link: VdfLink) -> bool {
        // Verify link extends our current chain
        if link.height != self.vdf_chain.height() + 1 {
            return false;
        }

        // Verify link is valid
        let expected_previous = self.vdf_chain.tip().map(|l| l.output).unwrap_or([0u8; 32]);
        if !link.verify(&expected_previous) {
            return false;
        }

        // Adopt the link
        // We need to reconstruct chain with new link
        let mut links = self.vdf_chain.all_links().to_vec();
        links.push(link);

        if let Some(new_chain) = VdfChain::from_links(self.genesis_seed, links, self.our_pubkey) {
            self.vdf_chain = new_chain;
            true
        } else {
            false
        }
    }

    /// Claim a slot in our swarm
    pub fn claim_slot(&mut self, slot: u64) -> AnchoredSlotClaim {
        let tip = self.vdf_chain.tip().expect("Chain must exist");
        let claim = AnchoredSlotClaim::new(slot, self.our_pubkey, tip, &self.signing_key);

        self.our_slot = Some(slot);
        self.slot_claims.insert(slot, claim.clone());

        claim
    }

    /// Process incoming slot claim
    pub fn process_slot_claim(&mut self, claim: AnchoredSlotClaim) -> bool {
        // Verify claim signature and VDF anchor
        if !claim.verify_signature() {
            return false;
        }

        // Check if we have the VDF height they reference
        if claim.vdf_height > self.vdf_chain.height() {
            // Their claim references a height we haven't seen
            // This might mean they're ahead of us - request sync
            return false;
        }

        // Check VDF output matches what we have at that height
        let our_link = self.vdf_chain.all_links().get(claim.vdf_height as usize);
        if let Some(link) = our_link {
            if link.output != claim.vdf_output {
                // Different VDF output - they're on a different chain!
                // This is a foreign swarm - trigger merge detection
                return false;
            }
        } else {
            return false;
        }

        // Check for existing claim on this slot
        let dominated = if let Some(existing) = self.slot_claims.get(&claim.slot) {
            claim_has_priority(&claim, existing)
        } else {
            true
        };

        if dominated {
            // Check if we lost our slot
            if self.our_slot == Some(claim.slot) && claim.claimer != self.our_pubkey {
                self.our_slot = None;
            }

            self.slot_claims.insert(claim.slot, claim);
            true
        } else {
            false
        }
    }

    /// Detect foreign swarm from heartbeat
    pub fn detect_foreign_swarm(&mut self, heartbeat: &SwarmMessage) -> bool {
        if let SwarmMessage::SwarmHeartbeat {
            vdf_tip,
            vdf_height,
            ..
        } = heartbeat
        {
            // If same height but different tip, it's a foreign swarm
            if *vdf_height == self.vdf_chain.height() {
                return *vdf_tip != self.tip_output();
            }

            // If different height, might be foreign or just out of sync
            // Need more info to determine
        }
        false
    }

    /// Evaluate merge with a candidate swarm
    pub fn evaluate_merge(&self, candidate: &SwarmMergeCandidate) -> MergeResult {
        let our_height = self.vdf_chain.height();
        let their_height = candidate.chain_links.last().map(|l| l.height).unwrap_or(0);

        // Check if same chain (same tip)
        if let Some(their_tip) = candidate.chain_links.last() {
            if their_tip.output == self.tip_output() {
                return MergeResult::SameSwarm;
            }
        }

        // Compare heights
        if our_height > their_height + REORG_THRESHOLD {
            return MergeResult::WeWon {
                our_height,
                their_height,
            };
        }

        if their_height > our_height + REORG_THRESHOLD {
            // Find which of our slot claims might be invalidated
            let claims_to_revalidate: Vec<u64> = self
                .slot_claims
                .iter()
                .filter(|(_, claim)| claim.vdf_height > their_height)
                .map(|(slot, _)| *slot)
                .collect();

            return MergeResult::TheyWon {
                our_height,
                their_height,
                claims_to_revalidate,
            };
        }

        // Close heights - use deterministic tiebreaker
        let our_tip = self.tip_output();
        let their_tip = candidate
            .chain_links
            .last()
            .map(|l| l.output)
            .unwrap_or([0u8; 32]);

        MergeResult::Tie {
            height: our_height.max(their_height),
            our_tip,
            their_tip,
            we_win: our_tip < their_tip, // Lower hash wins
        }
    }

    /// Execute merge - adopt foreign swarm's chain
    pub fn execute_merge(&mut self, candidate: SwarmMergeCandidate) -> bool {
        // Verify and adopt their chain
        if let Some(new_chain) =
            VdfChain::from_links(self.genesis_seed, candidate.chain_links, self.our_pubkey)
        {
            self.vdf_chain = new_chain;

            // Re-evaluate our slot claim
            if let Some(our_slot) = self.our_slot {
                // Check if our claim is still valid on new chain
                if let Some(our_claim) = self.slot_claims.get(&our_slot).cloned() {
                    if our_claim.vdf_height > self.vdf_chain.height() {
                        // Our claim was at a height that doesn't exist anymore
                        self.our_slot = None;
                        self.slot_claims.remove(&our_slot);
                    }
                }
            }

            // Import their slot claims (those compatible with new chain)
            for (slot, claim) in candidate.slot_claims {
                if claim.vdf_height <= self.vdf_chain.height() {
                    // Verify against our new chain
                    if let Some(link) = self.vdf_chain.all_links().get(claim.vdf_height as usize) {
                        if link.output == claim.vdf_output {
                            // Claim is valid on our chain
                            self.process_slot_claim(claim);
                        }
                    }
                }
            }

            true
        } else {
            false
        }
    }

    /// Record peer as part of our swarm
    pub fn record_swarm_peer(&mut self, peer: [u8; 32], height: u64) {
        self.swarm_peers.insert(peer, height);
    }

    /// Get swarm size estimate
    pub fn swarm_size(&self) -> usize {
        self.swarm_peers.len() + 1 // +1 for ourselves
    }

    /// Generate heartbeat message
    pub fn heartbeat(&self) -> SwarmMessage {
        SwarmMessage::SwarmHeartbeat {
            sender: self.our_pubkey,
            vdf_height: self.vdf_chain.height(),
            vdf_tip: self.tip_output(),
            slot_count: self.slot_claims.len(),
        }
    }

    /// Get chain links for syncing
    pub fn chain_links(&self) -> &[VdfLink] {
        self.vdf_chain.all_links()
    }

    /// Get chain links from a specific height
    pub fn chain_links_from(&self, height: u64) -> &[VdfLink] {
        self.vdf_chain.links_from(height)
    }

    /// Get all slot claims
    pub fn slot_claims(&self) -> &HashMap<u64, AnchoredSlotClaim> {
        &self.slot_claims
    }

    /// Find next available slot
    pub fn next_available_slot(&self) -> u64 {
        let mut slot = 0u64;
        while self.slot_claims.contains_key(&slot) {
            slot += 1;
        }
        slot
    }
}

/// Extension trait for AnchoredSlotClaim to verify signature without full chain
trait SlotClaimExt {
    fn verify_signature(&self) -> bool;
}

impl SlotClaimExt for AnchoredSlotClaim {
    fn verify_signature(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = match VerifyingKey::from_bytes(&self.claimer) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&self.slot.to_le_bytes());
        msg.extend_from_slice(&self.vdf_height.to_le_bytes());
        msg.extend_from_slice(&self.vdf_output);

        verifying_key.verify(&msg, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_swarm_genesis() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let swarm = SwarmState::new_genesis(genesis_seed, signing_key);

        assert_eq!(swarm.height(), 0);
        assert!(swarm.our_slot().is_none());
        assert_eq!(swarm.active_slot_count(), 0);

        // Genesis mode - anyone can compute
        assert_eq!(swarm.vdf_duty(), VdfDuty::Genesis);
    }

    #[test]
    fn test_vdf_duty_rotation() {
        let genesis_seed = [42u8; 32];
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let key3 = SigningKey::generate(&mut OsRng);

        // Create genesis swarm
        let mut swarm1 = SwarmState::new_genesis(genesis_seed, key1.clone());

        // Claim slot 0
        let claim0 = swarm1.claim_slot(0);

        // Now check duty
        match swarm1.vdf_duty() {
            VdfDuty::OurTurn => println!("Swarm1 has VDF duty"),
            _ => panic!("Should be our turn with only our slot"),
        }

        // Compute VDF
        let link1 = swarm1.compute_vdf_step().expect("Should compute");
        assert_eq!(link1.height, 1);

        // Add more nodes
        let chain = swarm1.chain_links().to_vec();
        let mut swarm2 =
            SwarmState::join_swarm(genesis_seed, key2.clone(), chain.clone()).expect("Should join");
        let mut swarm3 =
            SwarmState::join_swarm(genesis_seed, key3.clone(), chain).expect("Should join");

        // They claim slots 1 and 2
        let claim1 = swarm2.claim_slot(1);
        let claim2 = swarm3.claim_slot(2);

        // Propagate claims
        swarm1.process_slot_claim(claim1.clone());
        swarm1.process_slot_claim(claim2.clone());
        swarm2.process_slot_claim(claim0.clone());
        swarm2.process_slot_claim(claim2.clone());
        swarm3.process_slot_claim(claim0);
        swarm3.process_slot_claim(claim1);

        // Check duty rotation at height 1
        // height 1 % 3 slots = slot 1 = swarm2's turn
        println!(
            "Swarm1 duty at height {}: {:?}",
            swarm1.height(),
            swarm1.vdf_duty()
        );
        println!(
            "Swarm2 duty at height {}: {:?}",
            swarm2.height(),
            swarm2.vdf_duty()
        );
        println!(
            "Swarm3 duty at height {}: {:?}",
            swarm3.height(),
            swarm3.vdf_duty()
        );
    }

    #[test]
    fn test_cooperative_vdf_advancement() {
        let genesis_seed = [42u8; 32];

        // Create 5 nodes
        let keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();

        // Genesis swarm
        let mut swarms: Vec<SwarmState> =
            vec![SwarmState::new_genesis(genesis_seed, keys[0].clone())];

        // Claim slot 0
        let claim0 = swarms[0].claim_slot(0);

        // Other nodes join
        for key in keys.iter().skip(1) {
            let chain = swarms[0].chain_links().to_vec();
            let swarm =
                SwarmState::join_swarm(genesis_seed, key.clone(), chain).expect("Should join");
            swarms.push(swarm);
        }

        // Propagate claim0
        for swarm in swarms.iter_mut().skip(1) {
            swarm.process_slot_claim(claim0.clone());
        }

        // Each node claims a slot
        let claims: Vec<AnchoredSlotClaim> =
            (1..5).map(|i| swarms[i].claim_slot(i as u64)).collect();

        // Propagate all claims
        for claim in &claims {
            for swarm in &mut swarms {
                swarm.process_slot_claim(claim.clone());
            }
        }

        // Now cooperatively advance VDF 20 times
        let start = std::time::Instant::now();

        for _ in 0..20 {
            // Find who has duty
            let current_height = swarms[0].height();
            let duty_slot = (current_height as usize) % 5;

            // That swarm computes
            let link = swarms[duty_slot]
                .compute_vdf_step()
                .expect("Duty holder should compute");

            // Broadcast to all
            for (i, swarm) in swarms.iter_mut().enumerate() {
                if i != duty_slot {
                    assert!(
                        swarm.process_vdf_link(link.clone()),
                        "Swarm {} should accept link",
                        i
                    );
                }
            }
        }

        let elapsed = start.elapsed();

        // All swarms should be at height 20
        for (i, swarm) in swarms.iter().enumerate() {
            assert_eq!(swarm.height(), 20, "Swarm {} should be at height 20", i);
        }

        println!(
            "5 nodes cooperatively computed 20 VDF steps in {:?}",
            elapsed
        );
        println!("Average: {:?} per step", elapsed / 20);
    }

    #[test]
    fn test_swarm_merge_taller_wins() {
        let genesis_seed = [42u8; 32];

        println!("\n=== Swarm Merge: Taller Chain Wins ===\n");

        // Swarm A: 3 nodes
        let keys_a: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let mut swarm_a = SwarmState::new_genesis(genesis_seed, keys_a[0].clone());

        // Swarm A claims slots and advances chain
        swarm_a.claim_slot(0);
        for _ in 0..50 {
            swarm_a.compute_vdf_step();
        }

        // Swarm B: 2 nodes (started later, shorter chain)
        let keys_b: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let mut swarm_b = SwarmState::new_genesis(genesis_seed, keys_b[0].clone());

        swarm_b.claim_slot(0);
        for _ in 0..20 {
            swarm_b.compute_vdf_step();
        }

        println!("Swarm A height: {}", swarm_a.height());
        println!("Swarm B height: {}", swarm_b.height());

        // B discovers A
        let candidate = SwarmMergeCandidate {
            chain_links: swarm_a.chain_links().to_vec(),
            slot_claims: swarm_a.slot_claims().clone(),
            discovered_at: Instant::now(),
            source_peer: swarm_a.our_pubkey(),
        };

        // B evaluates merge
        let result = swarm_b.evaluate_merge(&candidate);

        println!("Merge result: {:?}", result);

        match result {
            MergeResult::TheyWon {
                our_height,
                their_height,
                ..
            } => {
                assert_eq!(our_height, 20);
                assert_eq!(their_height, 50);

                // Execute merge
                assert!(swarm_b.execute_merge(candidate));
                assert_eq!(swarm_b.height(), 50);

                println!("B adopted A's chain, new height: {}", swarm_b.height());
            }
            _ => panic!("Expected TheyWon result"),
        }

        println!("\n=== Swarm Merge PASSED ===\n");
    }

    #[test]
    fn test_swarm_merge_tie_deterministic() {
        let genesis_seed = [42u8; 32];

        println!("\n=== Swarm Merge: Deterministic Tie ===\n");

        // Two swarms with same height but different chains
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        let mut swarm_a = SwarmState::new_genesis(genesis_seed, key_a);
        let mut swarm_b = SwarmState::new_genesis(genesis_seed, key_b);

        // Both advance to same height
        swarm_a.claim_slot(0);
        swarm_b.claim_slot(0);

        for _ in 0..15 {
            swarm_a.compute_vdf_step();
            swarm_b.compute_vdf_step();
        }

        // Within REORG_THRESHOLD, so heights count as "tied"
        assert_eq!(swarm_a.height(), swarm_b.height());

        // Different tips (different producers)
        assert_ne!(swarm_a.tip_output(), swarm_b.tip_output());

        println!("Both at height: {}", swarm_a.height());
        println!("A tip: {}", hex::encode(swarm_a.tip_output()));
        println!("B tip: {}", hex::encode(swarm_b.tip_output()));

        // A evaluates B
        let candidate_b = SwarmMergeCandidate {
            chain_links: swarm_b.chain_links().to_vec(),
            slot_claims: swarm_b.slot_claims().clone(),
            discovered_at: Instant::now(),
            source_peer: swarm_b.our_pubkey(),
        };

        let result_a = swarm_a.evaluate_merge(&candidate_b);

        // B evaluates A
        let candidate_a = SwarmMergeCandidate {
            chain_links: swarm_a.chain_links().to_vec(),
            slot_claims: swarm_a.slot_claims().clone(),
            discovered_at: Instant::now(),
            source_peer: swarm_a.our_pubkey(),
        };

        let result_b = swarm_b.evaluate_merge(&candidate_a);

        println!("A's evaluation: {:?}", result_a);
        println!("B's evaluation: {:?}", result_b);

        // Verify deterministic - exactly one should win
        match (&result_a, &result_b) {
            (MergeResult::Tie { we_win: a_wins, .. }, MergeResult::Tie { we_win: b_wins, .. }) => {
                assert_ne!(a_wins, b_wins, "Exactly one should win");
                println!("A thinks they win: {}", a_wins);
                println!("B thinks they win: {}", b_wins);
            }
            _ => panic!("Both should be Tie results"),
        }

        println!("\n=== Deterministic Tie PASSED ===\n");
    }

    #[test]
    fn test_50_nodes_swarm_formation() {
        let genesis_seed = [42u8; 32];

        println!("\n=== 50 Node Swarm Formation ===\n");

        // Create 50 nodes
        let keys: Vec<SigningKey> = (0..50).map(|_| SigningKey::generate(&mut OsRng)).collect();

        // Genesis node
        let mut swarms: Vec<SwarmState> =
            vec![SwarmState::new_genesis(genesis_seed, keys[0].clone())];

        // Genesis claims slot 0
        let genesis_claim = swarms[0].claim_slot(0);

        // Advance genesis chain a bit
        for _ in 0..3 {
            swarms[0].compute_vdf_step();
        }

        let start = Instant::now();

        // Other 49 nodes join
        for (i, key) in keys.iter().enumerate().skip(1) {
            let chain = swarms[0].chain_links().to_vec();
            let mut swarm =
                SwarmState::join_swarm(genesis_seed, key.clone(), chain).expect("Should join");

            // Sync existing claims
            for (slot, claim) in swarms[0].slot_claims() {
                swarm.process_slot_claim(claim.clone());
            }

            // Claim next available slot
            let slot = swarm.next_available_slot();
            let claim = swarm.claim_slot(slot);

            // Broadcast to all existing nodes
            for other in &mut swarms {
                other.process_slot_claim(claim.clone());
            }

            swarms.push(swarm);

            // Cooperatively advance VDF periodically
            if i % 10 == 0 {
                // Find duty holder
                let height = swarms[0].height();
                let active_slots = swarms[0].active_slot_count();
                if active_slots > 0 {
                    let duty_slot = (height as usize) % active_slots;
                    if duty_slot < swarms.len() {
                        if let Some(link) = swarms[duty_slot].compute_vdf_step() {
                            // Broadcast to all
                            for (j, swarm) in swarms.iter_mut().enumerate() {
                                if j != duty_slot {
                                    swarm.process_vdf_link(link.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let formation_time = start.elapsed();

        // Verify all 50 nodes have unique slots
        let mut claimed_slots: HashSet<u64> = HashSet::new();
        for (i, swarm) in swarms.iter().enumerate() {
            if let Some(slot) = swarm.our_slot() {
                assert!(
                    claimed_slots.insert(slot),
                    "Duplicate slot {} at node {}",
                    slot,
                    i
                );
            }
        }

        assert_eq!(claimed_slots.len(), 50, "All 50 nodes should have slots");

        // Verify slots are contiguous 0..50
        for slot in 0..50 {
            assert!(claimed_slots.contains(&slot), "Missing slot {}", slot);
        }

        println!("Formation time: {:?}", formation_time);
        println!("Final chain height: {}", swarms[0].height());
        println!("All 50 nodes claimed unique slots 0-49");

        println!("\n=== 50 Node Swarm Formation PASSED ===\n");
    }
}
