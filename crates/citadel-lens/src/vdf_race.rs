//! VDF Race - Collaborative Verifiable Delay Function for Swarm Consensus
//!
//! # THE KEY INSIGHT
//!
//! ```text
//! LONGEST CHAIN = LARGEST SWARM
//!
//! Swarm A (30 nodes):              Swarm B (20 nodes):
//! [v0]─►[v1]─►[v2]─►...─►[v1000]   [v0]─►[v1]─►...─►[v600]
//!  │     │     │                     │     │
//!  n1    n2    n3  (round-robin)     n1    n2
//!
//! More nodes taking turns = faster VDF growth = longer chain
//! Longest chain is canonical. Period.
//! ```
//!
//! # Protocol Phases
//!
//! 1. **Bootstrap**: First node starts VDF chain from genesis
//! 2. **Growth**: Nodes take turns extending chain (round-robin by slot)
//! 3. **Merge**: Compare chain lengths, longer wins, shorter re-joins
//! 4. **Steady State**: TG-BFT takes over for ongoing consensus
//!
//! # Why This Works
//!
//! - VDF is inherently sequential (can't parallelize)
//! - More nodes = more turns = faster chain growth
//! - Chain length proves swarm size AND age
//! - No coordination needed - just extend and broadcast
//! - Split-brain resolution is deterministic: longest chain wins

use serde::{Deserialize, Serialize};

/// VDF difficulty - number of sequential hash iterations per step
/// Higher = more delay, more security against grinding
/// 100_000 iterations ≈ 10-50ms on modern hardware
pub const VDF_ITERATIONS: u32 = 100_000;

/// Minimum VDF height difference to trigger re-org
/// Prevents oscillation on small differences
pub const REORG_THRESHOLD: u64 = 10;

/// A single VDF chain link
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VdfLink {
    /// Chain height (0 = genesis)
    pub height: u64,
    /// VDF output hash (result of sequential computation)
    pub output: [u8; 32],
    /// Public key of node that computed this link
    pub producer: [u8; 32],
    /// Previous link's output (for verification)
    pub previous: [u8; 32],
    /// Timestamp (informational, not trusted)
    pub timestamp_ms: u64,
}

impl VdfLink {
    /// Create genesis link (height 0)
    pub fn genesis(seed: &[u8], producer: [u8; 32]) -> Self {
        let output = compute_vdf(seed, VDF_ITERATIONS);
        Self {
            height: 0,
            output,
            producer,
            previous: [0u8; 32], // Genesis has no previous
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Extend chain with new link
    pub fn extend(&self, producer: [u8; 32]) -> Self {
        // Input to VDF: previous output || producer pubkey
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.output);
        input.extend_from_slice(&producer);

        let output = compute_vdf(&input, VDF_ITERATIONS);

        Self {
            height: self.height + 1,
            output,
            producer,
            previous: self.output,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Verify this link is valid extension of previous
    pub fn verify(&self, previous_output: &[u8; 32]) -> bool {
        if self.height == 0 {
            // Genesis verification needs the seed
            return true; // Caller must verify genesis separately
        }

        // Check previous matches
        if &self.previous != previous_output {
            return false;
        }

        // Recompute VDF and check output
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(previous_output);
        input.extend_from_slice(&self.producer);

        let expected = compute_vdf(&input, VDF_ITERATIONS);
        self.output == expected
    }
}

/// Compute VDF: iterated BLAKE3 hashing
/// This is a simplified VDF - production would use Wesolowski or Pietrzak
fn compute_vdf(seed: &[u8], iterations: u32) -> [u8; 32] {
    let mut state = blake3::hash(seed);

    for _ in 0..iterations {
        state = blake3::hash(state.as_bytes());
    }

    *state.as_bytes()
}

/// VDF Chain - the collaborative timechain
#[derive(Clone, Debug)]
pub struct VdfChain {
    /// Genesis seed (shared across all nodes)
    genesis_seed: [u8; 32],
    /// Chain links (index = height)
    links: Vec<VdfLink>,
    /// Our public key for producing links
    our_pubkey: [u8; 32],
}

impl VdfChain {
    /// Create new chain (we are genesis producer)
    pub fn new_genesis(genesis_seed: [u8; 32], our_pubkey: [u8; 32]) -> Self {
        let genesis = VdfLink::genesis(&genesis_seed, our_pubkey);
        Self {
            genesis_seed,
            links: vec![genesis],
            our_pubkey,
        }
    }

    /// Create chain from received links (joining existing swarm)
    pub fn from_links(genesis_seed: [u8; 32], links: Vec<VdfLink>, our_pubkey: [u8; 32]) -> Option<Self> {
        if links.is_empty() {
            return None;
        }

        // Verify chain integrity
        let chain = Self {
            genesis_seed,
            links,
            our_pubkey,
        };

        if chain.verify_full() {
            Some(chain)
        } else {
            None
        }
    }

    /// Current chain height
    pub fn height(&self) -> u64 {
        self.links.last().map(|l| l.height).unwrap_or(0)
    }

    /// Get tip (latest link)
    pub fn tip(&self) -> Option<&VdfLink> {
        self.links.last()
    }

    /// Extend chain (we produce next link)
    pub fn extend(&mut self) -> &VdfLink {
        let tip = self.links.last().expect("Chain must have genesis");
        let new_link = tip.extend(self.our_pubkey);
        self.links.push(new_link);
        self.links.last().unwrap()
    }

    /// Try to adopt a longer chain
    /// Returns true if we switched to the new chain
    pub fn try_adopt(&mut self, other_links: Vec<VdfLink>) -> bool {
        if other_links.is_empty() {
            return false;
        }

        let other_height = other_links.last().map(|l| l.height).unwrap_or(0);
        let our_height = self.height();

        // Only adopt if significantly longer (prevents oscillation)
        if other_height <= our_height + REORG_THRESHOLD {
            return false;
        }

        // Verify the other chain
        let temp_chain = VdfChain {
            genesis_seed: self.genesis_seed,
            links: other_links.clone(),
            our_pubkey: self.our_pubkey,
        };

        if !temp_chain.verify_full() {
            return false;
        }

        // Adopt the longer chain
        self.links = other_links;
        true
    }

    /// Verify entire chain from genesis
    pub fn verify_full(&self) -> bool {
        if self.links.is_empty() {
            return false;
        }

        // Verify genesis
        let genesis = &self.links[0];
        if genesis.height != 0 {
            return false;
        }

        let expected_genesis_output = compute_vdf(&self.genesis_seed, VDF_ITERATIONS);
        if genesis.output != expected_genesis_output {
            return false;
        }

        // Verify each subsequent link
        for i in 1..self.links.len() {
            let prev = &self.links[i - 1];
            let curr = &self.links[i];

            if curr.height != prev.height + 1 {
                return false;
            }

            if !curr.verify(&prev.output) {
                return false;
            }
        }

        true
    }

    /// Get all links for syncing to another node
    pub fn all_links(&self) -> &[VdfLink] {
        &self.links
    }

    /// Get links from a specific height (for incremental sync)
    pub fn links_from(&self, height: u64) -> &[VdfLink] {
        let start = height as usize;
        if start >= self.links.len() {
            &[]
        } else {
            &self.links[start..]
        }
    }
}

/// Slot claim anchored to VDF height
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchoredSlotClaim {
    /// SPIRAL slot index
    pub slot: u64,
    /// Claimer's public key
    pub claimer: [u8; 32],
    /// VDF height when claim was made
    pub vdf_height: u64,
    /// VDF output at that height (for verification)
    pub vdf_output: [u8; 32],
    /// Signature over (slot || vdf_height || vdf_output)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

pub mod signature_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as hex string
        hex::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl AnchoredSlotClaim {
    /// Create a new anchored claim
    pub fn new(
        slot: u64,
        claimer: [u8; 32],
        vdf_tip: &VdfLink,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;

        // Create message to sign
        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&slot.to_le_bytes());
        msg.extend_from_slice(&vdf_tip.height.to_le_bytes());
        msg.extend_from_slice(&vdf_tip.output);

        let signature = signing_key.sign(&msg);

        Self {
            slot,
            claimer,
            vdf_height: vdf_tip.height,
            vdf_output: vdf_tip.output,
            signature: signature.to_bytes(),
        }
    }

    /// Verify claim signature and VDF anchor
    pub fn verify(&self, chain: &VdfChain) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Check VDF height exists in chain
        if self.vdf_height as usize >= chain.links.len() {
            return false;
        }

        // Check VDF output matches
        let link = &chain.links[self.vdf_height as usize];
        if link.output != self.vdf_output {
            return false;
        }

        // Verify signature
        let verifying_key = match VerifyingKey::from_bytes(&self.claimer) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Signature::from_bytes returns Signature directly (infallible)
        let signature = Signature::from_bytes(&self.signature);

        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&self.slot.to_le_bytes());
        msg.extend_from_slice(&self.vdf_height.to_le_bytes());
        msg.extend_from_slice(&self.vdf_output);

        verifying_key.verify(&msg, &signature).is_ok()
    }
}

/// Compare two claims - returns true if claim_a has priority over claim_b
/// Priority order (proven in Lean VdfRace.lean):
/// 1. Lower VDF height wins (earlier claim)
/// 2. Same height: lower claimer ID wins
/// 3. Same claimer: lower slot wins
/// 4. Same slot: lower vdf_output wins (final deterministic tiebreaker)
pub fn claim_has_priority(claim_a: &AnchoredSlotClaim, claim_b: &AnchoredSlotClaim) -> bool {
    // Earlier VDF height = earlier claim = higher priority
    if claim_a.vdf_height != claim_b.vdf_height {
        return claim_a.vdf_height < claim_b.vdf_height;
    }

    // Same height: lexicographic comparison of claimer pubkey
    if claim_a.claimer != claim_b.claimer {
        return claim_a.claimer < claim_b.claimer;
    }

    // Same claimer: lower slot wins
    if claim_a.slot != claim_b.slot {
        return claim_a.slot < claim_b.slot;
    }

    // Final tiebreaker: lower vdf_output (shouldn't happen in well-formed protocol)
    claim_a.vdf_output < claim_b.vdf_output
}

/// VDF Race state machine for a node
#[derive(Debug)]
pub struct VdfRace {
    /// Our VDF chain
    chain: VdfChain,
    /// Our signing key
    signing_key: ed25519_dalek::SigningKey,
    /// Pending slot claims (slot -> best claim we've seen)
    pending_claims: std::collections::HashMap<u64, AnchoredSlotClaim>,
    /// Our claimed slot (if any)
    our_slot: Option<u64>,
    /// Is this the bootstrap phase? (VDF race active)
    bootstrap_phase: bool,
}

impl VdfRace {
    /// Create new VDF race (genesis node)
    pub fn new_genesis(genesis_seed: [u8; 32], signing_key: ed25519_dalek::SigningKey) -> Self {
        let pubkey = signing_key.verifying_key().to_bytes();
        let chain = VdfChain::new_genesis(genesis_seed, pubkey);

        Self {
            chain,
            signing_key,
            pending_claims: std::collections::HashMap::new(),
            our_slot: None,
            bootstrap_phase: true,
        }
    }

    /// Join existing swarm with their chain
    pub fn join(
        genesis_seed: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
        existing_chain: Vec<VdfLink>,
    ) -> Option<Self> {
        let pubkey = signing_key.verifying_key().to_bytes();
        let chain = VdfChain::from_links(genesis_seed, existing_chain, pubkey)?;

        Some(Self {
            chain,
            signing_key,
            pending_claims: std::collections::HashMap::new(),
            our_slot: None,
            bootstrap_phase: true,
        })
    }

    /// Get current chain height
    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// Extend the VDF chain (we compute next link)
    pub fn extend_chain(&mut self) -> VdfLink {
        self.chain.extend().clone()
    }

    /// Try to adopt a longer chain from another node
    pub fn try_adopt_chain(&mut self, other_links: Vec<VdfLink>) -> bool {
        self.chain.try_adopt(other_links)
    }

    /// Claim a slot, anchored to current VDF height
    pub fn claim_slot(&mut self, slot: u64) -> AnchoredSlotClaim {
        let tip = self.chain.tip().expect("Chain must exist");
        let pubkey = self.signing_key.verifying_key().to_bytes();

        let claim = AnchoredSlotClaim::new(slot, pubkey, tip, &self.signing_key);

        // Record as our claim
        self.our_slot = Some(slot);
        self.pending_claims.insert(slot, claim.clone());

        claim
    }

    /// Process incoming claim - returns true if this claim wins
    pub fn process_claim(&mut self, claim: AnchoredSlotClaim) -> bool {
        // Verify the claim
        if !claim.verify(&self.chain) {
            return false;
        }

        let dominated = if let Some(existing) = self.pending_claims.get(&claim.slot) {
            // Compare with existing claim for this slot
            claim_has_priority(&claim, existing)
        } else {
            true // No existing claim, this one wins
        };

        if dominated {
            // Check if we lost our slot
            if self.our_slot == Some(claim.slot) {
                let our_pubkey = self.signing_key.verifying_key().to_bytes();
                if claim.claimer != our_pubkey {
                    // We lost! Need to reclaim a different slot
                    self.our_slot = None;
                }
            }

            self.pending_claims.insert(claim.slot, claim);
            true
        } else {
            false
        }
    }

    /// Get the winning claim for a slot
    pub fn get_claim(&self, slot: u64) -> Option<&AnchoredSlotClaim> {
        self.pending_claims.get(&slot)
    }

    /// Find next available slot (not claimed by anyone with priority)
    pub fn next_available_slot(&self) -> u64 {
        let mut slot = 0u64;
        while self.pending_claims.contains_key(&slot) {
            slot += 1;
        }
        slot
    }

    /// Check if we still have our slot
    pub fn our_slot(&self) -> Option<u64> {
        self.our_slot
    }

    /// Get chain for syncing to other nodes
    pub fn chain_links(&self) -> &[VdfLink] {
        self.chain.all_links()
    }

    /// Exit bootstrap phase (switch to TG-BFT)
    pub fn exit_bootstrap(&mut self) {
        self.bootstrap_phase = false;
    }

    /// Are we still in bootstrap phase?
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap_phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::time::Instant;

    #[test]
    fn test_vdf_computation() {
        let seed = b"test seed for vdf";
        let start = Instant::now();
        let output = compute_vdf(seed, VDF_ITERATIONS);
        let elapsed = start.elapsed();

        println!("VDF computation: {} iterations in {:?}", VDF_ITERATIONS, elapsed);
        println!("Output: {}", hex::encode(output));

        // Verify deterministic
        let output2 = compute_vdf(seed, VDF_ITERATIONS);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_vdf_chain_genesis() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();

        let chain = VdfChain::new_genesis(genesis_seed, pubkey);

        assert_eq!(chain.height(), 0);
        assert!(chain.verify_full());

        println!("Genesis link: {:?}", chain.tip());
    }

    #[test]
    fn test_vdf_chain_extension() {
        let genesis_seed = [42u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();

        let mut chain = VdfChain::new_genesis(genesis_seed, pubkey);

        // Extend 5 times
        for i in 1..=5 {
            let start = Instant::now();
            chain.extend();
            let elapsed = start.elapsed();
            println!("Link {} computed in {:?}", i, elapsed);
        }

        assert_eq!(chain.height(), 5);
        assert!(chain.verify_full());
    }

    #[test]
    fn test_vdf_chain_adoption() {
        let genesis_seed = [42u8; 32];

        // Node A starts chain
        let key_a = SigningKey::generate(&mut OsRng);
        let mut chain_a = VdfChain::new_genesis(genesis_seed, key_a.verifying_key().to_bytes());

        // Extend A's chain
        for _ in 0..20 {
            chain_a.extend();
        }

        // Node B starts its own chain (simulating partition)
        let key_b = SigningKey::generate(&mut OsRng);
        let mut chain_b = VdfChain::new_genesis(genesis_seed, key_b.verifying_key().to_bytes());

        // B's chain is shorter
        for _ in 0..5 {
            chain_b.extend();
        }

        println!("Chain A height: {}", chain_a.height());
        println!("Chain B height: {}", chain_b.height());

        // B tries to adopt A's chain
        let adopted = chain_b.try_adopt(chain_a.all_links().to_vec());

        assert!(adopted, "B should adopt A's longer chain");
        assert_eq!(chain_b.height(), chain_a.height());
    }

    #[test]
    fn test_anchored_slot_claims() {
        let genesis_seed = [42u8; 32];

        // Two nodes racing for same slot
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        // Shared chain
        let mut chain = VdfChain::new_genesis(genesis_seed, key_a.verifying_key().to_bytes());
        chain.extend();
        chain.extend();

        // A claims slot 0 at height 2
        let claim_a = AnchoredSlotClaim::new(
            0,
            key_a.verifying_key().to_bytes(),
            chain.tip().unwrap(),
            &key_a,
        );

        // Extend chain
        chain.extend();
        chain.extend();

        // B claims slot 0 at height 4 (later)
        let claim_b = AnchoredSlotClaim::new(
            0,
            key_b.verifying_key().to_bytes(),
            chain.tip().unwrap(),
            &key_b,
        );

        // Verify both claims
        assert!(claim_a.verify(&chain));
        assert!(claim_b.verify(&chain));

        // A should have priority (earlier height)
        assert!(claim_has_priority(&claim_a, &claim_b));
        assert!(!claim_has_priority(&claim_b, &claim_a));

        println!("Claim A height: {}", claim_a.vdf_height);
        println!("Claim B height: {}", claim_b.vdf_height);
        println!("A has priority: {}", claim_has_priority(&claim_a, &claim_b));
    }

    #[cfg(feature = "heavy_tests")]
    #[test]
    fn test_vdf_race_heavy() {
        run_test_vdf_race_n_nodes(50);
    }
    #[cfg(not(feature = "heavy_tests"))]
    #[test]
    fn test_vdf_race_light() {
        run_test_vdf_race_n_nodes(10);
    }
    fn run_test_vdf_race_n_nodes(nodes: usize) {
        let genesis_seed = [42u8; 32];

        println!("\n=== VDF Race: {} Node Bootstrap ===\n", nodes);

        // Create 50 nodes with their signing keys
        let keys: Vec<SigningKey> = (0..nodes)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();

        // Genesis node starts race
        let mut races: Vec<VdfRace> = vec![
            VdfRace::new_genesis(genesis_seed, keys[0].clone())
        ];

        // Genesis claims slot 0
        let genesis_claim = races[0].claim_slot(0);
        println!("Genesis claims slot 0 at height {}", genesis_claim.vdf_height);

        // Extend chain a few times
        for _ in 0..3 {
            races[0].extend_chain();
        }

        // Other nodes join and claim slots
        for (i, key) in keys.iter().enumerate().skip(1) {
            // Join with current chain
            let chain_links = races[0].chain_links().to_vec();
            let mut race = VdfRace::join(genesis_seed, key.clone(), chain_links)
                .expect("Should join");

            // Sync existing claims to new node (simulates joining mesh and receiving state)
            for slot in 0..races[0].pending_claims.len() as u64 {
                if let Some(claim) = races[0].get_claim(slot) {
                    race.process_claim(claim.clone());
                }
            }

            // Find next available slot
            let slot = race.next_available_slot();

            // Claim it
            let claim = race.claim_slot(slot);

            // Broadcast to all other nodes
            for other in &mut races {
                other.process_claim(claim.clone());
            }

            races.push(race);

            // Periodically extend chain (simulating time passing)
            if i % 5 == 0 {
                let _link = races[0].extend_chain();
                // Sync chain to all nodes - clone links first to avoid borrow issues
                let chain_to_sync = races[0].chain_links().to_vec();
                for race in races.iter_mut().skip(1) {
                    race.try_adopt_chain(chain_to_sync.clone());
                }
            }
        }

        // Verify results
        println!("\nResults:");
        println!("  Chain height: {}", races[0].height());
        println!("  Total nodes: {}", races.len());

        // Check all slots are unique
        let mut claimed_slots: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for (i, race) in races.iter().enumerate() {
            if let Some(slot) = race.our_slot() {
                assert!(
                    claimed_slots.insert(slot),
                    "Duplicate slot {} claimed by node {}", slot, i
                );
            }
        }

        println!("  Unique slots claimed: {}", claimed_slots.len());
        assert_eq!(claimed_slots.len(), nodes, "All {} nodes should have unique slots", nodes);

        // Check slots are contiguous 0..50
        for slot in 0..nodes {
            assert!(claimed_slots.contains(&(slot as u64)), "Missing slot {}", slot);
        }

        println!("  ✓ All slots 0-49 claimed uniquely");
        println!("\n=== VDF Race Bootstrap PASSED ===\n");
    }

    #[cfg(feature = "heavy_tests")]
    #[test]
    fn test_split_brain_merge_heavy() {
        run_test_split_brain_merge(30, 100, 20, 60);
    } 
    #[cfg(not(feature = "heavy_tests"))]
    #[test]
    fn test_split_brain_merge_light() {
        run_test_split_brain_merge(30, 60, 10, 40);
    } 
    fn run_test_split_brain_merge(node_a_count: usize, a_ext_count: usize, node_b_count: usize, b_ext_count: usize) {
        assert!(node_a_count > node_b_count, "test parameter error: {:?} should be larger than {:?}", node_a_count, node_b_count);
        let genesis_seed = [42u8; 32];

        println!("\n=== Split Brain Merge Test ===\n");

        // Partition A: 30 nodes, longer chain
        let keys_a: Vec<SigningKey> = (0..node_a_count)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();

        let mut chain_a = VdfChain::new_genesis(genesis_seed, keys_a[0].verifying_key().to_bytes());

        // A extends chain 100 times (simulating 30 nodes taking turns)
        for i in 0..a_ext_count {
            // Round-robin producers
            let producer_idx = i % node_a_count;
            chain_a = VdfChain {
                genesis_seed,
                links: chain_a.links.clone(),
                our_pubkey: keys_a[producer_idx].verifying_key().to_bytes(),
            };
            chain_a.extend();
        }

        // Partition B:  shorter chain (started later or fewer nodes)
        let keys_b: Vec<SigningKey> = (0..node_b_count)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();

        let mut chain_b = VdfChain::new_genesis(genesis_seed, keys_b[0].verifying_key().to_bytes());

        // B extends its chain
        for i in 0..b_ext_count {
            let producer_idx = i % node_b_count;
            chain_b = VdfChain {
                genesis_seed,
                links: chain_b.links.clone(),
                our_pubkey: keys_b[producer_idx].verifying_key().to_bytes(),
            };
            chain_b.extend();
        }

        println!("Partition A: {} nodes, chain height {}", keys_a.len(), chain_a.height());
        println!("Partition B: {} nodes, chain height {}", keys_b.len(), chain_b.height());

        // Merge: B discovers A's longer chain
        let adopted = chain_b.try_adopt(chain_a.all_links().to_vec());

        assert!(adopted, "B should adopt A's longer chain");
        println!("\nAfter merge:");
        println!("  B adopted A's chain: {}", adopted);
        println!("  B's new height: {}", chain_b.height());

        // Verify chains are now identical
        assert_eq!(chain_a.height(), chain_b.height());

        println!("\n=== Split Brain Merge PASSED ===\n");
    }
}
