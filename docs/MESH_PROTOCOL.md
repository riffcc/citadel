# SPIRAL Mesh Protocol: Slot Assignment Specification

## The Question This Document Answers

**How does a node join the SPIRAL mesh and get assigned to a slot?**

This covers:
- Single node joining an existing network
- Race conditions (two nodes claiming same slot)
- Latency optimization (post-join slot swaps)
- Network merges (zipper merge of two swarms)

---

## Design Principles

1. **Joiner is DUMB, Entry node is SMART**
   - Joiner doesn't need the whole network map
   - Entry node has Common Knowledge (CK) of network state
   - Entry node computes slot assignment and broadcasts it
   - Joiner receives only: slot number + neighbor addresses

2. **TGP is the bilateral primitive**
   - Every slot assignment starts with a TGP handshake
   - QuadProof artifact is unique per handshake (unforgeable, unreplayable)
   - Race resolution uses this artifact for deterministic priority

3. **Threshold scales with network size**
   - Small networks: lower thresholds
   - Mature networks: 11/20 neighbors required
   - Security grows with the network

---

## Join Protocol

```
┌─────────────────────────────────────────────────────────────────┐
│                        JOIN PROTOCOL                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. HANDSHAKE: Joiner → Entry Node                              │
│     ├── TGP handshake (C → D → T → Q)                           │
│     └── Result: QuadProof (bilateral, unforgeable, unique)      │
│                                                                 │
│  2. COMPUTE: Entry Node (has CK)                                │
│     └── first_empty_slot() → slot X                             │
│                                                                 │
│  3. BROADCAST: Entry → Network                                  │
│     └── CANDIDATE(joiner_id, slot_X, QuadProof)                 │
│         Priority = hash(joiner_id XOR QuadProof.artifact)       │
│                                                                 │
│  4. INFORM: Entry → Joiner                                      │
│     └── "You're slot X, neighbors: [A, B, C, ...]"              │
│         (Just slot number + addresses. NOT the whole bitmap)    │
│                                                                 │
│  5. CONNECT: Joiner → Neighbors (parallel)                      │
│     └── TGP handshakes with each existing neighbor              │
│                                                                 │
│  6. THRESHOLD: Count successful connections                     │
│     └── If connections >= scaling_ladder(neighbor_count) → IN   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### What the Joiner Receives

```
SlotAssignment {
    slot: u64,                    // Your assigned slot number
    neighbors: Vec<NeighborInfo>, // At most 20 entries
}

NeighborInfo {
    peer_id: PeerId,              // Their identity
    address: SocketAddr,          // How to reach them
    slot: u64,                    // Their slot number
}
```

The joiner does NOT receive:
- Full mesh bitmap
- Other nodes' connections
- Historical data
- Anything beyond what's needed to establish connections

### What the Entry Node Does

1. **Maintains CK**: Knows which slots are occupied
2. **Computes assignment**: `first_empty_slot()` in SPIRAL enumeration order
3. **Broadcasts CANDIDATE**: Tells network "this joiner is claiming slot X"
4. **Sends info to joiner**: Just the slot + neighbor addresses

---

## Race Resolution

When two joiners target the same slot simultaneously:

```
┌─────────────────────────────────────────────────────────────────┐
│                      RACE RESOLUTION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Scenario: J1 and J2 both want slot X                           │
│                                                                 │
│  Entry_A (serving J1):                                          │
│    └── CANDIDATE(J1, slot_X, QuadProof_J1A)                     │
│                                                                 │
│  Entry_B (serving J2):                                          │
│    └── CANDIDATE(J2, slot_X, QuadProof_J2B)                     │
│                                                                 │
│  Network computes (deterministically, no coordination):         │
│    priority_J1 = hash(J1.id XOR QuadProof_J1A.artifact)         │
│    priority_J2 = hash(J2.id XOR QuadProof_J2B.artifact)         │
│                                                                 │
│  Resolution:                                                    │
│    └── LOWER priority WINS                                      │
│                                                                 │
│  Outcome:                                                       │
│    ├── Winner's neighbors accept their TGP handshakes           │
│    ├── Loser's neighbors reject (slot already filling)          │
│    └── Loser's entry node reassigns to slot X+1                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why This Works

1. **QuadProof is unique per handshake**: Different entry nodes produce different artifacts
2. **Hash is deterministic**: All nodes compute the same priority
3. **No coordination needed**: Each node independently reaches the same conclusion
4. **No timestamps**: Arrival order doesn't matter, only hash value
5. **Ungameable**: Joiner can't predict which entry node they'll use or what the artifact will be

---

## Scaling Ladder

The threshold for slot occupancy scales with neighbor availability:

```
┌──────────────┬───────────┬─────────────────────────────────────┐
│ Neighbors    │ Threshold │ Notes                               │
├──────────────┼───────────┼─────────────────────────────────────┤
│ 1            │ 1         │ Genesis / early network             │
│ 2            │ 2         │ Both must agree                     │
│ 3            │ 2         │ 2/3 majority                        │
│ 4            │ 3         │ BFT emergence                       │
│ 5-6          │ 4         │ Growing BFT                         │
│ 7-9          │ 5         │ Approaching 2/3                     │
│ 10-14        │ 7         │ 2/3 + 1                             │
│ 15-19        │ 9         │ Approaching 11/20                   │
│ 20           │ 11        │ Full SPIRAL: 11/20                  │
└──────────────┴───────────┴─────────────────────────────────────┘

Formula: threshold(n) = ceil(n * 11/20) for n >= 3, else n
```

---

## Latency Trump (Post-Join Optimization)

Once in a slot, a node can only move by finding a **mutual benefit swap**:

```
┌─────────────────────────────────────────────────────────────────┐
│                       LATENCY TRUMP                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Node A at slot X, Node B at slot Y                             │
│                                                                 │
│  Current state:                                                 │
│    A's latency to X's neighbors = L_A                           │
│    B's latency to Y's neighbors = L_B                           │
│                                                                 │
│  If swapped:                                                    │
│    A's latency to Y's neighbors = L_A'                          │
│    B's latency to X's neighbors = L_B'                          │
│                                                                 │
│  TRUMP condition (BOTH must improve):                           │
│    L_A' < L_A  AND  L_B' < L_B                                  │
│                                                                 │
│  Protocol:                                                      │
│    1. A proposes swap to B with latency measurements            │
│    2. B independently verifies mutual benefit                   │
│    3. If verified: TGP-proven atomic slot exchange              │
│    4. Both update their neighbor connections                    │
│                                                                 │
│  Atomicity via TGP:                                             │
│    └── Either BOTH swap or NEITHER does                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Swap Execution

When a trump is agreed:

1. **Swap slot assignments**: A gets Y, B gets X
2. **Swap neighbor relationships**: A now neighbors Y's neighbors, B now neighbors X's neighbors
3. **Cities (physical locations) don't change**: The machines stay where they are
4. **TGP proves bilateral agreement**: QuadProof of the swap intent

---

## Zipper Merge (Two Swarms Become One)

When two isolated networks reconnect:

```
┌─────────────────────────────────────────────────────────────────┐
│                       ZIPPER MERGE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. DISCOVERY: Two swarms discover each other                   │
│     └── Via gossip, bootstrap, or direct connection             │
│                                                                 │
│  2. CHAIN WEIGHT COMPARISON:                                    │
│     ├── Each swarm has a CVDF chain                             │
│     ├── Chain weight = Σ(1 + attestation_count) per round       │
│     └── HEAVIER chain wins (not height, WEIGHT)                 │
│                                                                 │
│  3. WINNER keeps their slot assignments                         │
│     └── Their topology is the canonical one                     │
│                                                                 │
│  4. CONCEDING swarm releases their slots                        │
│     └── Nodes no longer claim their old positions               │
│                                                                 │
│  5. REINSERT: Conceding nodes rejoin via normal JOIN            │
│     └── They fill empty slots in winner's topology              │
│                                                                 │
│  Example:                                                       │
│    Winner slots:    [1, 2, 4, 5, 6, 9, 12]     (gaps: 3,7,8,10,11)│
│    Conceding nodes: [1, 2, 3, 4, 5, 8]         (6 nodes)        │
│    After merge:     [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Why Chain Weight Determines Winner

From `CitadelProofs/CVDF.lean` and `CONSTITUTIONAL_P2P.md`:

**It's NOT just "more attesters wins"** - that would be Sybil-vulnerable.

Chain weight is **diffusion-capped**:

```
effective_contribution = min(your_compute, diffusion_cap(latency_diversity))
```

**Proof of Diffusion (PoD)** bounds contribution by geographic distribution:

| Attack Strategy | Why It Fails |
|-----------------|--------------|
| 1000 nodes in one datacenter | Low latency diversity → capped → honest network outweighs |
| VMs across cloud regions | Cloud patterns detectable, paying $$ for what honest nodes get free |
| Nation-state infrastructure | Still can't be in more places than actual distributed userbase |

**The Attacker's Dilemma**:
- Concentration is cheap but useless (capped by diffusion)
- Diffusion is expensive and can't exceed organic distribution

**The Defender's Advantage**:
- Being a normal user IS maximum diffusion efficiency
- Just existing in your house contributes optimally

So a legitimate 50-node swarm with global distribution beats a Sybil 500-node swarm in one datacenter because:
1. Sybil swarm has low latency diversity
2. PoD caps their effective weight
3. Distributed swarm's attestations count fully

---

## Security: Attack Resistance

### The Four Resistances

| Resistance | Attack | Defense |
|------------|--------|---------|
| **Sybil** | Spin up 1000 fake nodes | PoD caps contribution by latency diversity |
| **Takeover** | 51% of nodes | Need 51% of FOUR orthogonal dimensions (VDF × BFT × PoL × PoD) |
| **Eclipse** | Isolate victim, feed lies | Victim can locally detect: "chain too light for network age" |
| **Grind** | Brute-force VDF | PoD caps you anyway; difficulty ramps against attackers |

### Nash Equilibrium Inversion

From `CitadelProofs/CVDF.lean`:

```
Traditional PoW: Nash equilibrium = MAXIMUM waste (everyone competes)
SPIRAL:          Nash equilibrium = MINIMUM difficulty (everyone cooperates)
```

**Difficulty adjustment**:
```
cooperation_difficulty = baseD           (minimum, network idles)
attack_difficulty      = baseD * (1 + attack_score)  (ramps geometrically)
```

- **Under cooperation**: Network runs at minimum difficulty
- **Under attack**: Difficulty ramps AGAINST the attacker
- **Recovery**: After attack subsides, difficulty decays back to minimum

**The attacker pays geometrically more. The defender pays nothing extra.**

### Individual Node Contribution

Each node's effective contribution:

```
effective_weight = min(individual_hashrate, diffusion_cap(latency_diversity))
```

- **Hashrate matters**: Faster nodes contribute more (up to cap)
- **Diffusion matters**: Geographic distribution determines cap
- **Both required**: High hashrate + low diversity = capped. High diversity + low hashrate = limited.

### Byzantine Behaviors in JOIN

| Byzantine Action | Who Does It | Defense |
|------------------|-------------|---------|
| Entry assigns wrong slot | Malicious entry node | Network rejects; neighbors won't TGP for wrong slot |
| Entry broadcasts fake CANDIDATE | Malicious entry node | No valid QuadProof; network ignores |
| Neighbors refuse TGP | Malicious neighbors | Try other neighbors; threshold is 11/20, not 20/20 |
| Two entries race same slot | Concurrent joins | Deterministic priority via hash; lower wins |
| Entry lies about neighbors | Malicious entry node | Joiner discovers via TGP failures; retries with new entry |

**Key insight**: Joiner can always retry with a different entry node. Byzantine entry nodes waste joiner's time but can't permanently exclude them.

### Eclipse Attack Detection

A fully eclipsed node can **locally verify** something is wrong:

1. **Chain too light**: "This chain weight doesn't match network age"
2. **Attestation mismatch**: "These counts don't make sense for claimed network size"
3. **Latency anomalies**: "All my neighbors have suspiciously similar latency"

The branches contradict each other. Eclipse attacks become **incoherent**.

---

## TGP: The Bilateral Primitive

Every operation in this protocol uses TGP (Two Generals Protocol):

```
┌─────────────────────────────────────────────────────────────────┐
│                     TGP HANDSHAKE                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1 - Commitment (C):                                      │
│    └── Exchange signed intent to coordinate                     │
│                                                                 │
│  Phase 2 - Double (D):                                          │
│    └── Prove receipt of counterparty's commitment               │
│                                                                 │
│  Phase 3 - Triple (T):                                          │
│    └── Prove knowledge of counterparty's double proof           │
│                                                                 │
│  Phase 4 - Quad (Q):                                            │
│    └── Epistemic fixpoint reached - coordination complete       │
│                                                                 │
│  Result: QuadProof                                              │
│    ├── Proves bilateral agreement                               │
│    ├── Unique per handshake (artifact differs each time)        │
│    ├── Unforgeable (cryptographically signed)                   │
│    └── Symmetric (both parties can construct it)                │
│                                                                 │
│  Timing: 4 packets, ~2 RTT                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### TGP Properties Used

| Property | How It's Used |
|----------|---------------|
| **Bilateral** | Entry↔Joiner, Joiner↔Neighbor, Node↔Node for swaps |
| **Unique artifact** | Race resolution priority hash |
| **Atomic** | Swap either happens for both or neither |
| **Persistent** | Once established, QuadProof is forever valid |

---

## State Machines

### Joiner State Machine

```
┌─────────┐    TGP with      ┌──────────┐   Got slot    ┌────────────┐
│ SEEKING │───────────────→  │ ASSIGNED │ ───────────→  │ CONNECTING │
└─────────┘   entry node     └──────────┘  assignment   └────────────┘
                                                              │
                                                              │ Threshold
                                                              │ reached
                                                              ▼
                                                        ┌──────────┐
                                                        │    IN    │
                                                        └──────────┘
```

### Entry Node State Machine (per joiner)

```
┌──────────┐   TGP done    ┌───────────┐  Broadcast   ┌───────────┐
│ HANDSHAKE│──────────────→│ COMPUTING │────────────→ │ ANNOUNCED │
└──────────┘               └───────────┘   CANDIDATE  └───────────┘
                                                            │
                                                            │ Joiner
                                                            │ connected
                                                            ▼
                                                      ┌──────────┐
                                                      │   DONE   │
                                                      └──────────┘
```

---

## Algorithms to Formalize in Lean

### 1. first_empty_slot

```lean
/-- Given occupancy bitmap, find first unoccupied slot in SPIRAL order -/
def first_empty_slot (occupied : Finset Slot) : Slot :=
  -- Enumerate slots in SPIRAL order (0, 1, 2, ...)
  -- Return first slot not in occupied set
```

### 2. priority

```lean
/-- Compute race priority from peer ID and TGP artifact -/
def priority (peer_id : PeerId) (artifact : QuadProofArtifact) : Hash :=
  hash (peer_id.bytes XOR artifact.bytes)

/-- Lower priority wins -/
def wins (p1 p2 : Hash) : Bool := p1 < p2
```

### 3. scaling_ladder

```lean
/-- Compute threshold given number of existing neighbors -/
def threshold (neighbor_count : Nat) : Nat :=
  if neighbor_count < 3 then neighbor_count
  else Nat.ceil (neighbor_count * 11 / 20)
```

### 4. is_valid_trump

```lean
/-- Check if slot swap is mutually beneficial -/
def is_valid_trump (a b : Node) (topology : Mesh) : Bool :=
  let a_current := avg_latency a (neighbors_of a.slot topology)
  let a_swapped := avg_latency a (neighbors_of b.slot topology)
  let b_current := avg_latency b (neighbors_of b.slot topology)
  let b_swapped := avg_latency b (neighbors_of a.slot topology)
  a_swapped < a_current ∧ b_swapped < b_current
```

### 5. chain_winner (from CVDF.lean)

```lean
/-- Determine winner by chain weight (already proven in CVDF.lean) -/
def mergeChains (c1 c2 : CvdfChain) : CvdfChain :=
  if c1.totalWeight ≥ c2.totalWeight then c1 else c2

/-- Chain weight = sum of round weights -/
def CvdfChain.totalWeight (c : CvdfChain) : Weight :=
  c.rounds.foldl (fun acc r => acc + r.weight) 0

/-- Round weight = 1 + attestation count -/
def CvdfRound.weight (r : CvdfRound) : Weight :=
  baseWeight + r.attestations.length * attestationWeight
```

Key theorems already proven:
- `heavier_survives_merge`: Heavier chain survives merge
- `collaboration_wins`: N-attester chain dominates 1-attester chain
- `merge_deterministic`: Chain merge is deterministic

---

## Invariants to Prove

1. **Uniqueness**: At most one node can occupy any slot
2. **Determinism**: Race resolution produces the same winner for all observers
3. **Liveness**: A joining node eventually gets a slot (assuming network connectivity)
4. **Safety**: Latency trumps only occur when both parties benefit
5. **Convergence**: After zipper merge, the network has no duplicate slots

---

## Summary

| Operation | Initiator | Computation Location | What Moves |
|-----------|-----------|---------------------|------------|
| **Join** | Joiner | Entry node computes slot | Joiner enters empty slot |
| **Race** | Network | Each node computes priority | Lower hash wins |
| **Trump** | Either node | Both verify mutual benefit | Nodes swap slots |
| **Merge** | Both swarms | Each computes CVDF comparison | Losers rejoin |

The key insight: **Joiner doesn't think, Entry node thinks, Network validates.**
