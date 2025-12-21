# TGP-Native Mesh: Design Document

## One Sentence

**Replace TCP connection management with TGP flooding—the mesh becomes a set of QuadProofs, not sockets.**

---

## The Problem

The current mesh implementation (`citadel-lens/src/mesh.rs`) uses TCP for peer connections:

```
CURRENT ARCHITECTURE (TCP):
├── TcpStream::connect() with 5s timeout
├── Exponential backoff retry loop (1s → 60s)
├── Connection state tracking (peers HashMap)
├── "Phantom peer" bugs (peers added before connection)
├── Isolated node bugs (retry loop checks wrong state)
├── Keepalive logic
└── STATE MACHINE HELL
```

Every bug we fix reveals another. The phantom peer bug exists because we track connection *intent* separate from connection *reality*. The isolated node bug exists because retry logic doesn't understand what "connected" means.

**These aren't bugs. They're symptoms of using TCP for TGP's job.**

---

## The Solution

The TGP paper proves: **Connection isn't a socket. It's a proof.**

```
TGP-NATIVE ARCHITECTURE:
├── QuadProof exists → accept packets from peer
├── No QuadProof → drop packets
├── Continuous UDP flooding (no retry logic—flooding IS retry)
├── Authorization = cryptographic proof, not socket state
└── That's it. That's the whole thing.
```

### What This Eliminates

| Gone | Replacement |
|------|-------------|
| TCP connection state | QuadProof HashMap |
| Reconnection logic | Flooding handles it |
| Exponential backoff | Flooding handles it |
| Keepalive timers | Proofs are permanent |
| Half-open detection | N/A (no half-open state) |
| "Is peer alive?" checks | N/A (irrelevant) |
| Phantom peer bugs | Can't exist (proof = authorization) |
| Isolated node bugs | Can't exist (flooding finds everyone) |

---

## Architecture

### Current vs TGP-Native

```
CURRENT (mesh.rs):
┌─────────────────────────────────────────────────────────┐
│  MeshService                                            │
│  ├── TCP Listener (accept incoming)                     │
│  ├── TCP Connect (outgoing to entry peers)              │
│  ├── peers: HashMap<PeerId, MeshPeer>  ← socket state   │
│  ├── Retry loop with exponential backoff                │
│  └── handle_connection() → per-peer TCP stream          │
└─────────────────────────────────────────────────────────┘

TGP-NATIVE:
┌─────────────────────────────────────────────────────────┐
│  MeshService                                            │
│  ├── UDP Socket (single socket for all peers)           │
│  ├── authorized_peers: HashMap<PeerId, QuadProof>       │
│  ├── pending_handshakes: HashMap<PeerId, TgpState>      │
│  └── Continuous flooding loop (drip → burst adaptive)   │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
INCOMING PACKET:
  UDP recv → extract peer_id → authorized_peers.contains(peer_id)?
    YES → process message (slot claim, CVDF round, SPORE sync, etc.)
    NO  → is it a TGP handshake message?
      YES → advance pending_handshakes[peer_id]
      NO  → drop (unauthorized)

OUTGOING MESSAGE:
  message → for each authorized_peer → UDP send
  (flooding: send to ALL authorized peers, they relay)
```

---

## The TGP Handshake

From the paper: **4 packets to meet. Zero packets to reconnect. Forever.**

```
PACKET 1 (A→B): C_A                    # A's commitment
PACKET 2 (B→A): C_B + D_B              # B's commitment + proof of A's
PACKET 3 (A→B): D_A + T_A              # A's double + triple
PACKET 4 (B→A): T_B + Q_B              # B's triple + quad

RESULT: Both have QuadProof. Forever.
```

After this handshake:
- Both parties have `QuadProof`
- Authorization is **permanent** (cryptographic, not connection-based)
- Future communication: just send UDP packets (no handshake needed)
- **Half-RTT instant start**: No TCP SYN/SYN-ACK/ACK dance

### Handshake State Machine

```rust
enum TgpHandshakeState {
    Init,                           // Haven't started
    SentCommitment(Commitment),     // Sent C, waiting for C+D
    SentDouble(Double),             // Sent D, waiting for D+T
    SentTriple(Triple),             // Sent T, waiting for T+Q
    Complete(QuadProof),            // Done forever
}
```

This state machine exists **only during initial handshake**. Once `Complete`, the peer moves to `authorized_peers` and the state is discarded. No ongoing connection state.

---

## Migration Plan

### Phase 1: Hybrid Mode (Parallel Operation)

Run TGP alongside TCP during transition:

```rust
struct MeshService {
    // Existing TCP infrastructure (to be removed)
    tcp_listener: TcpListener,
    tcp_peers: HashMap<String, MeshPeer>,

    // New TGP infrastructure
    udp_socket: Arc<UdpSocket>,
    authorized_peers: HashMap<PeerId, QuadProof>,
    pending_handshakes: HashMap<PeerId, TgpHandshakeState>,
}
```

- Entry peers: Attempt TGP handshake over UDP first
- Fallback to TCP if TGP fails (shouldn't happen)
- Accept both TCP connections AND TGP handshakes
- Log metrics to compare reliability

### Phase 2: TGP-Primary

- All new connections use TGP
- TCP only for legacy compatibility
- Deprecation warnings for TCP connections

### Phase 3: TGP-Only

- Remove TCP connection code entirely
- Remove `handle_connection()`, retry loops, timeout logic
- Remove `tcp_peers` HashMap
- Single UDP socket handles everything

---

## Implementation Details

### New Structures

```rust
/// A peer authorized via TGP QuadProof
struct AuthorizedPeer {
    peer_id: PeerId,
    public_key: VerifyingKey,
    quad_proof: QuadProof,
    last_addr: SocketAddr,      // Last known address (can change)
    slot: Option<SlotClaim>,    // Learned via SPORE flood
}

/// Pending TGP handshake
struct PendingHandshake {
    peer_id: PeerId,
    their_addr: SocketAddr,
    state: TgpHandshakeState,
    started: Instant,
}
```

### Message Types

Extend existing `MeshMessage` enum:

```rust
enum MeshMessage {
    // Existing messages (unchanged)
    Hello { ... },
    SlotClaim { ... },
    CvdfRound { ... },
    SporeSync { ... },

    // TGP handshake messages (new)
    TgpCommitment(Commitment),
    TgpDouble(Double),
    TgpTriple(Triple),
    TgpQuad(QuadProof),
}
```

### The Flooding Loop

Replace exponential backoff retry with adaptive flooding:

```rust
async fn run_flooding_loop(self: Arc<Self>) {
    // Adaptive rate: drip mode (~1/300s) when idle, burst when active
    let mut flood_interval = Duration::from_millis(300_000); // 5 min drip

    loop {
        tokio::time::sleep(flood_interval).await;

        let state = self.state.read().await;

        // Flood current state to all authorized peers
        for (peer_id, peer) in &state.authorized_peers {
            // Flood our slot claim
            if let Some(slot) = &state.our_slot {
                self.send_to_peer(peer, MeshMessage::SlotClaim(slot.clone())).await;
            }

            // Flood pending TGP handshakes
            for (_, handshake) in &state.pending_handshakes {
                self.flood_handshake_state(handshake).await;
            }
        }

        // Adaptive rate adjustment
        if state.has_pending_activity() {
            flood_interval = Duration::from_millis(10); // Burst mode
        } else {
            flood_interval = Duration::from_millis(300_000); // Drip mode
        }
    }
}
```

### Entry Peer Discovery

Current: TCP connect with timeout and retry.
New: UDP flood commitment, wait for response.

```rust
async fn discover_entry_peers(self: Arc<Self>) {
    for peer_addr in &self.entry_peers {
        // Resolve address
        let addr = resolve_peer_addr(peer_addr).await?;

        // Create commitment for this peer
        let commitment = self.create_commitment(peer_addr);

        // Add to pending handshakes
        self.state.write().await.pending_handshakes.insert(
            peer_addr.clone(),
            PendingHandshake {
                their_addr: addr,
                state: TgpHandshakeState::SentCommitment(commitment.clone()),
                started: Instant::now(),
            }
        );

        // Flood commitment (no waiting for response—flooding loop handles it)
        self.send_udp(addr, MeshMessage::TgpCommitment(commitment)).await;
    }

    // No retry logic needed—flooding loop will keep sending until handshake completes
}
```

---

## Why This Fixes Our Bugs

### Phantom Peer Bug

**Current**: `flood_peers` handler adds peers to `state.peers` before TCP connection.
**TGP**: Peers only exist in `authorized_peers` after QuadProof. No "phantom" state.

### Isolated Node Bug

**Current**: Retry loop checks `peers.len()` which includes phantom peers.
**TGP**: `authorized_peers.len()` is truth. No phantoms, no confusion.

### Timeout/Retry Complexity

**Current**: 5s TCP timeout, exponential backoff 1s→60s, separate retry loop.
**TGP**: Flooding IS the retry. No timeout logic. No backoff. Just keep flooding.

### Connection State Bugs

**Current**: TCP half-open, keepalive failures, FIN/RST handling.
**TGP**: No connection state. Proof exists or doesn't. Binary.

---

## Performance Characteristics

From the TGP paper:

| Metric | TCP | TGP | Improvement |
|--------|-----|-----|-------------|
| Coordination time (0% loss) | 22 ticks | 3 ticks | **7×** |
| Coordination time (50% loss) | 880+ ticks | 45 ticks | **20×** |
| Coordination time (90% loss) | timeout | 180 ticks | **∞** |
| Handshake overhead | Every session | Once, forever | **∞** |
| State per peer | Socket + buffers | 256-byte proof | **Minimal** |

### Scaling

```
1 GB RAM for proofs = ~4 million authorized peers
Cost per peer after handshake: 0
Packets from unknown peer: O(1) HashMap miss
Packets from authorized peer: O(1) HashMap hit + process
```

---

## Progressive TGP Scaling

TGP scales from bilateral (2-party) coordination to full Byzantine Fault Tolerant consensus as the mesh grows. **The same core mechanism extends seamlessly.**

### The Scaling Ladder

```
NODES    MECHANISM              THRESHOLD    HOW IT WORKS
─────────────────────────────────────────────────────────────────────────────
  1      Genesis                0/0          Origin node—void accepts you
  2      Bilateral TGP          1/1          Both agree or neither does
  3      TGP Triad              2/3          Pairwise TGP, majority wins
 4-6     BFT Emergence          ⌈n/2⌉+1      TGP pairs + deterministic tiebreaker
 7-11    Full BFT               2f+1         Threshold signatures (n=3f+1)
 12-20   Neighbor Validation    scaled       Growing toward 11/20
 20+     Full SPIRAL            11/20        Mature mesh, all 20 neighbors exist
```

### Stage 1: Genesis (1 Node)

The origin. No neighbors to validate against—the void accepts you.

```
┌─────┐
│  0  │  ← Slot 0, the origin
└─────┘
   Threshold: 0/0 (automatic)
```

### Stage 2: Bilateral TGP (2 Nodes)

Classic Two Generals. Both must agree or neither acts.

```
┌─────┐     TGP      ┌─────┐
│  0  │◄────────────►│  1  │
└─────┘   C→D→T→Q    └─────┘

Threshold: 1/1 (your only neighbor must agree)
```

The four-phase handshake:
1. **C (Commitment)**: "I intend to coordinate"
2. **D (Double)**: "I know you intend"
3. **T (Triple)**: "I know you know I intend"
4. **Q (Quad)**: Epistemic fixpoint—mutual knowledge achieved

### Stage 3: TGP Triad (3 Nodes)

Three nodes form a triangle. Each pair runs bilateral TGP.

```
        ┌─────┐
        │  0  │
        └──┬──┘
          ╱ ╲
    TGP  ╱   ╲  TGP
        ╱     ╲
   ┌───┴─┐ ┌──┴──┐
   │  1  │─│  2  │
   └─────┘ └─────┘
      TGP

├── TRIAD CONSENSUS: 2/3 pairs must agree
├── Can tolerate 1 Byzantine node
└── Deterministic: hash(peer_ids) breaks ties
```

**How it works**: Run bilateral TGP between each pair. If 2/3 pairs achieve QuadProof, consensus is reached. One malicious node cannot prevent the other two from coordinating.

### Stage 4: BFT Emergence (4-6 Nodes)

Threshold signatures emerge. The TGP bilateral construction extends to N-party.

```
N = 3f + 1  (total nodes)
T = 2f + 1  (threshold for quorum)

For N=4: f=1, T=3 (tolerate 1 Byzantine)
For N=7: f=2, T=5 (tolerate 2 Byzantine)
```

### Stage 5: Full BFT (7+ Nodes)

**BFT in Two Floods** - the same structural insight that solves Two Generals extends to N-party consensus.

```
PROPOSE FLOOD:
┌────────────────────────────────────────────────────────┐
│  Leader broadcasts: PROPOSE(round, value)              │
│  All nodes receive (flooding ensures delivery)         │
└────────────────────────────────────────────────────────┘
                          ↓
SHARE FLOOD:
┌────────────────────────────────────────────────────────┐
│  Each node signs: SHARE(round, H(value), partial_sig)  │
│  Flood partial signature to all                        │
└────────────────────────────────────────────────────────┘
                          ↓
COMMIT (Local Aggregation):
┌────────────────────────────────────────────────────────┐
│  Any node with ≥T shares aggregates threshold sig      │
│  COMMIT = proof that T nodes agreed                    │
│  Flood the commit (compact proof of consensus)         │
└────────────────────────────────────────────────────────┘
```

**Why this achieves BFT**:
- Two quorums of size T must overlap by ≥ f+1 nodes
- At least one overlapping node is honest (only f Byzantine)
- Honest nodes sign only one value per round
- Therefore: conflicting threshold signatures impossible

### Stage 6: Full SPIRAL (20+ Neighbors)

At maturity, each node has 20 neighbors in the honeycomb topology.

```
Threshold: 11/20 (ceil(20 × 0.55))
Byzantine tolerance: 6 nodes (need 14 honest, 14 > 11)

VALIDATION THRESHOLD FORMULA:
  threshold(n) = ceil(n × 11/20)

Examples:
  1 neighbor  → 1 required
  3 neighbors → 2 required
  6 neighbors → 4 required
  10 neighbors → 6 required
  20 neighbors → 11 required
```

### Implementation References

| Component | Location | Description |
|-----------|----------|-------------|
| Bilateral TGP | `citadel-protocols/src/coordinator.rs` | C→D→T→Q handshake |
| BFT Extension | `two-generals/rust/src/bft.rs` | Threshold signatures |
| BFT Proofs | `two-generals/lean4/BFT.lean` | Formal verification |
| Threshold calc | `citadel-consensus/src/threshold.rs` | `validation_threshold(n)` |
| SPIRAL topology | `citadel-topology/src/spiral3d.rs` | 3D hex coordinates |

### Key Theorems (from Lean proofs)

From `two-generals/lean4/BFT.lean`:

```lean
-- Two quorums must overlap
theorem two_quorums_must_overlap (config : BftConfig) :
    2 * config.threshold > config.n

-- No conflicting threshold signatures possible
theorem no_conflicting_threshold_signatures (config : BftConfig)
    (sig1 sig2 : ThresholdSignature config) :
    sig1.round = sig2.round → sig1.value = sig2.value

-- BFT safety: same round implies same value
theorem bft_safety (config : BftConfig) (c1 c2 : BftCommit config) :
    c1.round = c2.round → c1.value = c2.value
```

From `proofs/CitadelProofs/Convergence.lean`:

```lean
-- Slot identity through connections
theorem slot_occupancy_unique :
    ∀ slot, at_most_one_node_occupies slot

-- Direction exclusivity prevents double-occupancy
theorem direction_exclusivity :
    ∀ neighbor port, at_most_one_peer_in_direction neighbor port
```

### Why Progressive Scaling Works

The insight: **TGP's bilateral construction is the atomic unit of consensus.**

```
2-party:  A ←→ B                    (1 TGP session)
3-party:  A ←→ B, B ←→ C, A ←→ C    (3 TGP sessions, 2/3 majority)
N-party:  All pairs + threshold aggregation
```

Each stage builds on the previous:
1. Bilateral TGP provides the cryptographic foundation
2. Threshold signatures aggregate bilateral proofs
3. Quorum intersection guarantees safety
4. Flooding ensures liveness

**The mesh doesn't switch protocols as it grows—it scales the same mechanism.**

---

## Files to Modify

### Primary Changes

1. **`citadel-lens/src/mesh.rs`**
   - Add `authorized_peers: HashMap<PeerId, AuthorizedPeer>`
   - Add `pending_handshakes: HashMap<PeerId, PendingHandshake>`
   - Replace TCP listener loop with UDP recv loop
   - Replace `connect_to_entry_peers()` with TGP commitment flooding
   - Remove exponential backoff retry loop
   - Remove `handle_connection()` (TCP-specific)

2. **`citadel-protocols/src/coordinator.rs`**
   - Already has TGP `PeerCoordinator` - wire it into mesh

3. **`citadel-protocols/src/message.rs`**
   - Add TGP handshake message variants

### Remove Entirely (Phase 3)

- TCP listener setup code
- `TcpStream::connect()` calls
- `handle_connection()` function
- Exponential backoff constants and loop
- Timeout constants and logic
- `MeshPeer.is_entry_peer` field (all peers are equal)
- `MeshPeer.coordinated` field (QuadProof IS coordination)

---

## Testing Strategy

### Unit Tests

1. TGP handshake state machine transitions
2. Authorization check (proof exists vs doesn't)
3. Message routing (only to authorized peers)

### Integration Tests

1. Two nodes complete handshake via UDP
2. Node discovers mesh via entry peer flooding
3. Isolated node recovers via flooding (no manual retry)
4. 50% packet loss → coordination still succeeds
5. 90% packet loss → coordination still succeeds (slower)

### Chaos Tests

1. Random packet drops → no asymmetric outcomes
2. Random delays → no asymmetric outcomes
3. Network partition → both sides ABORT (symmetric)
4. Node crash mid-handshake → safe state (no phantom)

---

## Migration Checklist

- [ ] Add TGP message types to `MeshMessage`
- [ ] Implement `TgpHandshakeState` machine
- [ ] Add `authorized_peers` HashMap to `MeshState`
- [ ] Add UDP socket setup in `start()`
- [ ] Implement `run_udp_listener()`
- [ ] Implement `run_flooding_loop()`
- [ ] Wire `PeerCoordinator` into mesh handshakes
- [ ] Replace `connect_to_entry_peers()` with TGP flooding
- [ ] Add hybrid mode (TCP + TGP parallel)
- [ ] Metrics: compare TCP vs TGP success rates
- [ ] Remove TCP code path
- [ ] Remove retry loop
- [ ] Remove timeout constants
- [ ] Update tests

---

## References

- TGP Paper: `/home/micha/projects/two-generals/paper/main.pdf`
- Current mesh: `citadel-lens/src/mesh.rs`
- TGP implementation: `citadel-protocols/src/coordinator.rs`
- Mesh protocol spec: `docs/MESH_PROTOCOL.md` (already describes TGP vision)

---

## Conclusion

The MESH_PROTOCOL.md already says:

> **"Connection" isn't a socket. It's a proof.**

But `mesh.rs` still uses TCP sockets. This document bridges that gap.

The refactor isn't adding complexity—it's **removing** it. TCP connection management, retry logic, timeout handling, keepalives, half-open detection: all gone. Replaced by:

1. A HashMap of QuadProofs
2. A flooding loop

That's the entire connection layer. The bugs we've been fixing disappear because the conditions that created them no longer exist.

**The mesh computes itself.**
