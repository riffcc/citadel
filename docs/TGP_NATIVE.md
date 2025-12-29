# TGP-Native Mesh: Design Document

## One Sentence

**Replace TCP connection management with TGP flooding—the mesh becomes a set of QuadProofs, not sockets.**

---

## The Problem

The current mesh implementation (`citadel-lens/src/mesh/service.rs`) uses TCP for peer connections:

```
CURRENT ARCHITECTURE (TCP):
├── TcpStream::connect() with 5s timeout
├── Exponential backoff retry loop (1s → 60s)
├── Connection state tracking (peers HashMap)
├── "Phantom peer" bugs (peers added before connection)
├── Isolated node bugs (retry loop checks wrong state)
├── Keepalive logic
├── Broadcast channel for flood propagation (TCP pattern!)
└── STATE MACHINE HELL
```

Every bug we fix reveals another. The phantom peer bug exists because we track connection *intent* separate from connection *reality*. The isolated node bug exists because retry logic doesn't understand what "connected" means.

**These aren't bugs. They're symptoms of using TCP for TGP's job.**

### Current Code Analysis (December 2025)

The mesh service has **two parallel systems** that shouldn't coexist:

| Component | Location | Purpose | Problem |
|-----------|----------|---------|---------|
| TCP Listener | `service.rs:1812` | Accepts incoming peer connections | Stateful, requires connection management |
| TCP handle_connection | `service.rs:2009+` | Per-peer connection handler | Spawns task per peer, manages reader/writer |
| broadcast::channel | `service.rs:95` | Flood propagation to peers | **TCP pattern** - subscribers hold buffer in memory |
| flood_rx.subscribe() | `service.rs:2275` | Per-connection flood receiver | Each connection subscribes → memory per peer |
| UDP Socket | `service.rs:1817` | TGP coordination | **Correct pattern** - connectionless |
| run_tgp_udp_listener | `service.rs:1463` | TGP message handling | Event-driven, stateless |

**The broadcast channel is the smoking gun.** It's a TCP pattern (pub/sub with buffered subscribers) applied to what should be stateless UDP flooding. When citadel-1 handled an upload and spiked to 59MB while others stayed at 8-10MB, this is likely why.

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
| Broadcast channel | Direct UDP send to all authorized peers |
| Per-connection tasks | Single UDP recv loop |
| Per-connection memory | ~2KB per peer (QuadProof only) |

---

## Canonical TGP Design (from two-generals)

The authoritative TGP implementation lives in `/Users/wings/projects/two-generals/`. The Lean 4 proofs formally verify the protocol properties.

### The Core Insight: Epistemic Escalation

TGP solves the Two Generals Problem through **epistemic escalation**—each message level embeds proof of the previous level, creating a cryptographic chain that terminates at a fixpoint.

```
EPISTEMIC DEPTH:
C  = depth 0: "I intend to coordinate"
D  = depth 1: "I know YOU intend to coordinate" (contains C_A and C_B)
T  = depth 2: "I know you know I intend" (contains D_A and D_B)
Q  = depth ω: Fixpoint. No more depth needed. (contains T_A and T_B)
```

### The Four-Phase Protocol

```
PACKET 1 (A→B): C_A                    # A's commitment
PACKET 2 (B→A): C_B + D_B              # B's commitment + proof of A's
PACKET 3 (A→B): D_A + T_A              # A's double + triple
PACKET 4 (B→A): T_B + Q_B              # B's triple + quad

RESULT: Both have QuadProof. Forever.
```

### Self-Certifying Proofs (The Key Property)

Each proof level **embeds all previous levels**:

```rust
// From two-generals/rust/src/types.rs

struct Commitment {
    party: Party,
    message: Vec<u8>,         // The commitment message
    signature: Signature,     // Ed25519 signature
    public_key: PublicKey,
}

struct DoubleProof {
    own_commitment: Commitment,     // Embeds own C
    other_commitment: Commitment,   // Embeds their C
    signature: Signature,           // Signs over both
}

struct TripleProof {
    own_double: DoubleProof,        // Embeds own D (which embeds both C's)
    other_double: DoubleProof,      // Embeds their D (which embeds both C's)
    signature: Signature,
}

struct QuadProof {
    own_triple: TripleProof,        // Embeds own T (which embeds both D's, all C's)
    other_triple: TripleProof,      // Embeds their T
    signature: Signature,
}
```

**Why this matters**: Receiving a higher-level proof automatically gives you all lower-level proofs. If you receive Q_B, you can extract T_B, D_B, C_B, T_A, D_A, C_A—everything you need.

This enables **proof embedding shortcuts**:
- Receive D_B → extract C_B for free
- Receive T_B → extract D_B, C_B for free
- Receive Q_B → extract everything for free

### The State Machine

```rust
// From two-generals/rust/src/protocol.rs

pub enum ProtocolState {
    Init,           // Before commitment created
    Commitment,     // Flooding C_X, awaiting C_Y
    Double,         // Flooding D_X, awaiting D_Y
    Triple,         // Flooding T_X, awaiting T_Y
    Quad,           // Flooding Q_X, awaiting Q_Y
    Complete,       // Fixpoint achieved — can ATTACK
    Aborted,        // Deadline passed — must ABORT
}
```

**State transitions with proof embedding**:

```rust
fn receive_triple_proof(&mut self, triple: &TripleProof) -> Result<bool> {
    if self.other_triple.is_none() {
        // EXTRACT embedded artifacts for free
        self.other_double = Some(triple.own_double.clone());
        self.other_commitment = Some(triple.own_double.own_commitment.clone());

        // CASCADE state updates - jump multiple states at once!
        if matches!(self.state, ProtocolState::Commitment) && self.own_commitment.is_some() {
            self.create_double_proof();  // Jump to Double
        }
        if matches!(self.state, ProtocolState::Double) && self.own_double.is_some() {
            self.create_triple_proof();  // Jump to Triple
        }
    }
    // ...
}
```

This means a peer can receive a Q message and immediately construct their own Q in response, even if they missed earlier messages.

### What "Stateless After Handshake" Means

Once both parties reach Q (Complete state):
- No acknowledgments needed
- No further state mutations required
- The bilateral receipt pair (Q_A, Q_B) is self-contained
- Decision is deterministic: have Q → ATTACK, else ABORT

**Post-handshake memory model**: Store (Q_A, Q_B) and you're done. No ongoing protocols, no state machines, no background tasks.

```rust
pub fn can_attack(&self) -> bool {
    self.is_complete() && self.own_quad.is_some()
}

pub fn get_decision(&self) -> Decision {
    if self.is_complete() {
        Decision::Attack
    } else {
        Decision::Abort
    }
}
```

---

## The Lean Proofs

Location: `/Users/wings/projects/two-generals/lean4/`

### Verified Properties

| File | Theorems | What It Proves |
|------|----------|----------------|
| TwoGenerals.lean | 39 theorems | Bilateral construction, no asymmetric outcomes |
| BFT.lean | 16 theorems | Quorum intersection, BFT safety |
| ExtremeLoss.lean | 6 theorems | Convergence under arbitrary packet loss |
| LightweightTGP.lean | 19 theorems | Simplified construction, same guarantees |
| NetworkModel.lean | 5 theorems | Fair-lossy channel formalization |

### Key Theorems

**Bilateral Construction Property**:
```lean
-- If A has Q_A, then B can construct Q_B
theorem bilateral_construction (h : has_quad A) :
    constructible (quad B)
```

**No Asymmetric Outcomes**:
```lean
-- Both parties reach the same decision
theorem no_asymmetric_outcome :
    ∀ scenarios, ¬asymmetric_outcome
```

**Common Knowledge at Q**:
```lean
-- QuadProof establishes epistemic fixpoint
theorem quad_is_fixpoint :
    bilateral_receipt_pair (Q_A, Q_B) → common_knowledge coordination
```

**Liveness Under Extreme Loss**:
```lean
-- Even 99% packet loss converges
theorem extreme_loss_convergence :
    fair_lossy_channel p → (p > 0) → eventually_complete
```

The success probability calculation: **1 - 10^-1565** (physical certainty).

---

## Architecture

### Current vs TGP-Native

```
CURRENT (mesh/service.rs):
┌─────────────────────────────────────────────────────────────┐
│  MeshService                                                │
│  ├── TCP Listener (accept incoming)           [REMOVE]      │
│  ├── TCP Connect (outgoing to entry peers)    [REMOVE]      │
│  ├── broadcast::channel(1024)                 [REMOVE]      │
│  │     └── flood_rx.subscribe() per peer      [MEMORY LEAK] │
│  ├── peers: HashMap<PeerId, MeshPeer>         [REPLACE]     │
│  ├── handle_connection() per-peer TCP         [REMOVE]      │
│  ├── Retry loop with exponential backoff      [REMOVE]      │
│  │                                                          │
│  ├── UDP Socket                               [KEEP]        │
│  ├── run_tgp_udp_listener()                   [EXPAND]      │
│  ├── tgp_sessions: HashMap                    [EXPAND]      │
│  └── authorized_peers: HashMap                [CANONICAL]   │
└─────────────────────────────────────────────────────────────┘

TGP-NATIVE:
┌─────────────────────────────────────────────────────────────┐
│  MeshService                                                │
│  ├── UDP Socket (single socket for all peers)               │
│  ├── authorized_peers: HashMap<PeerId, AuthorizedPeer>      │
│  │     └── Contains bilateral QuadProofs                    │
│  ├── pending_handshakes: HashMap<PeerId, TgpState>          │
│  │     └── Active handshakes only, discarded on complete    │
│  └── Continuous flooding loop (drip → burst adaptive)       │
│        └── NO broadcast channel, direct UDP send            │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
INCOMING UDP PACKET:
  recv_from() → extract peer_id from message →

    Is it a TGP handshake message?
      YES → advance pending_handshakes[peer_id]
            if handshake complete → move to authorized_peers

    Is peer in authorized_peers?
      YES → process message (slot claim, CVDF round, SPORE sync, etc.)
      NO  → drop (unauthorized, not in handshake)

OUTGOING MESSAGE:
  for each peer in authorized_peers:
    UDP send_to(peer.last_addr, message)

  (No broadcast channel. Direct send. Stateless.)
```

### Memory Model Comparison

```
CURRENT (per peer):
├── MeshPeer struct                     ~200 bytes
├── TCP connection buffers              ~64KB (kernel)
├── Tokio task overhead                 ~8KB
├── broadcast::Receiver buffer          ~32KB (1024 × ~32 bytes)
├── BufReader/BufWriter                 ~16KB
└── Total per peer:                     ~120KB

TGP-NATIVE (per peer):
├── AuthorizedPeer struct               ~100 bytes
├── QuadProof (both directions)         ~2KB
├── Last address (SocketAddr)           ~32 bytes
└── Total per peer:                     ~2.5KB

IMPROVEMENT: 48× less memory per peer
```

For 100 peers:
- Current: ~12MB
- TGP-Native: ~250KB

---

## Adaptive Flooding

### The Core Mechanism

Instead of request-response or acknowledgment-based protocols, TGP uses **continuous flooding**: each party sends their highest available proof repeatedly until the protocol completes.

```rust
pub fn get_messages_to_send(&mut self) -> Vec<Message> {
    // Always send highest available proof (it embeds all lower ones)
    let payload = match self.state {
        ProtocolState::Complete | ProtocolState::Quad => {
            self.own_quad.as_ref().map(|q| MessagePayload::QuadProof(q.clone()))
        }
        ProtocolState::Triple => {
            self.own_triple.as_ref().map(|t| MessagePayload::TripleProof(t.clone()))
        }
        ProtocolState::Double => {
            self.own_double.as_ref().map(|d| MessagePayload::DoubleProof(d.clone()))
        }
        ProtocolState::Commitment => {
            self.own_commitment.as_ref().map(|c| MessagePayload::Commitment(c.clone()))
        }
        _ => None,
    };
    // ...
}
```

**Why flooding works**:
- Retransmission is built-in (just keep sending)
- No acknowledgment needed (proof arrival is self-evident)
- No timeout logic (flood until complete or deadline)
- Packet loss irrelevant (any instance of Q suffices)

### Rate Modes

```
Drip Mode:   1-10 pkts/sec     (idle/keep-alive)
Low:         100-1K pkts/sec   (small data)
Medium:      1K-10K pkts/sec   (normal transfer)
Burst:       10K-100K pkts/sec (high priority)
Max:         100K+ pkts/sec    (emergency)
```

The rate affects **timing** of arrivals, not **which proofs exist**. Bilateral construction is preserved at any rate because:
- Q_X still proves Q_Y constructible regardless of how fast it arrives
- Cryptographic structure is rate-agnostic
- Convergence is guaranteed under fair-lossy channel

### Implementation for Mesh

```rust
async fn run_flooding_loop(self: Arc<Self>) {
    // Event-driven: flood when there's work, drip when idle
    let mut flood_interval = Duration::from_secs(300); // 5 min drip

    loop {
        tokio::time::sleep(flood_interval).await;

        let state = self.state.read().await;

        // Flood to all authorized peers via direct UDP send
        // NO broadcast channel - just iterate and send
        for (peer_id, peer) in &state.authorized_peers {
            // Flood our slot claim
            if let Some(slot) = &state.our_slot {
                self.send_udp(peer.last_addr, &slot).await;
            }

            // Flood SPORE HaveList
            if state.have_list_changed {
                self.send_udp(peer.last_addr, &state.have_list).await;
            }
        }

        // Flood pending handshakes
        for (_, handshake) in &state.pending_handshakes {
            let msg = handshake.get_current_proof();
            self.send_udp(handshake.peer_addr, &msg).await;
        }

        // Adaptive rate: burst during activity, drip when idle
        if state.has_pending_activity() {
            flood_interval = Duration::from_millis(10);
        } else {
            flood_interval = Duration::from_secs(300);
        }
    }
}
```

---

## DH Hardening Layer (Optional Enhancement)

The canonical TGP can be extended with Diffie-Hellman key exchange embedded in the handshake. This provides:

1. **Perfect Forward Secrecy**: Session keys don't compromise future sessions
2. **Shared Secret**: Can derive encryption keys for mesh traffic
3. **Same 4-Packet Handshake**: DH fits into C→D→T→Q structure

```
C_X = Sign_X(g^a, "I will attack at dawn")
D_X = Sign_X(C_X ∥ C_Y ∥ g^b)
...
Shared secret S = g^ab (computed by both parties)
Session key = KDF(S, Q_A, Q_B)
```

**Decision Rule with DH**:
```
ATTACK if:  Can compute shared secret S = g^ab before deadline
ABORT if:   Cannot compute S before deadline
```

---

## BFT Extension (N-Party Consensus)

TGP extends from bilateral (2-party) to N-party BFT consensus using threshold signatures.

### System Model

```
Total nodes (arbitrators) = 3f + 1
Fault tolerance = f Byzantine
Threshold T = 2f + 1
```

### Two-Flood Protocol

```
FLOOD 1: PROPOSE + SHARE
├─ Any node floods proposal: PROPOSE(R, V)
└─ Each arbitrator creates and floods: SHARE_i(hash(R || V))

FLOOD 2: COMMIT
└─ Any aggregator with ≥ T shares floods: COMMIT(R, V, proof)
```

### Safety Guarantee

```
Any valid COMMIT(R, V, proof) requires ≥ 2f+1 shares.
Two different values V₁, V₂ would need:

Shares for V₁: ≥ 2f+1
Shares for V₂: ≥ 2f+1
Total possible: = 3f+1
                ─────── Impossible!

Therefore: No conflicting commits ever (Byzantine safety).
```

### Why No View Changes

Traditional BFT (PBFT, Raft, etc.) requires:
- Leader election
- View change protocol
- Timeout-based liveness

TGP-BFT has none of this:
- Any node can propose (no leader)
- Flooding ensures delivery (no view changes)
- Threshold aggregation is local (no coordination)

---

## Progressive TGP Scaling

TGP scales from bilateral coordination to full Byzantine consensus as the mesh grows.

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

### Stage 2: Bilateral TGP (2 Nodes)

```
┌─────┐     TGP      ┌─────┐
│  0  │◄────────────►│  1  │
└─────┘   C→D→T→Q    └─────┘

Threshold: 1/1 (your only neighbor must agree)
```

### Stage 3: TGP Triad (3 Nodes)

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

### Stage 6: Full SPIRAL (20+ Neighbors)

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

---

## Performance Characteristics

From the TGP paper simulations:

| Metric | TCP | TGP | Improvement |
|--------|-----|-----|-------------|
| Coordination time (0% loss) | 22 ticks | 3 ticks | **7×** |
| Coordination time (50% loss) | 880+ ticks | 45 ticks | **20×** |
| Coordination time (90% loss) | timeout | 180 ticks | **∞** |
| Handshake overhead | Every session | Once, forever | **∞** |
| State per peer | Socket + buffers | 256-byte proof | **48×** |

### Scaling

```
1 GB RAM for proofs = ~4 million authorized peers
Cost per peer after handshake: 0
Packets from unknown peer: O(1) HashMap miss
Packets from authorized peer: O(1) HashMap hit + process
```

---

## Current Implementation Status

### Already Implemented (Keep/Expand)

| Component | File | Status |
|-----------|------|--------|
| `AuthorizedPeer` struct | `mesh/peer.rs:71-100` | Ready for TGP-native use |
| `authorized_peers` HashMap | `mesh/state.rs:43` | Data structure exists |
| `PeerCoordinator` | `citadel-protocols/src/coordinator.rs` | Full TGP implementation |
| `TgpSession` | `mesh/tgp.rs` | Wrapper for mesh use |
| UDP socket setup | `mesh/service.rs:1817` | Bind exists |
| `run_tgp_udp_listener` | `mesh/service.rs:1463` | Event-driven listener |
| `send_tgp_messages` | `mesh/service.rs:1750` | UDP send |

### To Be Removed (Phase 3)

| Component | File | Reason |
|-----------|------|--------|
| TCP Listener | `service.rs:1812` | TCP not needed |
| `handle_connection()` | `service.rs:2009+` | Per-connection handling obsolete |
| `broadcast::channel` | `service.rs:95` | TCP pattern, causes memory issues |
| `flood_rx.subscribe()` | `service.rs:2275` | Per-connection buffer |
| TCP connect logic | scattered | Replaced by TGP handshake |
| Exponential backoff | scattered | Flooding handles retry |
| Timeout constants | scattered | No timeouts in TGP |

### Critical Insight from Code Analysis

From `mesh/service.rs:1541-1567`:

```rust
// TGP is TCP-free: we can establish coordination with ANY node that sends us
// a valid TGP message, using just the public key from the message itself.
// No pre-existing TCP peer relationship required!
```

This comment already describes the target architecture. The TCP code is legacy that needs removal.

---

## Migration Plan

### Phase 1: Hybrid Mode (Current State)

Run TGP alongside TCP during transition:

```rust
struct MeshService {
    // Existing TCP infrastructure (to be removed)
    tcp_listener: TcpListener,
    tcp_peers: HashMap<String, MeshPeer>,
    flood_tx: broadcast::Sender<FloodMessage>,  // THE PROBLEM

    // TGP infrastructure (to be expanded)
    udp_socket: Arc<UdpSocket>,
    authorized_peers: HashMap<PeerId, AuthorizedPeer>,
    pending_handshakes: HashMap<PeerId, TgpHandshakeState>,
}
```

### Phase 2: TGP-Primary

- All new connections use TGP
- TCP only for legacy compatibility
- Remove broadcast channel entirely
- Replace with direct UDP flood

### Phase 3: TGP-Only

- Remove TCP connection code entirely
- Remove `handle_connection()`, retry loops, timeout logic
- Remove `tcp_peers` HashMap
- Remove `broadcast::channel`
- Single UDP socket handles everything

---

## Files to Modify

### Primary Changes

1. **`citadel-lens/src/mesh/service.rs`**
   - Remove `broadcast::channel` and all `flood_tx`/`flood_rx` usage
   - Remove TCP listener loop (`TcpListener::bind`, `listener.accept`)
   - Remove `handle_connection()` function entirely
   - Remove exponential backoff retry loop
   - Expand `run_tgp_udp_listener()` to handle all message types
   - Add direct UDP flooding (no broadcast channel)
   - Use `authorized_peers` as the canonical peer set

2. **`citadel-lens/src/mesh/state.rs`**
   - Remove `flood_tx: broadcast::Sender<FloodMessage>`
   - Remove `peers: HashMap<String, MeshPeer>` (TCP peers)
   - `authorized_peers` becomes the only peer set
   - Add `last_flood_time` for adaptive rate control

3. **`citadel-lens/src/mesh/peer.rs`**
   - Remove `MeshPeer` struct (TCP-oriented)
   - `AuthorizedPeer` already exists and is correct
   - Add helper methods for TGP-native operations

4. **`citadel-protocols/src/coordinator.rs`**
   - Already complete - wire it into mesh more directly

### Remove Entirely (Phase 3)

- TCP listener setup code
- `TcpStream::connect()` calls
- `handle_connection()` function
- Exponential backoff constants and loop
- Timeout constants and logic
- `MeshPeer` struct
- `flood_tx` / `flood_rx` / `broadcast::channel`
- Line-delimited JSON protocol code

---

## Testing Strategy

### Unit Tests

1. TGP handshake state machine transitions
2. Proof embedding (receive T, extract D and C)
3. Authorization check (QuadProof exists vs doesn't)
4. Message routing (only to authorized peers)
5. Adaptive rate control (drip ↔ burst)

### Integration Tests

1. Two nodes complete handshake via UDP only
2. Node discovers mesh via entry peer flooding
3. Isolated node recovers via flooding (no manual retry)
4. 50% packet loss → coordination still succeeds
5. 90% packet loss → coordination still succeeds (slower)
6. Memory stays stable under continuous operation

### Chaos Tests

1. Random packet drops → no asymmetric outcomes
2. Random delays → no asymmetric outcomes
3. Network partition → both sides ABORT (symmetric)
4. Node crash mid-handshake → safe state (no phantom)
5. Memory leak test: 1000 handshakes, memory bounded

---

## Migration Checklist

### Phase 1: Remove TCP Patterns (Priority)
- [ ] Remove `broadcast::channel` from state
- [ ] Remove `flood_tx.subscribe()` from handle_connection
- [ ] Replace flood propagation with direct UDP send loop
- [ ] Verify memory stays stable after changes

### Phase 2: Expand TGP
- [ ] Route all mesh messages through UDP path
- [ ] Use `authorized_peers` as canonical peer set
- [ ] Remove `peers` HashMap (TCP peers)
- [ ] Move entry peer discovery to TGP handshake

### Phase 3: Remove TCP Entirely
- [ ] Remove TCP listener setup code
- [ ] Remove `handle_connection()` function
- [ ] Remove exponential backoff constants
- [ ] Remove timeout logic
- [ ] Remove `MeshPeer` struct
- [ ] Update tests to use UDP only

---

## Decision Rules Summary

### For Protocol Implementers

```
ATTACK (proceed) if:  Can construct Q before deadline
ABORT (fail safe) if: Cannot construct Q before deadline
```

### For Mesh Service

```
ACCEPT message if:    Sender has QuadProof in authorized_peers
ADVANCE handshake if: Valid TGP message from pending_handshakes
DROP otherwise:       Unauthorized, not in handshake
```

### For Memory Management

```
STORE: QuadProof only (~2KB per peer)
DISCARD: Handshake state after completion
NEVER: Per-connection buffers, broadcast subscribers
```

---

## References

### Canonical Sources

- **TGP Implementation**: `/Users/wings/projects/two-generals/rust/`
- **Lean Proofs**: `/Users/wings/projects/two-generals/lean4/`
- **TGP Paper**: `/Users/wings/projects/two-generals/paper/main.pdf`

### Current Implementation

- **Mesh Service**: `/Users/wings/projects/citadel/crates/citadel-lens/src/mesh/`
- **TGP Coordinator**: `/Users/wings/projects/citadel/crates/citadel-protocols/src/coordinator.rs`
- **Mesh Protocol Spec**: `/Users/wings/projects/citadel/docs/MESH_PROTOCOL.md`

### Key Code Locations

| Purpose | File | Lines |
|---------|------|-------|
| Broadcast channel (REMOVE) | service.rs | 95, 2275 |
| TCP listener (REMOVE) | service.rs | 1812 |
| handle_connection (REMOVE) | service.rs | 2009+ |
| UDP socket (KEEP) | service.rs | 1817 |
| TGP listener (EXPAND) | service.rs | 1463 |
| TGP send (EXPAND) | service.rs | 1750 |
| AuthorizedPeer (CANONICAL) | peer.rs | 71-100 |
| authorized_peers (CANONICAL) | state.rs | 43 |

---

## Conclusion

The MESH_PROTOCOL.md already says:

> **"Connection" isn't a socket. It's a proof.**

But `mesh/service.rs` still uses TCP sockets and broadcast channels. This document bridges that gap.

The refactor isn't adding complexity—it's **removing** it:

| Remove | Keep |
|--------|------|
| TCP connection state | UDP socket |
| broadcast::channel | Direct UDP send |
| Per-connection tasks | Single recv loop |
| Reconnection logic | Flooding |
| Exponential backoff | Flooding |
| Timeout handling | Flooding |
| Keepalives | Proofs are permanent |
| ~120KB per peer | ~2.5KB per peer |

The bugs we've been fixing (phantom peers, isolated nodes, memory leaks) disappear because the conditions that created them no longer exist.

**The mesh computes itself.**
