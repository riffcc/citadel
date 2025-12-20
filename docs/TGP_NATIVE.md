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
