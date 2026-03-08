/-
Copyright (c) 2025 Riff Labs. All rights reserved.
Released under AGPL-3.0-or-later license.
Authors: Wings@riff.cc (Riff Labs)

Bilateral CRDTs - Formal Verification
=====================================

This is the root module for bilateral CRDT proofs.

## The Breakthrough

Traditional CRDTs: Eventual consistency via merge functions
Bilateral CRDTs: IMMEDIATE consistency via TGP collapse

The insight: The CRDT itself is the "other general" in TGP.
The merge function's determinism IS the bilateral property.
Pure functions cannot disagree with themselves.

## Modules

* `Basic` - Core CRDT definitions and merge function properties
* `Bilateral` - Bilateral construction via pure functions
* `Convergence` - Guaranteed convergence proofs
* `TGPCollapse` - TGP level collapse for deterministic merge
* `PracticalCAP` - CAP theorem transcendence via proven convergence
* `StructuralLinearizability` - TRUE linearizability from mesh topology (research)

## Main Results

### Basic.lean
* All functions are deterministic (by definition)
* CRDT merges have the bilateral property
* Pure functions cannot disagree with themselves
* GCounter is a valid CRDT with total, commutative, associative, idempotent merge

### Bilateral.lean
* TGP collapse is instantaneous (no network required)
* CRDT signature is deterministic
* Offline operations are always possible
* Valid operations are self-certifying
* Bilateral CRDT = TGP bilateral construction

### Convergence.lean
* Empty ops = identity
* Single op is deterministic
* Two operations can be reordered (commutativity)
* Infallible merge always exists (totality)
* Merge cannot fail
* Full sync = convergence
* No coordination needed for convergence
* Offline-then-sync converges

### TGPCollapse.lean
* Pure function TGP has zero network latency
* All four TGP levels collapse into one
* Any CRDT operation produces a collapsed TGP
* Pure function TGP needs zero messages
* CRDTs are offline-first by construction
* No network partition can prevent local operations

### PracticalCAP.lean
* CRDTs have zero-latency writes
* CRDTs are partition tolerant
* CRDTs are always available
* CRDTs have proven convergence
* CRDTs achieve Practical CAP
* CRDTs transcend CAP theorem
* Zero latency worldwide
* Convergence after sync (proven)

### StructuralLinearizability.lean (RESEARCH)
* Structural order is transitive, irreflexive, asymmetric
* Structural order is total (trichotomous)
* Order computation is deterministic
* No coordination needed for order determination
* Causal consistency preserved
* Round assignment is verifiable
* All nodes see same order
* Write latency bounded by VDF round time
* Hybrid consistency approach valid

## CAP Theorem Transcendence

The CAP theorem (Brewer 2000, Gilbert-Lynch 2002) states:
> Distributed systems cannot simultaneously guarantee
> Consistency, Availability, and Partition tolerance.

**CAP's "Consistency" = Linearizability (total ordering, instant visibility)**

We prove that most applications don't need linearizability. They need:
* Zero-latency writes ✓
* Partition tolerance ✓
* Always available ✓
* Proven convergence ✓

This is **Practical CAP**: All the properties that matter, formally verified.

CAP theorem is still true. Its constraints are just irrelevant for us.

## The Key Insight

```
Traditional TGP:     Alice ←── network ──→ Bob
                     C → D → T → Q (4 phases, latency)

Bilateral CRDT:      You ←── local ──→ CRDT
                     C=D=T=Q (1 computation, instant)
```

The CRDT IS the other general.
The merge function IS its signature.
Pure functions CANNOT disagree with themselves.

## Comparison

| Property | Traditional CRDT | Bilateral CRDT |
|----------|-----------------|----------------|
| Network required | For sync | Never (offline-first) |
| Merge can fail | Possible | Impossible (total function) |
| Conflict resolution | LWW or custom | Rich semantic merge |
| Proof of operation | None | Self-certifying |
| TGP counterparty | Other peer | The CRDT itself |
| Coordination | Eventual | Immediate (local) |

## Theorems Summary

* **Basic**: 7 theorems proven
* **Bilateral**: 6 theorems proven
* **Convergence**: 8 theorems proven
* **TGPCollapse**: 10 theorems proven
* **PracticalCAP**: 10 theorems proven
* **StructuralLinearizability**: 26 theorems proven (RESEARCH)

**Total: 67 theorems**

Note: StructuralLinearizability proofs establish total order, spacetime coordinates,
partition tolerance, VDF integration, and Byzantine resistance properties.

## The Bottom Line

```lean
theorem the_bottom_line :
    zero_latency_writes ∧
    partition_tolerance ∧
    always_available ∧
    proven_convergence
```

**CAP is still true. It just doesn't matter anymore.**

*e cinere surgemus*
-/

import CitadelProofs.CRDT.Basic
import CitadelProofs.CRDT.Bilateral
import CitadelProofs.CRDT.Convergence
import CitadelProofs.CRDT.TGPCollapse
import CitadelProofs.CRDT.PracticalCAP
import CitadelProofs.CRDT.StructuralLinearizability
