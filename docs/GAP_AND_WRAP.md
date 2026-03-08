# Gap-and-Wrap: Toroidal SPIRAL with Ghost Connections

## Overview

Gap-and-Wrap (GnW) extends SPIRAL with:
1. **Toroidal wrapping** - the mesh wraps in all 20 directions
2. **Ghost connections** - if expected neighbor is empty, connect to next occupied slot in that direction

This ensures every node has exactly 20 logical connections regardless of mesh density.

---

## The Problem GnW Solves

In a sparse mesh:
```
Occupied slots: [0, 1, 4, 7, 12, 15]
Empty slots:    [2, 3, 5, 6, 8, 9, 10, 11, 13, 14, ...]

Slot 0's theoretical neighbors: [1, 2, 3, 5, 6, 8, ...]
                                    ↑  ↑     ↑  ↑
                                  EMPTY slots!
```

Without GnW: Slot 0 only connects to occupied neighbors → fewer than 20 connections → degraded routing.

With GnW: Empty neighbor directions "jump" to next occupied → always 20 connections.

---

## How It Works

### Step 1: Compute Theoretical Neighbor

For slot S in direction D (one of 20 directions):
```
theoretical_neighbor(S, D) = SPIRAL formula for neighbor in direction D
```

### Step 2: Check Occupancy

```
if occupied(theoretical_neighbor(S, D)):
    connect(S, theoretical_neighbor(S, D))  # Normal connection
else:
    # Gap-and-wrap: find next occupied in direction D
    ghost_target = next_occupied_in_direction(S, D)
    connect(S, ghost_target)  # Ghost connection
```

### Step 3: Toroidal Wrap

`next_occupied_in_direction(S, D)` walks direction D, wrapping toroidally:
```
current = theoretical_neighbor(S, D)
while not occupied(current):
    current = theoretical_neighbor(current, D)  # Keep walking
    if current == S:
        break  # Wrapped all the way around, no neighbor in this direction
return current
```

---

## Properties

### Invariant 1: 20 Logical Connections (or fewer if mesh < 20 nodes)

Every node has exactly min(20, mesh_size - 1) connections.

### Invariant 2: Bidirectional Ghost Connections

If A has ghost connection to B in direction D:
- B has ghost connection to A in direction opposite(D)

### Invariant 3: Routing Preservation

Routing "go in direction D" still works:
- Normal connection: one hop
- Ghost connection: one hop (spans gap transparently)

### Invariant 4: Self-Healing

When node X dies:
- X's neighbors in direction D now see gap
- They re-resolve to next occupied → connections heal automatically

---

## Lean Proof Sketch

```lean
/-- A direction in the 20-neighbor topology -/
inductive Direction where
  | planar : Fin 6 → Direction      -- 6 planar directions
  | vertical : Bool → Direction      -- up/down
  | extended : Fin 6 → Bool → Direction  -- 12 diagonal

/-- The opposite direction -/
def Direction.opposite : Direction → Direction
  | planar i => planar ((i + 3) % 6)
  | vertical up => vertical (!up)
  | extended i up => extended ((i + 3) % 6) (!up)

/-- Theoretical neighbor in direction D -/
def theoreticalNeighbor (slot : Nat) (d : Direction) : Nat := ...

/-- Next occupied slot in direction D, wrapping toroidally -/
def nextOccupied (occupied : Finset Nat) (slot : Nat) (d : Direction) : Option Nat := ...

/-- Ghost connection target -/
def ghostTarget (occupied : Finset Nat) (slot : Nat) (d : Direction) : Option Nat :=
  let theoretical := theoreticalNeighbor slot d
  if theoretical ∈ occupied then
    some theoretical
  else
    nextOccupied occupied slot d

/-- Theorem: Ghost connections are bidirectional -/
theorem ghost_bidirectional (occupied : Finset Nat) (a b : Nat) (d : Direction)
    (ha : a ∈ occupied) (hb : b ∈ occupied)
    (h : ghostTarget occupied a d = some b) :
    ghostTarget occupied b d.opposite = some a := by
  sorry  -- To prove

/-- Theorem: Every occupied node has connection in each direction (if mesh > 1) -/
theorem full_connectivity (occupied : Finset Nat) (slot : Nat)
    (h_occ : slot ∈ occupied) (h_size : occupied.card > 1) (d : Direction) :
    ∃ target, ghostTarget occupied slot d = some target := by
  sorry  -- To prove

/-- Theorem: Connections are symmetric -/
theorem connections_symmetric (occupied : Finset Nat) (a b : Nat)
    (h : ∃ d, ghostTarget occupied a d = some b) :
    ∃ d', ghostTarget occupied b d' = some a := by
  sorry  -- To prove
```

---

## Implementation Plan

### Phase 1: Lean Proofs (proofs/CitadelProofs/GapAndWrap.lean)

1. Define `Direction` enum (20 directions)
2. Define `theoreticalNeighbor : Nat → Direction → Nat`
3. Define `nextOccupied : Finset Nat → Nat → Direction → Option Nat`
4. Define `ghostTarget` combining the above
5. Prove `ghost_bidirectional`
6. Prove `full_connectivity`
7. Prove `connections_symmetric`

### Phase 2: Rust Implementation (crates/citadel-lens/src/spiral.rs)

1. Add `Direction` enum
2. Add `theoretical_neighbor(slot, direction) -> slot`
3. Add `next_occupied(occupied, slot, direction) -> Option<slot>`
4. Add `ghost_target(occupied, slot, direction) -> Option<slot>`
5. Add `compute_all_connections(occupied, slot) -> Vec<(Direction, Slot)>`

### Phase 3: Mesh Integration (crates/citadel-lens/src/mesh.rs)

1. Replace static neighbor lookup with dynamic GnW
2. On node join: recompute affected ghost connections
3. On node leave: recompute affected ghost connections
4. Store connection type: `Normal(slot)` or `Ghost(slot, gap_size)`

### Phase 4: Routing

1. Routing uses directions, not specific slots
2. "Forward in direction D" → use current connection for D
3. Works identically for normal and ghost connections

---

## Example Walkthrough

Mesh state: slots [0, 1, 7, 15] occupied

### Slot 0's Connections

```
Direction 0 (planar): theoretical = 1, occupied → Normal(1)
Direction 1 (planar): theoretical = 2, empty → walk → find 7 → Ghost(7)
Direction 2 (planar): theoretical = 3, empty → walk → find 15 → Ghost(15)
...
```

### Node 7 Leaves

Before: Slot 0 has Ghost(7) in direction 1
After:  Slot 0 recomputes → finds 15 in direction 1 → Ghost(15)

Self-healing: no orphaned connections.

---

## Relationship to Liveness

Ghost connections enable liveness monitoring:
- You always have connections to monitor
- Even in sparse mesh, you have 20 neighbors to exchange proofs with
- Node failure → ghost connections heal → monitoring continues

This is prerequisite for the VDF-based liveness system.

---

## Open Questions

1. **Maximum gap size**: Should we cap how far a ghost connection can span?
2. **Connection priority**: When multiple nodes could satisfy a direction, which wins?
3. **Blinded routing**: How does GnW interact with the privacy modes?

---

*e cinere surgemus*
