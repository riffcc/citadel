# Citadel Proofs

Lean 4 formal verification for Citadel.

## File Tree

```
CitadelProofs/
├── Topology.lean                    # HexCoord, 20 neighbors, metric space
├── Spiral3D.lean                    # 3D coordinate extension
├── Constitutional.lean              # Four branches, attack surface, PoD, Nash
├── CVDF.lean                        # Chain weight, attestation, merge
├── VdfRace.lean                     # VDF chain, priority ordering
├── FLPBypass.lean                   # Threshold consensus
├── Convergence.lean                 # Slot occupancy, JOIN, self-healing
├── ProofOfLatency.lean              # Latency trump, atomic swap
├── MeshProtocol.lean                # Race resolution, scaling ladder, first_empty_slot
├── TwoHopKnowledge.lean             # Mix/Smart/Full modes
├── EmergentOmniscience.lean         # Local → global knowledge
├── Spore.lean                       # XOR sync
├── Broadcast.lean                   # Turn-left algorithm
├── FailureDetectorElimination.lean  # TwoGen
└── Transfer.lean                    # State transfer
```

## Progressive Disclosure

### Level 1: Results
Read `CitadelProofs.lean` module docstring.

### Level 2: Mechanism
1. Topology.lean - Hex coordinates, 20 neighbors
2. Constitutional.lean - Four branches
3. CVDF.lean - Chain weight
4. Convergence.lean - Self-assembly

### Level 3: Specific claims
Use the proof status tables below.

### Level 4: Extend
Pick a `sorry` from the incomplete table, fill in the proof.

## Proof Status

### Complete

| Theorem | File |
|---------|------|
| `allConnections_length` | Topology.lean |
| `branch_exclusive_action` | Constitutional.lean |
| `no_cross_branch_action` | Constitutional.lean |
| `attack_probability_bound` | Constitutional.lean |
| `collaboration_dominates` | Constitutional.lean |
| `concentration_is_capped` | Constitutional.lean |
| `distributed_optimal` | Constitutional.lean |
| `nash_equilibrium_is_honest` | Constitutional.lean |
| `priority_irreflexive` | VdfRace.lean |
| `priority_asymmetric` | VdfRace.lean |
| `priority_transitive` | VdfRace.lean |
| `priority_total` | VdfRace.lean |
| `flp_bypass` | FLPBypass.lean |
| `direction_exclusive` | Convergence.lean |
| `pareto_symmetric` | ProofOfLatency.lean |
| `halflock_reversible` | ProofOfLatency.lean |
| `bilateral_commutative` | ProofOfLatency.lean |
| `merge_takes_heavier` | CVDF.lean |
| `heavier_survives_merge` | CVDF.lean |
| `no_wasted_work` | CVDF.lean |
| `race_priority_deterministic` | MeshProtocol.lean |
| `race_priority_total` | MeshProtocol.lean |
| `race_winner_unique` | MeshProtocol.lean |
| `threshold_le_neighbors` | MeshProtocol.lean |
| `threshold_pos` | MeshProtocol.lean |
| `first_empty_slot_unoccupied` | MeshProtocol.lean |
| `first_empty_slot_minimal` | MeshProtocol.lean |
| `trump_pareto` | MeshProtocol.lean |
| `pod_cap_limits_concentration` | MeshProtocol.lean |

### Incomplete (has sorry)

| Theorem | File |
|---------|------|
| `slot_occupancy_unique` | Convergence.lean |
| `join_terminates` | Convergence.lean |
| `join_valid` | Convergence.lean |
| `pretender_insufficient` | Convergence.lean |
| `self_healing` | Convergence.lean |
| `bootstrap_produces_unique_slots` | VdfRace.lean |
| `chain_weight_monotonic` | CVDF.lean |
| `collaboration_wins` | CVDF.lean |
| `distance_to_planar_neighbor` | Topology.lean |
| `hex_sum_even` | Topology.lean |

### TODO

- Eclipse detection
- Zipper merge with PoD-capped attestation weight

## Key Formulas

| Concept | Formula | Status |
|---------|---------|--------|
| Attack probability | 0.51⁴ ≈ 6.8% | ✅ Proven |
| Quorum threshold | 2f + 1 from 3f + 1 | ✅ Proven |
| Connection count | 6 + 2 + 12 = 20 | ✅ Proven |
| Chain weight | Σ(1 + attestations) | ⚠️ Monotonicity has sorry |
| Scaling threshold | ceil(n × 11/20) | ✅ Proven |
| Effective contribution | min(compute, diffusion_cap) | ✅ Proven |

## Build

```bash
lake build
```

## Related

- `spiral/proofs/` - SPIRAL shell formulas, enumeration
- `citadel/docs/MESH_PROTOCOL.md` - Mesh protocol spec
- `citadel/docs/CONSTITUTIONAL_P2P.md` - Design doc
