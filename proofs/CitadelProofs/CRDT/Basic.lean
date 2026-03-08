/-
Copyright (c) 2025 Riff Labs. All rights reserved.
Released under AGPL-3.0-or-later license.
Authors: Wings@riff.cc (Riff Labs)

Bilateral CRDTs - The Merge Function as Counterparty
====================================================

This module proves the fundamental properties of Bilateral CRDTs:
the insight that pure, total merge functions create bilateral
construction without network coordination.

Key Insight: The CRDT itself is the "other general" in TGP.
The merge function's determinism IS the bilateral property.
-/

import Mathlib.Tactic

namespace CitadelProofs.CRDT

/-! ## Core Types -/

/-- Content identifier (Blake3 hash) -/
structure ContentId where
  hash : Fin (2^256)
  deriving DecidableEq, Repr

/-! ## Merge Function Properties -/

/-- A merge function is TOTAL: it always succeeds.
    This is the key property - no merge can fail. -/
class TotalMerge (α : Type*) where
  /-- Merge two states - ALWAYS succeeds, returns α not Option α -/
  merge : α → α → α

/-- A merge function is COMMUTATIVE -/
class CommutativeMerge (α : Type*) extends TotalMerge α where
  merge_comm : ∀ a b : α, merge a b = merge b a

/-- A merge function is ASSOCIATIVE -/
class AssociativeMerge (α : Type*) extends TotalMerge α where
  merge_assoc : ∀ a b c : α, merge (merge a b) c = merge a (merge b c)

/-- A merge function is IDEMPOTENT -/
class IdempotentMerge (α : Type*) extends TotalMerge α where
  merge_idem : ∀ a : α, merge a a = a

/-- A CRDT is a type with a total, commutative, associative, idempotent merge -/
class IsCRDT (α : Type*) extends CommutativeMerge α, AssociativeMerge α, IdempotentMerge α

/-! ## Pure Function Properties -/

/-- A function is DETERMINISTIC if same inputs → same outputs -/
def deterministic {α β : Type*} (f : α → β) : Prop :=
  ∀ x y : α, x = y → f x = f y

/-- THEOREM: All functions are deterministic (by definition of equality) -/
theorem all_functions_deterministic {α β : Type*} (f : α → β) :
    deterministic f := by
  intro x y h
  rw [h]

/-- A function is PURE if it has no side effects.
    In Lean, all functions are pure by construction. -/
def pure_function {α β : Type*} (_ : α → β) : Prop := True

/-- THEOREM: Merge is deterministic -/
theorem merge_deterministic {α : Type*} [TotalMerge α] (a b a' b' : α) :
    a = a' → b = b' → TotalMerge.merge a b = TotalMerge.merge a' b' := by
  intro ha hb
  rw [ha, hb]

/-! ## The Bilateral Property -/

/-- The bilateral property: if the merge function produces a result,
    that result is the SAME for all parties computing it.

    This is trivially true for pure functions but is the KEY insight:
    The determinism of the merge function IS the bilateral construction. -/
def bilateral_property {α : Type*} [TotalMerge α] (a b : α) : Prop :=
  ∀ (party1_result party2_result : α),
    party1_result = TotalMerge.merge a b →
    party2_result = TotalMerge.merge a b →
    party1_result = party2_result

/-- THEOREM: All CRDT merges have the bilateral property -/
theorem crdt_bilateral {α : Type*} [TotalMerge α] (a b : α) :
    bilateral_property a b := by
  intro r1 r2 h1 h2
  rw [h1, h2]

/-! ## Cannot Disagree -/

/-- A pure function cannot disagree with itself.
    If f(x) = y, then f(x) = y for all evaluations. -/
theorem pure_function_cannot_disagree {α β : Type*} (f : α → β) (x : α) :
    ∀ y1 y2 : β, y1 = f x → y2 = f x → y1 = y2 := by
  intro y1 y2 h1 h2
  rw [h1, h2]

/-- COROLLARY: Merge cannot disagree with itself -/
theorem merge_cannot_disagree {α : Type*} [TotalMerge α] (a b : α) :
    ∀ r1 r2 : α,
      r1 = TotalMerge.merge a b →
      r2 = TotalMerge.merge a b →
      r1 = r2 := by
  intro r1 r2 h1 h2
  rw [h1, h2]

/-! ## CRDT Operation Typeclass -/

/-- A CRDT with typed operations -/
class CRDTOp (α : Type*) (op : Type*) where
  /-- Apply an operation to a state -/
  apply : α → op → α

/-- A CRDT state with content addressing -/
class CRDTState (α : Type*) where
  /-- Get the content ID (hash) of a state -/
  contentId : α → ContentId

/-! ## Example CRDTs -/

/-- G-Counter: Grow-only counter with total merge (max) -/
structure GCounter where
  counts : Nat → Nat  -- Node ID → count

instance : TotalMerge GCounter where
  merge a b := { counts := fun id => max (a.counts id) (b.counts id) }

instance : CommutativeMerge GCounter where
  merge_comm a b := by
    simp only [TotalMerge.merge]
    congr 1
    funext id
    exact Nat.max_comm (a.counts id) (b.counts id)

instance : AssociativeMerge GCounter where
  merge_assoc a b c := by
    simp only [TotalMerge.merge]
    congr 1
    funext id
    exact Nat.max_assoc (a.counts id) (b.counts id) (c.counts id)

instance : IdempotentMerge GCounter where
  merge_idem a := by
    simp only [TotalMerge.merge]
    congr 1
    funext id
    exact Nat.max_self (a.counts id)

instance : IsCRDT GCounter := {}

/-- G-Set: Grow-only set with total merge (union) -/
structure GSet (α : Type*) where
  elements : List α

instance {α : Type*} [DecidableEq α] : TotalMerge (GSet α) where
  merge a b := { elements := a.elements ++ b.elements.filter (· ∉ a.elements) }

/-- THEOREM: GCounter merge is total (always succeeds) -/
theorem gcounter_merge_total (a b : GCounter) :
    ∃ c : GCounter, c = TotalMerge.merge a b := by
  exact ⟨TotalMerge.merge a b, rfl⟩

/-- THEOREM: GCounter merge is bilateral -/
theorem gcounter_bilateral (a b : GCounter) :
    bilateral_property a b := by
  exact crdt_bilateral a b

/-! ## Verification Summary -/

/-!
## Core Theorems Proven

1. `all_functions_deterministic` - Pure functions are deterministic by definition
2. `merge_deterministic` - CRDT merge is deterministic
3. `crdt_bilateral` - All CRDT merges have the bilateral property
4. `pure_function_cannot_disagree` - Pure functions cannot produce different outputs
5. `merge_cannot_disagree` - Merge cannot disagree with itself
6. `gcounter_merge_total` - GCounter merge always succeeds
7. `gcounter_bilateral` - GCounter merge is bilateral

## Key Insight

The BILATERAL PROPERTY is trivially true for pure functions.
This is not a weakness - it's the POINT:

The merge function's determinism IS the bilateral construction.
No network needed. No coordination needed. The math agrees with itself.

In TGP terms:
- C (Commitment): You propose an operation
- D (Double): Merge function "accepts" (it always does - total)
- T (Triple): You know merge accepted (you ran it)
- Q (Quaternary): Bilateral fixpoint (merge is deterministic, cannot disagree)

All four levels COLLAPSE into a single local computation.
-/

#check all_functions_deterministic
#check merge_deterministic
#check crdt_bilateral
#check pure_function_cannot_disagree
#check merge_cannot_disagree

end CitadelProofs.CRDT
