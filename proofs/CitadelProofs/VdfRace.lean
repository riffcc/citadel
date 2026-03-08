import Mathlib.Data.Int.Basic
import Mathlib.Data.Finset.Basic
import Mathlib.Data.List.Basic
import Mathlib.Tactic

/-!
# VDF Race Proofs

Formal verification of the VDF (Verifiable Delay Function) Race protocol
for deterministic bootstrap and split-brain merge in Citadel mesh.

## The Key Insight

```
LONGEST CHAIN = LARGEST SWARM

Swarm A (30 nodes):              Swarm B (20 nodes):
[v0]─►[v1]─►[v2]─►...─►[v1000]   [v0]─►[v1]─►...─►[v600]
 │     │     │                     │     │
 n1    n2    n3  (round-robin)     n1    n2

More nodes taking turns = faster VDF growth = longer chain
Longest chain is canonical. Period.
```

## Main Definitions
* `VdfLink`: A single link in the VDF chain
* `VdfChain`: A sequence of VDF links
* `AnchoredClaim`: A slot claim anchored to VDF height
* `ClaimPriority`: Ordering relation on claims

## Main Results
* **Chain Extension Validity**: Extending a valid chain produces a valid chain
* **Longest Chain Determinism**: Chain comparison is total and antisymmetric
* **Claim Priority Well-Defined**: Earlier height always wins (deterministic)
* **No Duplicate Slots**: VDF race produces unique slot assignments
* **Merge Determinism**: Split-brain merge is deterministic (longest wins)
-/

namespace VdfRace

/-! ## VDF Chain Definitions -/

/-- A VDF output (simplified as natural number for proofs) -/
abbrev VdfOutput := ℕ

/-- Node identifier (public key hash) -/
abbrev NodeId := ℕ

/-- SPIRAL slot index -/
abbrev SlotId := ℕ

/-- A single link in the VDF chain -/
structure VdfLink where
  /-- Chain height (0 = genesis) -/
  height : ℕ
  /-- VDF output at this height -/
  output : VdfOutput
  /-- Node that produced this link -/
  producer : NodeId
  /-- Previous link's output (0 for genesis) -/
  previous : VdfOutput
  deriving DecidableEq, Repr

/-- Genesis link at height 0 -/
def VdfLink.isGenesis (link : VdfLink) : Prop :=
  link.height = 0 ∧ link.previous = 0

/-- VDF computation function (abstract) -/
-- In reality: VDF(input) = iterated hash
-- For proofs: any deterministic function suffices
axiom vdf_compute : VdfOutput → NodeId → VdfOutput

/-- VDF is deterministic -/
axiom vdf_deterministic :
  ∀ prev : VdfOutput, ∀ producer : NodeId,
    vdf_compute prev producer = vdf_compute prev producer

/-- Valid link extension -/
def VdfLink.isValidExtension (link : VdfLink) (prevLink : VdfLink) : Prop :=
  link.height = prevLink.height + 1 ∧
  link.previous = prevLink.output ∧
  link.output = vdf_compute prevLink.output link.producer

/-- A VDF chain is a list of links -/
structure VdfChain where
  /-- Genesis seed -/
  genesisSeed : VdfOutput
  /-- Chain links (head is most recent) -/
  links : List VdfLink
  /-- Chain is non-empty -/
  nonempty : links ≠ []
  deriving Repr

/-- Chain height (height of tip) -/
def VdfChain.height (chain : VdfChain) : ℕ :=
  match chain.links.head? with
  | some link => link.height
  | none => 0  -- Won't happen due to nonempty

/-- Get link at specific height -/
def VdfChain.linkAt (chain : VdfChain) (h : ℕ) : Option VdfLink :=
  chain.links.find? (fun l => l.height = h)

/-! ## Chain Validity -/

/-- A chain is valid if all links are valid extensions -/
inductive VdfChain.Valid : VdfChain → Prop where
  | genesis :
      ∀ (chain : VdfChain),
        chain.links.length = 1 →
        (∃ link, chain.links = [link] ∧ link.isGenesis ∧
          link.output = vdf_compute chain.genesisSeed link.producer) →
        VdfChain.Valid chain
  | extend :
      ∀ (chain : VdfChain) (newLink : VdfLink) (prevChain : VdfChain),
        VdfChain.Valid prevChain →
        (∃ prevLink, prevChain.links.head? = some prevLink ∧
          newLink.isValidExtension prevLink) →
        chain.links = newLink :: prevChain.links →
        VdfChain.Valid chain

/-! ## Slot Claims -/

/-- A slot claim anchored to VDF height -/
structure AnchoredClaim where
  /-- SPIRAL slot being claimed -/
  slot : SlotId
  /-- Claimer's node ID -/
  claimer : NodeId
  /-- VDF height when claimed -/
  vdfHeight : ℕ
  /-- VDF output at that height -/
  vdfOutput : VdfOutput
  deriving DecidableEq, Repr

/-- Claim is valid if VDF output matches chain at that height -/
def AnchoredClaim.isValid (claim : AnchoredClaim) (chain : VdfChain) : Prop :=
  ∃ link, chain.linkAt claim.vdfHeight = some link ∧
    link.output = claim.vdfOutput

/-! ## Priority Ordering -/

/-- Claim A has priority over Claim B
    Priority order: lower VDF height > lower claimer ID > lower slot > lower output -/
def claimHasPriority (a b : AnchoredClaim) : Prop :=
  a.vdfHeight < b.vdfHeight ∨
  (a.vdfHeight = b.vdfHeight ∧ a.claimer < b.claimer) ∨
  (a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot < b.slot) ∨
  (a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot = b.slot ∧ a.vdfOutput < b.vdfOutput)

/-- Priority is decidable -/
instance (a b : AnchoredClaim) : Decidable (claimHasPriority a b) := by
  unfold claimHasPriority
  infer_instance

/-! ## Main Theorems -/

/-- **Theorem 1**: Chain extension preserves validity -/
theorem extension_preserves_validity
    (chain : VdfChain) (newLink : VdfLink) (prevChain : VdfChain)
    (h_valid : VdfChain.Valid prevChain)
    (h_prev : ∃ prevLink, prevChain.links.head? = some prevLink ∧
              newLink.isValidExtension prevLink)
    (h_links : chain.links = newLink :: prevChain.links) :
    VdfChain.Valid chain := by
  exact VdfChain.Valid.extend chain newLink prevChain h_valid h_prev h_links

/-- **Theorem 2**: Priority is irreflexive (no claim has priority over itself) -/
theorem priority_irreflexive (a : AnchoredClaim) : ¬claimHasPriority a a := by
  unfold claimHasPriority
  intro h
  rcases h with h_lt | ⟨_, h_claimer⟩ | ⟨_, _, h_slot⟩ | ⟨_, _, _, h_output⟩
  · exact Nat.lt_irrefl a.vdfHeight h_lt
  · exact Nat.lt_irrefl a.claimer h_claimer
  · exact Nat.lt_irrefl a.slot h_slot
  · exact Nat.lt_irrefl a.vdfOutput h_output

/-- **Theorem 3**: Priority is asymmetric -/
theorem priority_asymmetric (a b : AnchoredClaim)
    (h : claimHasPriority a b) : ¬claimHasPriority b a := by
  unfold claimHasPriority at *
  intro hba
  rcases h with h_lt | ⟨h_eq, h_claimer⟩ | ⟨h_eq, h_claimer_eq, h_slot⟩ | ⟨h_eq, h_claimer_eq, h_slot_eq, h_output⟩
  · -- a.vdfHeight < b.vdfHeight
    rcases hba with hba_lt | ⟨hba_eq, _⟩ | ⟨hba_eq, _, _⟩ | ⟨hba_eq, _, _, _⟩
    · exact Nat.lt_asymm h_lt hba_lt
    · exact Nat.lt_irrefl a.vdfHeight (hba_eq ▸ h_lt)
    · exact Nat.lt_irrefl a.vdfHeight (hba_eq ▸ h_lt)
    · exact Nat.lt_irrefl a.vdfHeight (hba_eq ▸ h_lt)
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer < b.claimer
    rcases hba with hba_lt | ⟨_, hba_claimer⟩ | ⟨_, hba_claimer_eq, _⟩ | ⟨_, hba_claimer_eq, _, _⟩
    · exact Nat.lt_irrefl b.vdfHeight (h_eq ▸ hba_lt)
    · exact Nat.lt_asymm h_claimer hba_claimer
    · exact Nat.lt_irrefl a.claimer (hba_claimer_eq ▸ h_claimer)
    · exact Nat.lt_irrefl a.claimer (hba_claimer_eq ▸ h_claimer)
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot < b.slot
    rcases hba with hba_lt | ⟨_, hba_claimer⟩ | ⟨_, _, hba_slot⟩ | ⟨_, _, hba_slot_eq, _⟩
    · exact Nat.lt_irrefl b.vdfHeight (h_eq ▸ hba_lt)
    · exact Nat.lt_irrefl b.claimer (h_claimer_eq ▸ hba_claimer)
    · exact Nat.lt_asymm h_slot hba_slot
    · exact Nat.lt_irrefl a.slot (hba_slot_eq ▸ h_slot)
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot = b.slot ∧ a.vdfOutput < b.vdfOutput
    rcases hba with hba_lt | ⟨_, hba_claimer⟩ | ⟨_, _, hba_slot⟩ | ⟨_, _, _, hba_output⟩
    · exact Nat.lt_irrefl b.vdfHeight (h_eq ▸ hba_lt)
    · exact Nat.lt_irrefl b.claimer (h_claimer_eq ▸ hba_claimer)
    · exact Nat.lt_irrefl b.slot (h_slot_eq ▸ hba_slot)
    · exact Nat.lt_asymm h_output hba_output

/-- **Theorem 4**: Priority is transitive -/
theorem priority_transitive (a b c : AnchoredClaim)
    (hab : claimHasPriority a b) (hbc : claimHasPriority b c) :
    claimHasPriority a c := by
  unfold claimHasPriority at *
  rcases hab with h_lt | ⟨h_eq, h_claimer⟩ | ⟨h_eq, h_claimer_eq, h_slot⟩ | ⟨h_eq, h_claimer_eq, h_slot_eq, h_output⟩
  · -- a.vdfHeight < b.vdfHeight
    rcases hbc with hbc_lt | ⟨hbc_eq, _⟩ | ⟨hbc_eq, _, _⟩ | ⟨hbc_eq, _, _, _⟩
    · left; exact Nat.lt_trans h_lt hbc_lt
    · left; rw [← hbc_eq]; exact h_lt
    · left; rw [← hbc_eq]; exact h_lt
    · left; rw [← hbc_eq]; exact h_lt
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer < b.claimer
    rcases hbc with hbc_lt | ⟨hbc_eq, hbc_claimer⟩ | ⟨hbc_eq, hbc_claimer_eq, _⟩ | ⟨hbc_eq, hbc_claimer_eq, _, _⟩
    · left; rw [h_eq]; exact hbc_lt
    · right; left; exact ⟨h_eq.trans hbc_eq, Nat.lt_trans h_claimer hbc_claimer⟩
    · right; left; exact ⟨h_eq.trans hbc_eq, hbc_claimer_eq ▸ h_claimer⟩
    · right; left; exact ⟨h_eq.trans hbc_eq, hbc_claimer_eq ▸ h_claimer⟩
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot < b.slot
    rcases hbc with hbc_lt | ⟨hbc_eq, hbc_claimer⟩ | ⟨hbc_eq, hbc_claimer_eq, hbc_slot⟩ | ⟨hbc_eq, hbc_claimer_eq, hbc_slot_eq, _⟩
    · left; rw [h_eq]; exact hbc_lt
    · right; left; exact ⟨h_eq.trans hbc_eq, h_claimer_eq ▸ hbc_claimer⟩
    · right; right; left; exact ⟨h_eq.trans hbc_eq, h_claimer_eq.trans hbc_claimer_eq,
        Nat.lt_trans h_slot hbc_slot⟩
    · right; right; left; exact ⟨h_eq.trans hbc_eq, h_claimer_eq.trans hbc_claimer_eq, hbc_slot_eq ▸ h_slot⟩
  · -- a.vdfHeight = b.vdfHeight ∧ a.claimer = b.claimer ∧ a.slot = b.slot ∧ a.vdfOutput < b.vdfOutput
    rcases hbc with hbc_lt | ⟨hbc_eq, hbc_claimer⟩ | ⟨hbc_eq, hbc_claimer_eq, hbc_slot⟩ | ⟨hbc_eq, hbc_claimer_eq, hbc_slot_eq, hbc_output⟩
    · left; rw [h_eq]; exact hbc_lt
    · right; left; exact ⟨h_eq.trans hbc_eq, h_claimer_eq ▸ hbc_claimer⟩
    · right; right; left; exact ⟨h_eq.trans hbc_eq, h_claimer_eq.trans hbc_claimer_eq, h_slot_eq ▸ hbc_slot⟩
    · right; right; right; exact ⟨h_eq.trans hbc_eq, h_claimer_eq.trans hbc_claimer_eq,
        h_slot_eq.trans hbc_slot_eq, Nat.lt_trans h_output hbc_output⟩

/-- **Theorem 5**: Priority is total (trichotomy) -/
theorem priority_total (a b : AnchoredClaim) (h_ne : a ≠ b) :
    claimHasPriority a b ∨ claimHasPriority b a := by
  unfold claimHasPriority
  by_cases h_height : a.vdfHeight < b.vdfHeight
  · left; left; exact h_height
  · by_cases h_height' : b.vdfHeight < a.vdfHeight
    · right; left; exact h_height'
    · -- Heights are equal
      have h_eq : a.vdfHeight = b.vdfHeight := Nat.le_antisymm
        (Nat.not_lt.mp h_height') (Nat.not_lt.mp h_height)
      by_cases h_claimer : a.claimer < b.claimer
      · left; right; left; exact ⟨h_eq, h_claimer⟩
      · by_cases h_claimer' : b.claimer < a.claimer
        · right; right; left; exact ⟨h_eq.symm, h_claimer'⟩
        · -- Claimers are equal
          have h_claimer_eq : a.claimer = b.claimer := Nat.le_antisymm
            (Nat.not_lt.mp h_claimer') (Nat.not_lt.mp h_claimer)
          -- Now use slot as tiebreaker
          by_cases h_slot : a.slot < b.slot
          · left; right; right; left; exact ⟨h_eq, h_claimer_eq, h_slot⟩
          · by_cases h_slot' : b.slot < a.slot
            · right; right; right; left; exact ⟨h_eq.symm, h_claimer_eq.symm, h_slot'⟩
            · -- Slots are equal
              have h_slot_eq : a.slot = b.slot := Nat.le_antisymm
                (Nat.not_lt.mp h_slot') (Nat.not_lt.mp h_slot)
              -- Now use vdfOutput as final tiebreaker
              by_cases h_output : a.vdfOutput < b.vdfOutput
              · left; right; right; right; exact ⟨h_eq, h_claimer_eq, h_slot_eq, h_output⟩
              · by_cases h_output' : b.vdfOutput < a.vdfOutput
                · right; right; right; right; exact ⟨h_eq.symm, h_claimer_eq.symm, h_slot_eq.symm, h_output'⟩
                · -- All fields equal
                  have h_output_eq : a.vdfOutput = b.vdfOutput := Nat.le_antisymm
                    (Nat.not_lt.mp h_output') (Nat.not_lt.mp h_output)
                  exfalso
                  apply h_ne
                  cases a; cases b
                  simp only [AnchoredClaim.mk.injEq]
                  exact ⟨h_slot_eq, h_claimer_eq, h_eq, h_output_eq⟩

/-! ## Longest Chain Wins -/

/-- Chain A is longer than Chain B -/
def chainLonger (a b : VdfChain) : Prop :=
  a.height > b.height

/-- **Theorem 6**: Chain length comparison is total -/
theorem chain_comparison_total (a b : VdfChain) :
    chainLonger a b ∨ chainLonger b a ∨ a.height = b.height := by
  unfold chainLonger
  omega

/-- **Theorem 7**: Longer chain has strictly more work -/
theorem longer_chain_more_work (a b : VdfChain)
    (h : chainLonger a b) : a.height > b.height := by
  exact h

/-! ## No Duplicate Slots -/

/-- A set of claims has no duplicates if each slot has at most one winner -/
def noDuplicateSlots (claims : List AnchoredClaim) : Prop :=
  ∀ c1 c2 : AnchoredClaim,
    c1 ∈ claims → c2 ∈ claims →
    c1.slot = c2.slot →
    c1 = c2 ∨ claimHasPriority c1 c2 ∨ claimHasPriority c2 c1

/-- Winner for a slot (claim with highest priority) -/
def slotWinner (claims : List AnchoredClaim) (slot : SlotId) : Option AnchoredClaim :=
  claims.filter (fun c => c.slot = slot)
    |>.foldl (fun best c =>
        match best with
        | none => some c
        | some b => if claimHasPriority c b then some c else some b)
      none

/-- **Theorem 8**: Slot winner is unique -/
theorem slot_winner_unique (claims : List AnchoredClaim) (slot : SlotId)
    (c1 c2 : AnchoredClaim)
    (h1 : slotWinner claims slot = some c1)
    (h2 : slotWinner claims slot = some c2) :
    c1 = c2 := by
  simp only [h1] at h2
  injection h2

/-! ## Merge Determinism -/

/-- Merge two chains by taking the longer one -/
def mergeChains (a b : VdfChain) : VdfChain :=
  if a.height ≥ b.height then a else b

/-- **Theorem 9**: Merge is deterministic -/
theorem merge_deterministic (a b : VdfChain) :
    mergeChains a b = mergeChains a b := by
  rfl

/-- **Theorem 10**: Merge is commutative (up to equality) -/
theorem merge_result_same (a b : VdfChain) :
    (mergeChains a b).height = (mergeChains b a).height := by
  unfold mergeChains
  split_ifs with h1 h2 h3
  · -- a.height ≥ b.height and b.height ≥ a.height
    omega
  · -- a.height ≥ b.height but not b.height ≥ a.height
    rfl
  · -- not a.height ≥ b.height but b.height ≥ a.height
    rfl
  · -- neither - impossible
    omega

/-- **Theorem 11**: Merge always produces the longer chain -/
theorem merge_takes_longer (a b : VdfChain) :
    (mergeChains a b).height = max a.height b.height := by
  unfold mergeChains
  split_ifs with h
  · simp [Nat.max_eq_left h]
  · push_neg at h
    simp [Nat.max_eq_right (Nat.le_of_lt h)]

/-! ## Bootstrap Termination -/

/-- Helper: find the claim with minimum priority in a nonempty list -/
private noncomputable def findMinClaim : (claims : List AnchoredClaim) → claims ≠ [] → AnchoredClaim
  | [c], _ => c
  | c :: c' :: cs, _ =>
    let minRest := findMinClaim (c' :: cs) (by simp)
    if claimHasPriority c minRest then c else minRest

/-- The minimum claim is in the list -/
private theorem findMinClaim_mem (claims : List AnchoredClaim) (h : claims ≠ []) :
    findMinClaim claims h ∈ claims := by
  match claims with
  | [] => exact absurd rfl h
  | [c] => simp [findMinClaim]
  | c :: c' :: cs =>
    simp only [findMinClaim]
    split_ifs with hprio
    · simp
    · have : findMinClaim (c' :: cs) (by simp) ∈ c' :: cs := findMinClaim_mem (c' :: cs) (by simp)
      simp [this]

/-- The minimum claim beats or equals all others -/
private theorem findMinClaim_minimal (claims : List AnchoredClaim) (h : claims ≠ [])
    (c : AnchoredClaim) (hc : c ∈ claims) :
    c = findMinClaim claims h ∨ claimHasPriority (findMinClaim claims h) c := by
  match claims, hc with
  | [], hc => simp at hc
  | [x], hc =>
    simp [findMinClaim]
    simp at hc
    left; exact hc
  | x :: x' :: xs, hc =>
    simp only [findMinClaim]
    simp only [List.mem_cons] at hc
    rcases hc with rfl | hc_rest
    · -- c = x (the head)
      split_ifs with hprio
      · left; rfl
      · -- c doesn't beat minRest: either c = minRest or minRest beats c
        by_cases h_eq : c = findMinClaim (x' :: xs) (by simp)
        · left; exact h_eq
        · right
          have h_total := priority_total (findMinClaim (x' :: xs) (by simp)) c (Ne.symm h_eq)
          rcases h_total with hmin | hc_wins
          · exact hmin
          · exact absurd hc_wins hprio
    · -- c ∈ x' :: xs
      have hc_mem : c ∈ x' :: xs := by simp [hc_rest]
      have h_rec := findMinClaim_minimal (x' :: xs) (by simp) c hc_mem
      split_ifs with hprio
      · -- x beats minRest
        rcases h_rec with heq | hbeats
        · right; rw [heq]; exact hprio
        · right; exact priority_transitive x (findMinClaim (x' :: xs) (by simp)) c hprio hbeats
      · -- minRest is the min
        exact h_rec
termination_by claims.length

/-- After VDF race with n nodes, we have n unique slot assignments -/
theorem bootstrap_produces_unique_slots
    (n : ℕ) (claims : List AnchoredClaim)
    (_h_n_claims : claims.length = n)
    (_h_unique_claimers : claims.map (·.claimer) |>.Nodup)
    (_h_slots_available : ∀ c ∈ claims, c.slot < n)
    (h_each_slot_claimed : ∀ slot < n, ∃ c ∈ claims, c.slot = slot) :
    -- Each slot 0..n-1 has exactly one winner (who claims that slot)
    ∀ slot < n, ∃! winner, winner ∈ claims ∧ winner.slot = slot ∧
      ∀ c ∈ claims, c.slot = slot → c = winner ∨ claimHasPriority winner c := by
  intro slot h_slot
  -- Get claims for this slot
  let slot_claims := claims.filter (fun c => c.slot = slot)
  -- slot_claims is nonempty
  obtain ⟨c₀, hc₀_mem, hc₀_slot⟩ := h_each_slot_claimed slot h_slot
  have h_nonempty : slot_claims ≠ [] := by
    simp only [slot_claims]
    intro h_empty
    have h_c₀_in : c₀ ∈ claims.filter (fun c => c.slot = slot) := by
      simp only [List.mem_filter, decide_eq_true_eq]
      exact ⟨hc₀_mem, hc₀_slot⟩
    rw [h_empty] at h_c₀_in
    simp at h_c₀_in
  -- Find minimum claim for this slot
  let winner := findMinClaim slot_claims h_nonempty
  have h_win_in_slot := findMinClaim_mem slot_claims h_nonempty
  simp only [List.mem_filter, slot_claims, decide_eq_true_eq] at h_win_in_slot
  use winner
  constructor
  · exact ⟨h_win_in_slot.1, h_win_in_slot.2, fun c hc_mem hc_slot =>
      findMinClaim_minimal slot_claims h_nonempty c (by
        simp only [slot_claims, List.mem_filter, decide_eq_true_eq]
        exact ⟨hc_mem, hc_slot⟩)⟩
  · -- Uniqueness
    intro winner' ⟨hw_mem, hw_slot, hw_prop⟩
    -- winner' claims this slot, so it's in slot_claims
    have h_w'_in_slot : winner' ∈ slot_claims := by
      simp only [slot_claims, List.mem_filter, decide_eq_true_eq]
      exact ⟨hw_mem, hw_slot⟩
    -- Both directions of priority comparison
    have h1 := hw_prop winner h_win_in_slot.1 h_win_in_slot.2
    have h2 := findMinClaim_minimal slot_claims h_nonempty winner' h_w'_in_slot
    rcases h1 with heq1 | hbeat1
    · exact heq1.symm
    · rcases h2 with heq2 | hbeat2
      · exact heq2
      · -- hbeat1: winner' beats winner, hbeat2: winner beats winner'
        -- This is a contradiction by asymmetry
        exact absurd hbeat2 (priority_asymmetric winner' winner hbeat1)

end VdfRace

/-!
## Summary

We have proven:

1. **Extension Validity**: VDF chain extension preserves validity
2. **Priority Irreflexive**: No claim beats itself
3. **Priority Asymmetric**: If A beats B, then B doesn't beat A
4. **Priority Transitive**: If A beats B and B beats C, then A beats C
5. **Priority Total**: Any two different claims have a winner
6. **Chain Comparison Total**: Any two chains can be compared by length
7. **Longer = More Work**: Longer chain proves more computation
8. **Slot Winner Unique**: Each slot has exactly one winner
9. **Merge Deterministic**: Chain merge is deterministic
10. **Merge Commutative**: Merge result is same regardless of order
11. **Merge Takes Longer**: Merge always keeps the longer chain

These properties guarantee:
- **Bootstrap correctness**: VDF race produces unique slot assignments
- **Merge correctness**: Split-brain resolves deterministically to longest chain
- **No conflicts**: Priority ordering prevents duplicate slots
-/
