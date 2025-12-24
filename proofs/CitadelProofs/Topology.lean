import Mathlib.Data.Int.Basic
import Mathlib.Algebra.Group.Defs
import Mathlib.Tactic

-- Increase recursion depth for simp tactics in complex proofs
set_option maxRecDepth 10000

/-!
# Hexagonal Coordinate System

This file formalizes the hexagonal coordinate system used in the Citadel Mesh Topology.
We use cube coordinates (q, r, s) where q + r + s = 0.

## Main Definitions
* `HexCoord`: A structure representing a hexagonal coordinate with the constraint q + r + s = 0
* `distance`: The hexagonal distance function between two coordinates
* Neighbor functions: planar, vertical, and extended neighbors

## Main Results
* Distance forms a metric on the planar (q, r) space
* Every node has exactly 20 connections: 6 planar + 2 vertical + 12 extended
-/

/-- A hexagonal coordinate in cube coordinate system with the constraint q + r + s = 0.
    The z coordinate represents the vertical layer. -/
structure HexCoord where
  q : ℤ
  r : ℤ
  z : ℤ
  constraint : q + r + (-q - r) = 0 := by simp
  deriving DecidableEq, Repr

namespace HexCoord

/-- The s coordinate is derived from q and r to maintain q + r + s = 0 -/
def s (h : HexCoord) : ℤ := -h.q - h.r

/-- Constructor that automatically ensures the cube coordinate constraint -/
def make (q r z : ℤ) : HexCoord :=
  ⟨q, r, z, by simp⟩

/-- The origin hex coordinate -/
def origin : HexCoord := make 0 0 0

theorem s_eq_neg_q_r (h : HexCoord) : h.s = -h.q - h.r := rfl

theorem cube_constraint (h : HexCoord) : h.q + h.r + h.s = 0 := by
  simp only [s]
  ring

/-- Planar hexagonal distance between two coordinates (ignoring z) -/
def distance (a b : HexCoord) : ℕ :=
  (Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (a.s - b.s)) / 2

/-- The six planar neighbors in the hexagonal grid -/
def planarNeighbors (h : HexCoord) : List HexCoord :=
  [ make (h.q + 1) h.r h.z          -- East
  , make (h.q + 1) (h.r - 1) h.z    -- Northeast
  , make h.q (h.r - 1) h.z          -- Northwest
  , make (h.q - 1) h.r h.z          -- West
  , make (h.q - 1) (h.r + 1) h.z    -- Southwest
  , make h.q (h.r + 1) h.z          -- Southeast
  ]

/-- The two vertical neighbors (above and below) -/
def verticalNeighbors (h : HexCoord) : List HexCoord :=
  [ make h.q h.r (h.z + 1)  -- Above
  , make h.q h.r (h.z - 1)  -- Below
  ]

/-- The twelve extended neighbors (planar neighbors of vertical neighbors) -/
def extendedNeighbors (h : HexCoord) : List HexCoord :=
  let above := make h.q h.r (h.z + 1)
  let below := make h.q h.r (h.z - 1)
  planarNeighbors above ++ planarNeighbors below

/-- All 20 connections for a hex coordinate -/
def allConnections (h : HexCoord) : List HexCoord :=
  planarNeighbors h ++ verticalNeighbors h ++ extendedNeighbors h

-- Theorems about the structure

theorem planarNeighbors_length (h : HexCoord) :
  (planarNeighbors h).length = 6 := by rfl

theorem verticalNeighbors_length (h : HexCoord) :
  (verticalNeighbors h).length = 2 := by rfl

theorem extendedNeighbors_length (h : HexCoord) :
  (extendedNeighbors h).length = 12 := by
  unfold extendedNeighbors planarNeighbors
  simp

/-- The fundamental theorem: every node has exactly 20 connections -/
theorem allConnections_length (h : HexCoord) :
  (allConnections h).length = 20 := by
  unfold allConnections
  simp only [List.length_append, planarNeighbors_length, verticalNeighbors_length, extendedNeighbors_length]

-- Metric space properties

/-- Distance is non-negative (automatically satisfied by ℕ) -/
theorem distance_nonneg (a b : HexCoord) : 0 ≤ distance a b := Nat.zero_le _

/-- Identity: distance to self is zero -/
theorem distance_self (a : HexCoord) : distance a a = 0 := by
  unfold distance s
  simp

/-- Symmetry: distance is symmetric -/
theorem distance_symm (a b : HexCoord) : distance a b = distance b a := by
  unfold distance s
  congr 1
  -- |x - y| = |y - x| follows from |-(x-y)| = |x-y|
  have h1 : Int.natAbs (a.q - b.q) = Int.natAbs (b.q - a.q) := by
    rw [← Int.natAbs_neg (a.q - b.q)]
    ring_nf
  have h2 : Int.natAbs (a.r - b.r) = Int.natAbs (b.r - a.r) := by
    rw [← Int.natAbs_neg (a.r - b.r)]
    ring_nf
  have h3 : Int.natAbs (-a.q - a.r - (-b.q - b.r)) = Int.natAbs (-b.q - b.r - (-a.q - a.r)) := by
    rw [← Int.natAbs_neg (-a.q - a.r - (-b.q - b.r))]
    ring_nf
  omega

/-- Distance to planar neighbors is 1 -/
theorem distance_to_planar_neighbor (h : HexCoord) (n : HexCoord) :
  n ∈ planarNeighbors h → distance h n = 1 := by
  intro hn
  unfold planarNeighbors at hn
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hn
  -- Each of the 6 neighbors: check distance formula gives 1
  rcases hn with rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp only [distance, s, make] <;> omega

/-- Helper: sum of absolute values in hex distance is always even -/
private lemma hex_sum_even (q r : ℤ) :
    2 ∣ (Int.natAbs q + Int.natAbs r + Int.natAbs (-q - r)) := by
  -- Key insight: |-q-r| = |q+r|, and the sum |q| + |r| + |q+r| is always even
  have h : Int.natAbs (-q - r) = Int.natAbs (q + r) := by
    rw [← Int.natAbs_neg]; ring_nf
  rw [h]
  -- Use omega to handle all the case analysis automatically
  omega

/-- Triangle inequality for hexagonal distance -/
theorem distance_triangle (a b c : HexCoord) :
  distance a c ≤ distance a b + distance b c := by
  unfold distance s
  -- Use triangle inequality: |x - z| ≤ |x - y| + |y - z| for each coordinate
  have hq : Int.natAbs (a.q - c.q) ≤ Int.natAbs (a.q - b.q) + Int.natAbs (b.q - c.q) := by
    calc Int.natAbs (a.q - c.q)
        = Int.natAbs ((a.q - b.q) + (b.q - c.q)) := by ring_nf
      _ ≤ Int.natAbs (a.q - b.q) + Int.natAbs (b.q - c.q) := Int.natAbs_add_le _ _
  have hr : Int.natAbs (a.r - c.r) ≤ Int.natAbs (a.r - b.r) + Int.natAbs (b.r - c.r) := by
    calc Int.natAbs (a.r - c.r)
        = Int.natAbs ((a.r - b.r) + (b.r - c.r)) := by ring_nf
      _ ≤ Int.natAbs (a.r - b.r) + Int.natAbs (b.r - c.r) := Int.natAbs_add_le _ _
  have hs : Int.natAbs (-a.q - a.r - (-c.q - c.r)) ≤
            Int.natAbs (-a.q - a.r - (-b.q - b.r)) + Int.natAbs (-b.q - b.r - (-c.q - c.r)) := by
    calc Int.natAbs (-a.q - a.r - (-c.q - c.r))
        = Int.natAbs ((-a.q - a.r - (-b.q - b.r)) + (-b.q - b.r - (-c.q - c.r))) := by ring_nf
      _ ≤ Int.natAbs (-a.q - a.r - (-b.q - b.r)) + Int.natAbs (-b.q - b.r - (-c.q - c.r)) :=
          Int.natAbs_add_le _ _
  -- Sum the inequalities
  have sum_ineq : Int.natAbs (a.q - c.q) + Int.natAbs (a.r - c.r) + Int.natAbs (-a.q - a.r - (-c.q - c.r)) ≤
      (Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (-a.q - a.r - (-b.q - b.r))) +
      (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) + Int.natAbs (-b.q - b.r - (-c.q - c.r))) := by
    omega
  -- The sums are even due to hex coordinate constraint, so division is exact
  -- Key: |-a.q - a.r - (-b.q - b.r)| = |-(a.q - b.q) - (a.r - b.r)| since the terms simplify
  have hab : 2 ∣ (Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) +
      Int.natAbs (-a.q - a.r - (-b.q - b.r))) := by
    have heq : -a.q - a.r - (-b.q - b.r) = -(a.q - b.q) - (a.r - b.r) := by ring
    rw [heq]
    exact hex_sum_even (a.q - b.q) (a.r - b.r)
  have hbc : 2 ∣ (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) +
      Int.natAbs (-b.q - b.r - (-c.q - c.r))) := by
    have heq : -b.q - b.r - (-c.q - c.r) = -(b.q - c.q) - (b.r - c.r) := by ring
    rw [heq]
    exact hex_sum_even (b.q - c.q) (b.r - c.r)
  -- When 2 | a and 2 | b, (a + b) / 2 = a / 2 + b / 2
  have hdiv : ((Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (-a.q - a.r - (-b.q - b.r))) +
      (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) + Int.natAbs (-b.q - b.r - (-c.q - c.r)))) / 2 =
      (Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (-a.q - a.r - (-b.q - b.r))) / 2 +
      (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) + Int.natAbs (-b.q - b.r - (-c.q - c.r))) / 2 := by
    obtain ⟨k, hk⟩ := hab
    obtain ⟨m, hm⟩ := hbc
    simp only [hk, hm]
    omega
  calc (Int.natAbs (a.q - c.q) + Int.natAbs (a.r - c.r) + Int.natAbs (-a.q - a.r - (-c.q - c.r))) / 2
      ≤ ((Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (-a.q - a.r - (-b.q - b.r))) +
         (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) + Int.natAbs (-b.q - b.r - (-c.q - c.r)))) / 2 :=
        Nat.div_le_div_right sum_ineq
    _ = (Int.natAbs (a.q - b.q) + Int.natAbs (a.r - b.r) + Int.natAbs (-a.q - a.r - (-b.q - b.r))) / 2 +
        (Int.natAbs (b.q - c.q) + Int.natAbs (b.r - c.r) + Int.natAbs (-b.q - b.r - (-c.q - c.r))) / 2 := hdiv

/-- Planar neighbors are distinct -/
theorem planarNeighbors_distinct (h : HexCoord) :
  (planarNeighbors h).Nodup := by
  unfold planarNeighbors
  simp only [List.nodup_cons, List.mem_cons, List.not_mem_nil,
             make, HexCoord.mk.injEq, not_and, or_false]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, List.nodup_nil⟩ <;> (intro h1; omega)

/-- Vertical neighbors are distinct -/
theorem verticalNeighbors_distinct (h : HexCoord) :
  (verticalNeighbors h).Nodup := by
  unfold verticalNeighbors
  simp only [List.nodup_cons, List.mem_singleton, List.not_mem_nil,
             make, HexCoord.mk.injEq, not_and, List.nodup_nil, not_false_eq_true, and_true,
             true_implies]
  omega

-- Connection invariants

/-- Planar neighbors stay on the same z-layer -/
theorem planarNeighbors_same_z (h : HexCoord) (n : HexCoord) :
  n ∈ planarNeighbors h → n.z = h.z := by
  intro hn
  unfold planarNeighbors at hn
  simp [make] at hn
  rcases hn with rfl | rfl | rfl | rfl | rfl | rfl <;> rfl

/-- Vertical neighbors differ by exactly 1 in z-coordinate -/
theorem verticalNeighbors_z_diff (h : HexCoord) (n : HexCoord) :
  n ∈ verticalNeighbors h → Int.natAbs (n.z - h.z) = 1 := by
  intro hn
  unfold verticalNeighbors at hn
  simp [make] at hn
  rcases hn with rfl | rfl <;> simp

/-- Extended neighbors differ by exactly 1 in z-coordinate -/
theorem extendedNeighbors_z_diff (h : HexCoord) (n : HexCoord) :
  n ∈ extendedNeighbors h → Int.natAbs (n.z - h.z) = 1 := by
  intro hn
  unfold extendedNeighbors at hn
  simp only [List.mem_append] at hn
  rcases hn with hup | hdown
  · -- n is a planar neighbor of the cell above h
    have hz : n.z = (make h.q h.r (h.z + 1)).z := planarNeighbors_same_z _ _ hup
    simp only [make] at hz
    simp [hz]
  · -- n is a planar neighbor of the cell below h
    have hz : n.z = (make h.q h.r (h.z - 1)).z := planarNeighbors_same_z _ _ hdown
    simp only [make] at hz
    simp [hz]

/-- Extended neighbors (above + below planar) are distinct -/
theorem extendedNeighbors_nodup (h : HexCoord) :
    (extendedNeighbors h).Nodup := by
  unfold extendedNeighbors
  -- Need to show: planarNeighbors(above) ++ planarNeighbors(below) is nodup
  apply List.Nodup.append
  · -- planarNeighbors of above is nodup
    exact planarNeighbors_distinct _
  · -- planarNeighbors of below is nodup
    exact planarNeighbors_distinct _
  · -- They are disjoint (different z-levels)
    intro x hAbove hBelow
    have hz1 := planarNeighbors_same_z _ _ hAbove
    have hz2 := planarNeighbors_same_z _ _ hBelow
    simp only [make] at hz1 hz2
    omega

/-- Planar and vertical neighbors are disjoint (different z-levels) -/
theorem planar_vertical_disjoint (h : HexCoord) :
    ∀ x, x ∈ planarNeighbors h → x ∉ verticalNeighbors h := by
  intro x hp hv
  have hz1 := planarNeighbors_same_z h x hp
  have hz2 := verticalNeighbors_z_diff h x hv
  simp [hz1] at hz2

/-- Planar and extended neighbors are disjoint (different z-levels) -/
theorem planar_extended_disjoint (h : HexCoord) :
    ∀ x, x ∈ planarNeighbors h → x ∉ extendedNeighbors h := by
  intro x hp he
  have hz1 := planarNeighbors_same_z h x hp
  have hz2 := extendedNeighbors_z_diff h x he
  simp [hz1] at hz2

/-- Vertical and extended neighbors are disjoint -/
theorem vertical_extended_disjoint (h : HexCoord) :
    ∀ x, x ∈ verticalNeighbors h → x ∉ extendedNeighbors h := by
  intro x hv he
  -- Vertical neighbors are at (h.q, h.r, h.z±1)
  -- Extended neighbors are planar neighbors of (h.q, h.r, h.z±1), which have different q or r
  unfold verticalNeighbors at hv
  simp only [List.mem_cons, List.not_mem_nil, or_false] at hv
  unfold extendedNeighbors at he
  simp only [List.mem_append] at he
  rcases hv with rfl | rfl
  · -- x = above = (h.q, h.r, h.z+1)
    rcases he with hAbove | hBelow
    · -- In planarNeighbors of above - but above itself isn't a planar neighbor of itself
      unfold planarNeighbors at hAbove
      simp only [List.mem_cons, List.not_mem_nil, or_false, make, HexCoord.mk.injEq] at hAbove
      rcases hAbove with ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ <;> omega
    · -- In planarNeighbors of below - different z
      have hz := planarNeighbors_same_z _ _ hBelow
      simp only [make] at hz
      omega
  · -- x = below = (h.q, h.r, h.z-1)
    rcases he with hAbove | hBelow
    · -- In planarNeighbors of above - different z
      have hz := planarNeighbors_same_z _ _ hAbove
      simp only [make] at hz
      omega
    · -- In planarNeighbors of below - but below isn't a planar neighbor of itself
      unfold planarNeighbors at hBelow
      simp only [List.mem_cons, List.not_mem_nil, or_false, make, HexCoord.mk.injEq] at hBelow
      rcases hBelow with ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ | ⟨hq, _, _⟩ <;> omega

/-- All 20 connections are distinct -/
theorem allConnections_nodup (h : HexCoord) :
    (allConnections h).Nodup := by
  unfold allConnections
  -- First combine planar ++ vertical
  have h_pv : (planarNeighbors h ++ verticalNeighbors h).Nodup := by
    apply List.Nodup.append
    · exact planarNeighbors_distinct h
    · exact verticalNeighbors_distinct h
    · intro x hp hv
      exact planar_vertical_disjoint h x hp hv
  -- Then combine with extended
  apply List.Nodup.append
  · exact h_pv
  · exact extendedNeighbors_nodup h
  · intro x hpv he
    simp only [List.mem_append] at hpv
    rcases hpv with hp | hv
    · exact planar_extended_disjoint h x hp he
    · exact vertical_extended_disjoint h x hv he

end HexCoord
