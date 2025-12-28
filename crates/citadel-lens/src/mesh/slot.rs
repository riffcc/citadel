//! SPIRAL slot management.
//!
//! This module handles:
//! - SlotClaim creation and neighbor computation
//! - Consensus threshold calculation (BFT scaling)
//! - Latency tracking for optimization

use citadel_topology::{
    compute_all_connections, ghost_target, Connection, Direction, HexCoord, Neighbors,
    Spiral3DIndex, spiral3d_to_coord,
};
use std::collections::HashSet;

/// A claimed SPIRAL slot in the mesh
#[derive(Debug, Clone)]
pub struct SlotClaim {
    /// SPIRAL index (deterministic ordering)
    pub index: u64,
    /// 3D hex coordinate
    pub coord: HexCoord,
    /// PeerID that claimed this slot
    pub peer_id: String,
    /// Public key of the claiming peer (for TGP)
    pub public_key: Option<Vec<u8>>,
    /// Number of validators who confirmed this claim
    pub confirmations: u32,
}

impl SlotClaim {
    /// Create a new slot claim (without public key)
    pub fn new(index: u64, peer_id: String) -> Self {
        let coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        Self {
            index,
            coord,
            peer_id,
            public_key: None,
            confirmations: 0,
        }
    }

    /// Create a new slot claim with public key
    pub fn with_public_key(index: u64, peer_id: String, public_key: Option<Vec<u8>>) -> Self {
        let coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        Self {
            index,
            coord,
            peer_id,
            public_key,
            confirmations: 0,
        }
    }

    /// Get the 20 theoretical neighbor coordinates of this slot.
    ///
    /// This returns the "ideal" neighbors assuming all slots are occupied.
    /// Used for slot validation: to claim slot N, you need TGP with its theoretical neighbors.
    pub fn neighbor_coords(&self) -> [HexCoord; 20] {
        Neighbors::of(self.coord)
    }

    /// Get the actual connections for this slot using Gap-and-Wrap.
    ///
    /// In a sparse mesh, some theoretical neighbors may be empty. GnW creates
    /// "ghost connections" that span gaps to the next occupied slot in each direction.
    /// This ensures every node has up to 20 logical connections regardless of density.
    ///
    /// Returns connections sorted by direction (6 planar + 2 vertical + 12 extended).
    pub fn ghost_connections(&self, occupied: &HashSet<HexCoord>) -> Vec<Connection> {
        compute_all_connections(occupied, self.coord)
    }

    /// Get the ghost target for a specific direction.
    ///
    /// Returns the actual connection target in the given direction:
    /// - If theoretical neighbor is occupied → normal connection
    /// - Otherwise → ghost connection to next occupied slot in that direction
    pub fn ghost_target_in_direction(
        &self,
        occupied: &HashSet<HexCoord>,
        direction: Direction,
    ) -> Option<HexCoord> {
        ghost_target(occupied, self.coord, direction)
    }
}

/// Calculate consensus threshold based on mesh size.
///
/// # THE MECHANISM
///
/// This is NOT arbitrary - these are the minimum thresholds for Byzantine fault
/// tolerance at each scale:
///
/// ```text
/// NODES   THRESHOLD   BYZANTINE TOLERANCE   MECHANISM
/// ─────────────────────────────────────────────────────────
///   1       1/1       0 faults              Genesis (trivial)
///   2       2/2       0 faults              Pure TGP bilateral
///   3       2/3       1 fault               TGP triad
///   4       3/4       1 fault               BFT: 2f+1 = 3
///  5-6      4/n       1 fault               Growing BFT
///  7-9      2f+1      2 faults              Full BFT formula
/// 10-14     2f+1      3-4 faults            Scaling BFT
/// 15-19     2f+1      4-6 faults            Approaching 11/20
///  20+      11/20     9 faults              Mature mesh BFT
/// ```
///
/// # BFT Formula
///
/// For `n` nodes, Byzantine fault tolerance requires:
/// - Maximum faults tolerated: `f = ⌊(n-1)/3⌋`
/// - Threshold: `2f + 1` (need honest majority of non-faulty)
///
/// At 20 neighbors: `f = ⌊19/3⌋ = 6`, but we use f=9 (11/20) because:
/// - Each neighbor independently validates via their own TGP
/// - We need >50% of TOTAL neighbors, not just non-faulty
///
/// # Security Scaling
///
/// Security GROWS with the network:
/// - 2 nodes: Both must agree (trivial to attack, but trivial network)
/// - 7 nodes: 5/7 must agree (2 Byzantine tolerated)
/// - 20 nodes: 11/20 must agree (9 Byzantine tolerated!)
pub fn consensus_threshold(mesh_size: usize) -> usize {
    match mesh_size {
        0 | 1 => 1,      // Genesis: auto-occupy slot 0
        2 => 2,          // Pure TGP: 2/2 bilateral (both agree or neither)
        3 => 2,          // Triad: 2/3 (one Byzantine tolerated)
        4 => 3,          // BFT emerges: 3/4 (f=1, 2f+1=3)
        5 => 4,          // f=1, 2f+1=3, but need >50% so 4/5
        6 => 4,          // f=1, 2f+1=3, but need >50% so 4/6
        7 => 5,          // f=2, 2f+1=5 (two Byzantine tolerated)
        8 => 6,          // f=2, need >50%
        9 => 6,          // f=2, need >50%
        10 => 7,         // f=3, 2f+1=7
        11..=13 => 8,    // f=3-4, scaling
        14..=16 => 9,    // f=4-5, approaching full mesh
        17..=19 => 10,   // f=5-6, almost there
        _ => 11,         // Full mesh: 11/20 (9 Byzantine tolerated)
    }
}

/// A single latency measurement sample
#[derive(Debug, Clone)]
pub struct LatencySample {
    pub latency_ms: u64,
    pub timestamp: std::time::Instant,
}

/// Latency history for a single neighbor - tracks samples over time windows
/// Uses VecDeque for O(1) push/pop. Memory-optimized: 360 samples (10s intervals)
#[derive(Debug, Clone, Default)]
pub struct LatencyHistory {
    /// Recent samples (circular buffer, 360 samples = 1h at 10s resolution)
    samples: std::collections::VecDeque<LatencySample>,
    /// Maximum samples to keep (reduced to save memory)
    max_samples: usize,
}

impl LatencyHistory {
    pub fn new() -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(64), // Start small, grow as needed
            max_samples: 360, // 1 hour at 10-second resolution
        }
    }

    /// Record a new latency sample - O(1) amortized
    pub fn record(&mut self, latency_ms: u64) {
        let sample = LatencySample {
            latency_ms,
            timestamp: std::time::Instant::now(),
        };

        if self.samples.len() >= self.max_samples {
            self.samples.pop_front(); // O(1) with VecDeque
        }
        self.samples.push_back(sample);
    }

    /// Compute latency statistics over multiple time windows
    pub fn compute_stats(&self) -> crate::api::LatencyStats {
        use std::time::Duration;

        let now = std::time::Instant::now();
        let one_sec = Duration::from_secs(1);
        let one_min = Duration::from_secs(60);
        let one_hour = Duration::from_secs(3600);

        let mut sum_1s = 0u64;
        let mut count_1s = 0u32;
        let mut sum_60s = 0u64;
        let mut count_60s = 0u32;
        let mut sum_1h = 0u64;
        let mut count_1h = 0u32;

        for sample in &self.samples {
            let age = now.duration_since(sample.timestamp);

            if age <= one_hour {
                sum_1h += sample.latency_ms;
                count_1h += 1;

                if age <= one_min {
                    sum_60s += sample.latency_ms;
                    count_60s += 1;

                    if age <= one_sec {
                        sum_1s += sample.latency_ms;
                        count_1s += 1;
                    }
                }
            }
        }

        crate::api::LatencyStats {
            last_1s_ms: if count_1s > 0 {
                Some(sum_1s as f64 / count_1s as f64)
            } else {
                None
            },
            last_60s_ms: if count_60s > 0 {
                Some(sum_60s as f64 / count_60s as f64)
            } else {
                None
            },
            last_1h_ms: if count_1h > 0 {
                Some(sum_1h as f64 / count_1h as f64)
            } else {
                None
            },
            samples_1s: count_1s,
            samples_60s: count_60s,
            samples_1h: count_1h,
        }
    }

    /// Get the most recent latency measurement
    pub fn latest(&self) -> Option<u64> {
        self.samples.back().map(|s| s.latency_ms)
    }
}
