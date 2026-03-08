//! Traffic simulation and visualization.
//!
//! Simulates network traffic between mesh nodes:
//! - Unicast: Shows path through mesh from source to destination (BFS routing)
//! - Broadcast: Wave propagation through entire mesh using 20-neighbor topology

use crate::hex_to_world;
use citadel_topology::{HexCoord, Neighbors, Spiral3D};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// A packet traveling between nodes.
#[derive(Clone, Debug)]
pub struct Packet {
    /// Source node position
    pub source: [f32; 3],
    /// Destination node position
    pub dest: [f32; 3],
    /// Progress along path (0.0 = source, 1.0 = destination)
    pub progress: f32,
    /// Packet type for coloring
    pub packet_type: PacketType,
    /// Time packet was created
    pub created: Instant,
}

/// Type of traffic for different visualizations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Unicast path packet (yellow)
    Unicast,
    /// Broadcast wave packet (green/cyan)
    Broadcast,
}

impl Packet {
    /// Create a new packet.
    pub fn new(source: [f32; 3], dest: [f32; 3], packet_type: PacketType) -> Self {
        Self {
            source,
            dest,
            progress: 0.0,
            packet_type,
            created: Instant::now(),
        }
    }

    /// Get current interpolated position (clamped to destination).
    pub fn current_position(&self) -> [f32; 3] {
        let t = self.progress.min(1.0); // Clamp to destination
        [
            self.source[0] + (self.dest[0] - self.source[0]) * t,
            self.source[1] + (self.dest[1] - self.source[1]) * t,
            self.source[2] + (self.dest[2] - self.source[2]) * t,
        ]
    }

    /// Check if packet has arrived.
    pub fn arrived(&self) -> bool {
        self.progress >= 1.0
    }
}

/// Broadcast wave state - tracks propagation through mesh.
#[derive(Clone, Debug)]
pub struct BroadcastWave {
    /// Source node index
    pub source_idx: usize,
    /// Nodes that have received the broadcast (by index)
    pub reached: HashSet<usize>,
    /// Current frontier: (node_idx, came_from_idx, delay_remaining)
    /// Each node has its own random latency before it propagates
    pub frontier: Vec<(usize, Option<usize>, f32)>,
}

/// Unicast path visualization state.
#[derive(Clone, Debug)]
pub struct UnicastPath {
    /// Source node index
    pub source_idx: usize,
    /// Destination node index
    pub dest_idx: usize,
    /// Path as sequence of node indices (source to dest)
    pub path: Vec<usize>,
    /// Current position along path (0.0 to path.len()-1)
    pub progress: f32,
    /// Whether path is fully computed
    pub complete: bool,
}

/// Traffic simulation state.
pub struct TrafficSimulation {
    /// All node hex coordinates
    node_coords: Vec<HexCoord>,
    /// All node positions (cached for fast lookup)
    node_positions: Vec<[f32; 3]>,
    /// Coord to index mapping for fast neighbor lookup
    coord_to_idx: HashMap<HexCoord, usize>,
    /// Mesh bounds for toroidal wrapping
    bounds_min: (i64, i64, i64), // (q, r, z)
    bounds_max: (i64, i64, i64),
    /// Number of currently visible/active nodes (traffic only between these)
    visible_nodes: u32,
    /// Active packets in flight
    pub packets: Vec<Packet>,
    /// Active broadcast waves
    pub broadcast_waves: Vec<BroadcastWave>,
    /// Active unicast path visualizations
    pub unicast_paths: Vec<UnicastPath>,
    /// Speed of packet travel (progress per second)
    pub packet_speed: f32,
    /// Statistics
    pub stats: TrafficStats,
    /// Random number generator state (simple LCG)
    rng_state: u64,
    /// Whether path visualization is active (makes mesh transparent)
    pub path_active: bool,
}

/// Traffic statistics.
#[derive(Default, Clone, Debug)]
pub struct TrafficStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Unicast packets sent
    pub unicast_sent: u64,
    /// Broadcast packets sent
    pub broadcast_sent: u64,
    /// Packets that arrived
    pub packets_delivered: u64,
}

impl TrafficSimulation {
    /// Create a new traffic simulation for the given node count.
    pub fn new(node_count: u32) -> Self {
        // Pre-compute all node coordinates and positions
        let node_coords: Vec<HexCoord> = Spiral3D::take_slots(node_count as u64).collect();
        let node_positions: Vec<[f32; 3]> = node_coords.iter().map(|&c| hex_to_world(c)).collect();

        // Build coord to index map
        let coord_to_idx: HashMap<HexCoord, usize> = node_coords
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i))
            .collect();

        // Calculate mesh bounds for toroidal wrapping
        let bounds_min = node_coords
            .iter()
            .fold((i64::MAX, i64::MAX, i64::MAX), |(mq, mr, mz), c| {
                (mq.min(c.q), mr.min(c.r), mz.min(c.z))
            });
        let bounds_max = node_coords
            .iter()
            .fold((i64::MIN, i64::MIN, i64::MIN), |(mq, mr, mz), c| {
                (mq.max(c.q), mr.max(c.r), mz.max(c.z))
            });

        Self {
            node_coords,
            node_positions,
            coord_to_idx,
            bounds_min,
            bounds_max,
            visible_nodes: node_count,
            packets: Vec::with_capacity(100000),
            broadcast_waves: Vec::new(),
            unicast_paths: Vec::new(),
            packet_speed: 33.0, // ~30ms per hop for packets
            stats: TrafficStats::default(),
            rng_state: 12345,
            path_active: false,
        }
    }

    /// Set the number of visible nodes (traffic only goes between visible nodes).
    pub fn set_visible_nodes(&mut self, count: u32) {
        self.visible_nodes = count.min(self.node_positions.len() as u32);
    }

    /// Simple random number generator.
    fn rand(&mut self) -> u64 {
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        self.rng_state
    }

    /// Get a random float 0.0-1.0.
    fn rand_f32(&mut self) -> f32 {
        (self.rand() & 0xFFFFFF) as f32 / 0xFFFFFF as f32
    }

    /// Get a random visible node index.
    fn random_node(&mut self) -> usize {
        if self.visible_nodes == 0 {
            return 0;
        }
        (self.rand() as usize) % (self.visible_nodes as usize)
    }

    /// Generate random hop latency: 95% = 30ms, 5% = 30-150ms
    fn random_latency(&mut self) -> f32 {
        if self.rand_f32() < 0.95 {
            0.03 // 30ms - normal case
        } else {
            0.03 + self.rand_f32() * 0.12 // 30-150ms - slow case
        }
    }

    /// Get visible neighbors of a node (by index).
    fn visible_neighbors(&self, node_idx: usize) -> Vec<usize> {
        if node_idx >= self.visible_nodes as usize {
            return vec![];
        }

        let coord = self.node_coords[node_idx];
        let neighbors = Neighbors::of(coord);

        neighbors
            .iter()
            .filter_map(|&n| {
                self.coord_to_idx
                    .get(&n)
                    .copied()
                    .filter(|&idx| idx < self.visible_nodes as usize)
            })
            .collect()
    }

    /// Find path from source to dest using BFS.
    fn find_path(&self, src_idx: usize, dst_idx: usize) -> Option<Vec<usize>> {
        if src_idx >= self.visible_nodes as usize || dst_idx >= self.visible_nodes as usize {
            return None;
        }

        let mut visited = HashSet::new();
        let mut parent: HashMap<usize, usize> = HashMap::new();
        let mut queue = VecDeque::new();

        visited.insert(src_idx);
        queue.push_back(src_idx);

        while let Some(current) = queue.pop_front() {
            if current == dst_idx {
                // Reconstruct path
                let mut path = vec![dst_idx];
                let mut node = dst_idx;
                while let Some(&p) = parent.get(&node) {
                    path.push(p);
                    node = p;
                }
                path.reverse();
                return Some(path);
            }

            for neighbor in self.visible_neighbors(current) {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    parent.insert(neighbor, current);
                    queue.push_back(neighbor);
                }
            }
        }

        None
    }

    /// Spawn random unicast traffic (mass traffic mode).
    pub fn spawn_unicast(&mut self, intensity: f32) {
        if self.visible_nodes < 2 {
            return;
        }

        let packet_count = (intensity * 500.0) as usize;

        for _ in 0..packet_count {
            let src_idx = self.random_node();
            let mut dst_idx = self.random_node();
            while dst_idx == src_idx {
                dst_idx = self.random_node();
            }

            let packet = Packet::new(
                self.node_positions[src_idx],
                self.node_positions[dst_idx],
                PacketType::Unicast,
            );

            self.packets.push(packet);
            self.stats.packets_sent += 1;
            self.stats.unicast_sent += 1;
        }
    }

    /// Spawn broadcast traffic (mass traffic mode).
    /// Each broadcast creates a wave that propagates through the ENTIRE mesh.
    pub fn spawn_broadcast(&mut self, intensity: f32) {
        if self.visible_nodes < 2 {
            return;
        }

        // Spawn fewer waves since each one covers the entire mesh
        let broadcast_count = (intensity * 5.0).ceil() as usize;

        for _ in 0..broadcast_count {
            let src_idx = self.random_node();

            let mut reached = HashSet::new();
            reached.insert(src_idx);

            let initial_delay = self.random_latency();
            self.broadcast_waves.push(BroadcastWave {
                source_idx: src_idx,
                reached,
                frontier: vec![(src_idx, None, initial_delay)], // No sender for origin
            });

            self.stats.broadcast_sent += 1;
        }
    }

    /// Start a single unicast path visualization (R3/R4 mode).
    /// Returns true if path mode is now active.
    pub fn spawn_single_unicast(&mut self) -> bool {
        if self.visible_nodes < 2 {
            return false;
        }

        let src_idx = self.random_node();
        let mut dst_idx = self.random_node();
        while dst_idx == src_idx {
            dst_idx = self.random_node();
        }

        if let Some(path) = self.find_path(src_idx, dst_idx) {
            self.unicast_paths.push(UnicastPath {
                source_idx: src_idx,
                dest_idx: dst_idx,
                path,
                progress: 0.0,
                complete: true,
            });
            self.path_active = true;
            self.stats.unicast_sent += 1;
            true
        } else {
            false
        }
    }

    /// Start a single broadcast wave propagation (L3/L4 mode).
    pub fn spawn_single_broadcast(&mut self) {
        if self.visible_nodes < 2 {
            return;
        }

        let src_idx = self.random_node();

        let mut reached = HashSet::new();
        reached.insert(src_idx);

        let initial_delay = self.random_latency();
        self.broadcast_waves.push(BroadcastWave {
            source_idx: src_idx,
            reached,
            frontier: vec![(src_idx, None, initial_delay)], // No sender for origin
        });

        self.stats.broadcast_sent += 1;
    }

    /// Update all traffic.
    pub fn update(&mut self, dt: f32) {
        // Update regular packets
        for packet in &mut self.packets {
            packet.progress += self.packet_speed * dt;
        }
        // Count delivered packets
        let before = self.packets.len();
        // Remove packets that have faded out (progress > 1.0 means delivered, then fade for 0.5 more)
        self.packets.retain(|p| p.progress < 1.5);
        let arrived = before - self.packets.len();
        self.stats.packets_delivered += arrived as u64;

        // Update broadcast waves - per-node random latency
        // Turn-left algorithm: forward to all neighbors except who sent to us
        let mut wave_updates: Vec<(usize, Vec<(usize, usize, f32)>)> = Vec::new();

        // Pre-extract bounds for toroidal wrapping (avoid borrow issues)
        let (min_q, min_r, min_z) = self.bounds_min;
        let (max_q, max_r, max_z) = self.bounds_max;
        let range_q = max_q - min_q + 1;
        let range_r = max_r - min_r + 1;
        let range_z = max_z - min_z + 1;

        let wrap_coord = |coord: HexCoord| -> HexCoord {
            let wrap = |v: i64, min: i64, range: i64| -> i64 {
                if range <= 0 {
                    return v;
                }
                min + (v - min).rem_euclid(range)
            };
            HexCoord::new(
                wrap(coord.q, min_q, range_q),
                wrap(coord.r, min_r, range_r),
                wrap(coord.z, min_z, range_z),
            )
        };

        for (wave_idx, wave) in self.broadcast_waves.iter_mut().enumerate() {
            let mut new_hops = Vec::new();
            let mut remaining_frontier = Vec::new();

            // Check each frontier node - propagate when its delay expires
            for &(node_idx, came_from, delay) in &wave.frontier {
                let new_delay = delay - dt;

                if new_delay <= 0.0 {
                    // This node's delay expired - propagate to neighbors
                    let coord = self.node_coords[node_idx];
                    let neighbors = Neighbors::of(coord);

                    for &neighbor_coord in neighbors.iter() {
                        // Try direct lookup first, then wrap toroidally
                        let neighbor_idx =
                            self.coord_to_idx.get(&neighbor_coord).copied().or_else(|| {
                                let wrapped = wrap_coord(neighbor_coord);
                                self.coord_to_idx.get(&wrapped).copied()
                            });

                        if let Some(neighbor_idx) = neighbor_idx {
                            // Turn-left: skip sender, skip already reached, skip out of bounds
                            if Some(neighbor_idx) == came_from {
                                continue;
                            }
                            if neighbor_idx >= self.visible_nodes as usize {
                                continue;
                            }
                            if wave.reached.contains(&neighbor_idx) {
                                continue;
                            }

                            wave.reached.insert(neighbor_idx);
                            // Random latency for this hop: 95% = 30ms, 5% = 30-150ms
                            let hop_latency =
                                if (self.rng_state.wrapping_mul(2685821657736338717) >> 56) < 243 {
                                    0.03
                                } else {
                                    0.03 + ((self.rng_state.wrapping_mul(1103515245) >> 40)
                                        & 0xFFFF) as f32
                                        / 0xFFFF as f32
                                        * 0.12
                                };
                            self.rng_state = self.rng_state.wrapping_add(1);
                            new_hops.push((node_idx, neighbor_idx, hop_latency));
                        }
                    }
                } else {
                    // Keep waiting
                    remaining_frontier.push((node_idx, came_from, new_delay));
                }
            }

            wave_updates.push((wave_idx, new_hops));
            wave.frontier = remaining_frontier;
        }

        // Apply the wave updates (add new frontier nodes)
        for (wave_idx, hops) in wave_updates {
            for (from, to, delay) in hops {
                self.broadcast_waves[wave_idx]
                    .frontier
                    .push((to, Some(from), delay));
            }
        }

        // Remove completed waves
        self.broadcast_waves.retain(|w| !w.frontier.is_empty());

        // Update unicast paths
        for path in &mut self.unicast_paths {
            if path.path.len() > 1 {
                path.progress += self.packet_speed * dt;

                // Create packets along the path as progress moves
                let path_len = path.path.len() as f32 - 1.0;
                let current_segment = (path.progress as usize).min(path.path.len() - 2);

                // Spawn packet for current segment if not already there
                if path.progress <= path_len {
                    let src_idx = path.path[current_segment];
                    let dst_idx = path.path[current_segment + 1];

                    let packet = Packet::new(
                        self.node_positions[src_idx],
                        self.node_positions[dst_idx],
                        PacketType::Unicast,
                    );
                    self.packets.push(packet);
                }
            }
        }

        // Remove completed paths (keep for a bit after completion)
        self.unicast_paths
            .retain(|p| p.progress < (p.path.len() as f32 + 2.0));

        // Update path_active state
        self.path_active = !self.unicast_paths.is_empty();
    }

    /// Get mesh transparency (0.0 = opaque, 1.0 = invisible).
    /// Returns 0.3 when path visualization is active.
    pub fn mesh_transparency(&self) -> f32 {
        if self.path_active {
            0.3
        } else {
            0.0
        }
    }

    /// Get all line vertices for rendering active packets.
    /// Simple: just current hop (source to current position), no accumulated trails.
    pub fn get_line_vertices(&self) -> Vec<LineVertex> {
        let mut vertices = Vec::new();

        // Draw regular packets - just current hop
        for packet in &self.packets {
            if packet.progress >= 1.0 {
                continue; // Don't draw delivered packets
            }

            let color = match packet.packet_type {
                PacketType::Unicast => 0xFF00FFFF,   // Cyan (ABGR)
                PacketType::Broadcast => 0xFF00FF00, // Green (ABGR)
            };

            let current = packet.current_position();

            // Line from source to current position (one hop trail)
            vertices.push(LineVertex {
                position: packet.source,
                color: 0x4000FF00, // Dim green at source
            });
            vertices.push(LineVertex {
                position: current,
                color, // Bright at head
            });
        }

        // Draw unicast paths - full path shown
        for path in &self.unicast_paths {
            if path.path.len() > 1 {
                let path_color = 0xFFFFFF00; // Yellow (ABGR)
                let dim_color = 0x8080FF00; // Dimmer yellow

                for i in 0..(path.path.len() - 1) {
                    let src_pos = self.node_positions[path.path[i]];
                    let dst_pos = self.node_positions[path.path[i + 1]];
                    let traveled = i < path.progress as usize;

                    vertices.push(LineVertex {
                        position: src_pos,
                        color: if traveled { path_color } else { dim_color },
                    });
                    vertices.push(LineVertex {
                        position: dst_pos,
                        color: if traveled { path_color } else { dim_color },
                    });
                }
            }
        }

        // Broadcast waves - only show CURRENT frontier edges (not all accumulated)
        for wave in &self.broadcast_waves {
            let wave_color = 0xFF00FF00; // Green (ABGR)

            // Only draw edges from the current frontier (last hop)
            for &(node_idx, came_from, _delay) in &wave.frontier {
                if let Some(from_idx) = came_from {
                    vertices.push(LineVertex {
                        position: self.node_positions[from_idx],
                        color: 0x4000FF00, // Dim at source
                    });
                    vertices.push(LineVertex {
                        position: self.node_positions[node_idx],
                        color: wave_color, // Bright at frontier
                    });
                }
            }
        }

        vertices
    }

    /// Get point vertices for packet heads.
    pub fn get_point_vertices(&self) -> Vec<LineVertex> {
        let mut vertices = Vec::with_capacity(self.packets.len());

        for packet in &self.packets {
            // Don't show head for delivered packets (only show fading trail)
            if packet.progress >= 1.0 {
                continue;
            }

            let base_color = match packet.packet_type {
                PacketType::Unicast => 0x00FFFF00,   // Yellow RGB
                PacketType::Broadcast => 0x0000FFFF, // Cyan RGB
            };

            let current = packet.current_position();

            vertices.push(LineVertex {
                position: current,
                color: base_color | 0xFF000000, // Full alpha for packet head
            });
        }

        // Also draw path endpoints
        for path in &self.unicast_paths {
            if !path.path.is_empty() {
                // Source - bright green
                vertices.push(LineVertex {
                    position: self.node_positions[path.path[0]],
                    color: 0xFF00FF00,
                });
                // Destination - bright red
                if path.path.len() > 1 {
                    vertices.push(LineVertex {
                        position: self.node_positions[*path.path.last().unwrap()],
                        color: 0xFF0000FF,
                    });
                }
            }
        }

        vertices
    }

    /// Get number of active packets.
    pub fn active_packets(&self) -> usize {
        self.packets.len()
    }

    /// Clear all traffic.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.broadcast_waves.clear();
        self.unicast_paths.clear();
        self.path_active = false;
    }
}

/// Vertex for line rendering.
#[repr(C)]
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LineVertex {
    pub position: [f32; 3],
    pub color: u32,
}

impl LineVertex {
    /// Get the vertex buffer layout for line vertices.
    pub fn buffer_layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: std::mem::size_of::<LineVertex>() as wgpu::BufferAddress,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &[
                wgpu::VertexAttribute {
                    offset: 0,
                    shader_location: 0,
                    format: wgpu::VertexFormat::Float32x3,
                },
                wgpu::VertexAttribute {
                    offset: 12,
                    shader_location: 1,
                    format: wgpu::VertexFormat::Uint32,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_interpolation() {
        let packet = Packet {
            source: [0.0, 0.0, 0.0],
            dest: [10.0, 0.0, 0.0],
            progress: 0.5,
            packet_type: PacketType::Unicast,
            created: Instant::now(),
        };

        let pos = packet.current_position();
        assert!((pos[0] - 5.0).abs() < 0.001);
    }

    #[test]
    fn traffic_simulation_creates_packets() {
        let mut sim = TrafficSimulation::new(100);
        sim.spawn_unicast(0.5);
        assert!(sim.packets.len() > 0);
    }

    #[test]
    fn line_vertex_size() {
        assert_eq!(std::mem::size_of::<LineVertex>(), 16);
    }

    #[test]
    fn broadcast_wave_propagates() {
        let mut sim = TrafficSimulation::new(100);
        sim.spawn_single_broadcast();
        assert_eq!(sim.broadcast_waves.len(), 1);

        // Step forward
        sim.update(0.5);
        assert!(sim.packets.len() > 0);
    }
}
