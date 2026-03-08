//! Mesh assembly simulation with event recording.
//!
//! Uses the 3D SPIRAL enumeration for true 20-neighbor mesh assembly.

use std::collections::HashMap;

use citadel_consensus::validation_threshold;
use citadel_topology::{spiral3d_to_coord, HexCoord, Neighbors, Spiral3DIndex};

use crate::events::{ConnectionState, MeshEvent, MeshSnapshot, NodeId, NodeState};

/// Configuration for the simulation.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Seed for deterministic simulation
    pub seed: u64,
    /// Whether to simulate network delays
    pub simulate_delays: bool,
    /// Probability of Byzantine behavior (0.0 - 1.0)
    pub byzantine_rate: f64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            simulate_delays: false,
            byzantine_rate: 0.0,
        }
    }
}

/// Simulates mesh assembly and records events.
pub struct Simulation {
    config: SimulationConfig,
    events: Vec<MeshEvent>,
    nodes: HashMap<NodeId, NodeState>,
    slot_to_node: HashMap<Spiral3DIndex, NodeId>,
    coord_to_node: HashMap<HexCoord, NodeId>,
    next_node_id: u64,
    current_frame: u64,
    frontier: Spiral3DIndex,
}

impl Simulation {
    /// Create a new simulation with the given configuration.
    pub fn new(config: SimulationConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
            nodes: HashMap::new(),
            slot_to_node: HashMap::new(),
            coord_to_node: HashMap::new(),
            next_node_id: 0,
            current_frame: 0,
            frontier: Spiral3DIndex::new(0),
        }
    }

    /// Add a node to the mesh using 3D SPIRAL self-assembly.
    ///
    /// The 3D spiral enumerates coordinates in shells of increasing radius,
    /// ensuring each new node connects to its 20 neighbors as they exist.
    pub fn add_node(&mut self) -> NodeId {
        let node_id = NodeId(self.next_node_id);
        self.next_node_id += 1;

        // Find next available slot in 3D spiral
        let slot = self.find_next_slot();
        let coord = spiral3d_to_coord(slot);

        // Record join event
        self.events.push(MeshEvent::NodeJoined {
            node: node_id,
            slot: citadel_topology::SpiralIndex::new(slot.value()), // Convert for compatibility
            coord,
            frame: self.current_frame,
        });

        // Get all 20 neighbor coordinates
        let neighbor_coords = Neighbors::of(coord);
        let mut connections = Vec::new();

        // Establish connections to existing neighbors
        for neighbor_coord in neighbor_coords {
            if let Some(&neighbor_id) = self.coord_to_node.get(&neighbor_coord) {
                // Establish connection
                self.events.push(MeshEvent::ConnectionEstablished {
                    from: node_id,
                    to: neighbor_id,
                    direction: 0,
                    frame: self.current_frame,
                });

                // Confirm bidirectional
                self.events.push(MeshEvent::ConnectionConfirmed {
                    from: node_id,
                    to: neighbor_id,
                    frame: self.current_frame,
                });

                connections.push(neighbor_id);

                // Update neighbor's connection list
                if let Some(neighbor) = self.nodes.get_mut(&neighbor_id) {
                    if !neighbor.connections.contains(&node_id) {
                        neighbor.connections.push(node_id);
                    }
                }
            }
        }

        let connection_count = connections.len();

        // Check validation threshold
        let threshold = validation_threshold(connection_count);
        let is_valid = connection_count >= threshold;

        if is_valid {
            self.events.push(MeshEvent::NodeValidated {
                node: node_id,
                connection_count,
                threshold,
                frame: self.current_frame,
            });
        }

        // Create and store node state
        let node_state = NodeState {
            id: node_id,
            slot: citadel_topology::SpiralIndex::new(slot.value()),
            coord,
            connections,
            is_valid,
        };

        self.nodes.insert(node_id, node_state);
        self.slot_to_node.insert(slot, node_id);
        self.coord_to_node.insert(coord, node_id);

        // Update frontier
        if slot.value() >= self.frontier.value() {
            self.frontier = Spiral3DIndex::new(slot.value() + 1);
        }

        self.current_frame += 1;
        node_id
    }

    /// Find the next available slot in 3D SPIRAL order.
    fn find_next_slot(&self) -> Spiral3DIndex {
        // Use next in sequence
        Spiral3DIndex::new(self.nodes.len() as u64)
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[MeshEvent] {
        &self.events
    }

    /// Get the number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get the number of nodes in the mesh.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get a snapshot of the mesh at the current state.
    pub fn snapshot(&self) -> MeshSnapshot {
        let nodes: Vec<_> = self.nodes.values().cloned().collect();
        let connections: Vec<_> = self
            .nodes
            .values()
            .flat_map(|n| {
                n.connections.iter().map(move |&to| ConnectionState {
                    from: n.id,
                    to,
                    direction: 0,
                    is_bidirectional: true,
                })
            })
            .collect();

        let valid_count = nodes.iter().filter(|n| n.is_valid).count();
        let frontier_shell = self.frontier.shell();

        MeshSnapshot {
            frame: self.current_frame,
            nodes,
            connections,
            node_count: self.nodes.len(),
            valid_count,
            frontier_ring: frontier_shell,
        }
    }

    /// Run assembly for N nodes.
    pub fn run_assembly(&mut self, count: usize) {
        for _ in 0..count {
            self.add_node();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_topology::SpiralIndex;

    #[test]
    fn simulation_starts_empty() {
        let sim = Simulation::new(SimulationConfig::default());
        assert_eq!(sim.node_count(), 0);
        assert_eq!(sim.event_count(), 0);
    }

    #[test]
    fn first_node_is_origin() {
        let mut sim = Simulation::new(SimulationConfig::default());
        let node = sim.add_node();

        assert_eq!(node, NodeId(0));
        assert_eq!(sim.node_count(), 1);

        // First node should be at origin (slot 0 in both 2D and 3D spiral)
        let state = sim.nodes.get(&node).unwrap();
        assert_eq!(state.slot, SpiralIndex::new(0));
        assert_eq!(state.coord, HexCoord::ORIGIN);
    }

    #[test]
    fn nodes_get_sequential_slots() {
        let mut sim = Simulation::new(SimulationConfig::default());

        for i in 0..10 {
            let node = sim.add_node();
            let state = sim.nodes.get(&node).unwrap();
            assert_eq!(state.slot.value(), i as u64);
        }
    }

    #[test]
    fn connections_established_to_neighbors() {
        let mut sim = Simulation::new(SimulationConfig::default());

        // Add 7 nodes (origin + 6 neighbors)
        sim.run_assembly(7);

        // Origin should have connections to ring-1 nodes
        let origin = sim.nodes.get(&NodeId(0)).unwrap();
        // Origin gets connections as neighbors join
        assert!(!origin.connections.is_empty());
    }

    #[test]
    fn snapshot_captures_state() {
        let mut sim = Simulation::new(SimulationConfig::default());
        sim.run_assembly(10);

        let snap = sim.snapshot();
        assert_eq!(snap.node_count, 10);
        assert!(snap.nodes.len() == 10);
    }

    #[test]
    fn events_recorded_for_each_join() {
        let mut sim = Simulation::new(SimulationConfig::default());
        sim.run_assembly(5);

        // Should have at least 5 NodeJoined events
        let join_events = sim
            .events()
            .iter()
            .filter(|e| matches!(e, MeshEvent::NodeJoined { .. }))
            .count();

        assert_eq!(join_events, 5);
    }
}
