//! Mesh events for visualization timeline.

use citadel_topology::{HexCoord, SpiralIndex};
use serde::{Deserialize, Serialize};

/// A unique node identifier for visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

/// State of a node in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub id: NodeId,
    pub slot: SpiralIndex,
    pub coord: HexCoord,
    pub connections: Vec<NodeId>,
    pub is_valid: bool,
}

/// State of a connection between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub from: NodeId,
    pub to: NodeId,
    pub direction: u8,
    pub is_bidirectional: bool,
}

/// Events that occur during mesh assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MeshEvent {
    /// A new node joined the mesh
    NodeJoined {
        node: NodeId,
        slot: SpiralIndex,
        coord: HexCoord,
        frame: u64,
    },

    /// A connection was established
    ConnectionEstablished {
        from: NodeId,
        to: NodeId,
        direction: u8,
        frame: u64,
    },

    /// A connection became bidirectional (mutual acknowledgment)
    ConnectionConfirmed {
        from: NodeId,
        to: NodeId,
        frame: u64,
    },

    /// A node achieved valid occupancy (≥threshold connections)
    NodeValidated {
        node: NodeId,
        connection_count: usize,
        threshold: usize,
        frame: u64,
    },

    /// A node was nudged to a different slot (self-healing)
    NodeNudged {
        node: NodeId,
        from_slot: SpiralIndex,
        to_slot: SpiralIndex,
        frame: u64,
    },

    /// A node left the mesh
    NodeLeft {
        node: NodeId,
        slot: SpiralIndex,
        frame: u64,
    },

    /// Contention resolved via deterministic selection
    ContentionResolved {
        slot: SpiralIndex,
        winner: NodeId,
        loser: NodeId,
        frame: u64,
    },
}

impl MeshEvent {
    /// Get the frame number for this event.
    pub fn frame(&self) -> u64 {
        match self {
            MeshEvent::NodeJoined { frame, .. } => *frame,
            MeshEvent::ConnectionEstablished { frame, .. } => *frame,
            MeshEvent::ConnectionConfirmed { frame, .. } => *frame,
            MeshEvent::NodeValidated { frame, .. } => *frame,
            MeshEvent::NodeNudged { frame, .. } => *frame,
            MeshEvent::NodeLeft { frame, .. } => *frame,
            MeshEvent::ContentionResolved { frame, .. } => *frame,
        }
    }
}

/// A snapshot of the mesh at a point in time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeshSnapshot {
    pub frame: u64,
    pub nodes: Vec<NodeState>,
    pub connections: Vec<ConnectionState>,
    pub node_count: usize,
    pub valid_count: usize,
    pub frontier_ring: u64,
}

impl MeshSnapshot {
    /// Rebuild mesh state from events up to (but not including) the given event index.
    pub fn from_events(events: &[MeshEvent], up_to_event: usize) -> Self {
        use std::collections::HashMap;

        let mut nodes: HashMap<NodeId, NodeState> = HashMap::new();
        let mut connections: Vec<ConnectionState> = Vec::new();
        let mut frame = 0u64;
        let mut frontier_ring = 0u64;

        for event in events.iter().take(up_to_event) {
            match event {
                MeshEvent::NodeJoined {
                    node,
                    slot,
                    coord,
                    frame: f,
                } => {
                    frame = *f;
                    nodes.insert(
                        *node,
                        NodeState {
                            id: *node,
                            slot: *slot,
                            coord: *coord,
                            connections: Vec::new(),
                            is_valid: false,
                        },
                    );
                    frontier_ring = frontier_ring.max(slot.ring());
                }
                MeshEvent::ConnectionEstablished {
                    from,
                    to,
                    direction,
                    frame: f,
                } => {
                    frame = *f;
                    connections.push(ConnectionState {
                        from: *from,
                        to: *to,
                        direction: *direction,
                        is_bidirectional: false,
                    });
                    // Add to node's connection list
                    if let Some(node) = nodes.get_mut(from) {
                        if !node.connections.contains(to) {
                            node.connections.push(*to);
                        }
                    }
                    if let Some(node) = nodes.get_mut(to) {
                        if !node.connections.contains(from) {
                            node.connections.push(*from);
                        }
                    }
                }
                MeshEvent::ConnectionConfirmed { from, to, frame: f } => {
                    frame = *f;
                    // Mark connection as bidirectional
                    for conn in &mut connections {
                        if (conn.from == *from && conn.to == *to)
                            || (conn.from == *to && conn.to == *from)
                        {
                            conn.is_bidirectional = true;
                        }
                    }
                }
                MeshEvent::NodeValidated { node, frame: f, .. } => {
                    frame = *f;
                    if let Some(n) = nodes.get_mut(node) {
                        n.is_valid = true;
                    }
                }
                MeshEvent::NodeLeft { node, frame: f, .. } => {
                    frame = *f;
                    nodes.remove(node);
                    connections.retain(|c| c.from != *node && c.to != *node);
                }
                MeshEvent::NodeNudged {
                    node,
                    to_slot,
                    frame: f,
                    ..
                } => {
                    frame = *f;
                    if let Some(n) = nodes.get_mut(node) {
                        n.slot = *to_slot;
                        n.coord = citadel_topology::spiral_to_coord(*to_slot);
                    }
                }
                MeshEvent::ContentionResolved { .. } => {
                    // Just informational for viz
                }
            }
        }

        let node_vec: Vec<_> = nodes.into_values().collect();
        let valid_count = node_vec.iter().filter(|n| n.is_valid).count();
        let node_count = node_vec.len();

        MeshSnapshot {
            frame,
            nodes: node_vec,
            connections,
            node_count,
            valid_count,
            frontier_ring,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization() {
        let event = MeshEvent::NodeJoined {
            node: NodeId(1),
            slot: SpiralIndex::new(42),
            coord: HexCoord::new(3, -2, 0),
            frame: 100,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("NodeJoined"));
        assert!(json.contains("42"));

        let parsed: MeshEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.frame(), 100);
    }

    #[test]
    fn snapshot_default() {
        let snap = MeshSnapshot::default();
        assert_eq!(snap.frame, 0);
        assert_eq!(snap.node_count, 0);
    }
}
