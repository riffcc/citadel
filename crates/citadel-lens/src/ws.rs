//! WebSocket Streaming for Real-time Mesh Updates
//!
//! This module provides WebSocket endpoints for streaming real-time updates
//! about the Citadel mesh network. Clients can subscribe to receive:
//!
//! - Peer join/leave events
//! - Slot claim announcements
//! - Content sync progress
//! - SPORE state changes
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     WebSocket      ┌─────────────┐
//! │   Browser   │ ←─────────────────→ │   Lens API  │
//! │  (Flagship) │                     │             │
//! └─────────────┘                     │  ┌───────┐  │
//!                                     │  │ Mesh  │  │
//!                                     │  │Service│──┼──→ Other Nodes
//!                                     │  └───────┘  │
//!                                     └─────────────┘
//! ```
//!
//! # Usage
//!
//! Connect to `/api/v1/ws/mesh` for real-time mesh topology updates.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::mesh::{FloodMessage, MeshState};
use crate::node::LensState;

/// WebSocket message types for mesh updates
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MeshEvent {
    /// Initial mesh state snapshot
    Snapshot {
        self_id: String,
        peers: Vec<PeerInfo>,
        slots: Vec<SlotInfo>,
        edges: Vec<EdgeInfo>,
    },
    /// Peer joined the mesh
    PeerJoined {
        id: String,
        addr: String,
        slot: Option<u64>,
    },
    /// Peer left the mesh
    PeerLeft { id: String },
    /// Slot claimed by a peer
    SlotClaimed {
        index: u64,
        peer_id: String,
        coord: [i64; 3],
    },
    /// Slot validation received
    SlotValidated {
        index: u64,
        peer_id: String,
        validator_id: String,
        accepted: bool,
    },
    /// SPORE sync update
    SporeSync {
        peer_id: String,
        have_count: usize,
        want_count: usize,
    },
    /// Admin list changed
    AdminsChanged { admins: Vec<String> },
    /// Heartbeat to keep connection alive
    Heartbeat { timestamp: u64 },
    /// VDF chain updated (for bootstrap/merge)
    VdfChainUpdate {
        height: u64,
        link_count: usize,
    },
    /// VDF-anchored slot claimed
    VdfSlotClaimed {
        slot: u64,
        vdf_height: u64,
        claimer: String,
    },
    /// CVDF chain update (collaborative VDF)
    CvdfChainUpdate {
        height: u64,
        weight: u64,
    },
    /// CVDF new round produced (with SPORE sync proof)
    CvdfNewRound {
        round: u64,
        weight: u64,
        attestation_count: usize,
        /// SPORE XOR ranges - 0 at convergence (zero overhead)
        spore_ranges: usize,
    },
}

/// Peer information for snapshots - MUST match REST API PeerNode structure
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    pub id: String,
    pub label: String,
    pub slot: HexSlot,
    pub peer_type: String,
    pub last_heartbeat: u64,
    pub capabilities: Vec<String>,
    pub online: bool,
}

/// Hex slot - MUST match REST API HexSlot structure
#[derive(Debug, Clone, Serialize)]
pub struct HexSlot {
    pub index: Option<u64>,
    pub q: i64,
    pub r: i64,
    pub z: i64,
}

/// Slot information (for slots list in snapshot)
#[derive(Debug, Clone, Serialize)]
pub struct SlotInfo {
    pub index: u64,
    pub peer_id: String,
    pub coord: [i64; 3],
    pub confirmations: u32,
}

/// Edge information (SPIRAL neighbor connection)
/// MUST match REST API PeerEdge structure for Flagship compatibility
#[derive(Debug, Clone, Serialize)]
pub struct EdgeInfo {
    pub from: String,
    pub to: String,
    pub connection_type: String,
    pub latency_ms: Option<u32>,
    pub latency_stats: LatencyStatsWs,
    pub bidirectional: bool,
}

/// Latency statistics for WebSocket (matches REST API LatencyStats)
#[derive(Debug, Clone, Default, Serialize)]
pub struct LatencyStatsWs {
    pub last_1s_ms: Option<f64>,
    pub last_60s_ms: Option<f64>,
    pub last_1h_ms: Option<f64>,
    pub samples_1s: u32,
    pub samples_60s: u32,
    pub samples_1h: u32,
}

/// WebSocket handler for mesh updates
pub async fn ws_mesh_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RwLock<LensState>>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_mesh_socket(socket, state))
}

/// Handle a WebSocket connection for mesh updates
async fn handle_mesh_socket(mut socket: WebSocket, state: Arc<RwLock<LensState>>) {
    info!("WebSocket client connected for mesh updates");

    // Get initial mesh state and flood receiver
    let (mesh_state, _flood_rx) = {
        let state = state.read().await;
        match &state.mesh_state {
            Some(mesh) => {
                // We need to get a flood receiver from somewhere
                // For now, we'll just use the mesh state
                (Some(Arc::clone(mesh)), None::<broadcast::Receiver<FloodMessage>>)
            }
            None => (None, None),
        }
    };

    // Send initial snapshot
    if let Some(ref mesh) = mesh_state {
        let snapshot = create_snapshot(mesh).await;
        if let Err(e) = send_event(&mut socket, snapshot).await {
            warn!("Failed to send initial snapshot: {}", e);
            return;
        }
    }

    // Handle the WebSocket connection
    // For now, we'll poll the mesh state periodically and send updates
    // In a full implementation, we'd subscribe to the flood channel
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    let mut last_peer_count = 0usize;
    let mut last_slot_count = 0usize;

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Received from client: {}", text);
                        // Could handle client requests here (e.g., force refresh)
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket client disconnected");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if let Err(e) = socket.send(Message::Pong(data)).await {
                            warn!("Failed to send pong: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            // Send periodic updates
            _ = interval.tick() => {
                if let Some(ref mesh) = mesh_state {
                    let mesh = mesh.read().await;

                    // Check for changes
                    let peer_count = mesh.peers.len();
                    let slot_count = mesh.claimed_slots.len();

                    // Send heartbeat with current state
                    let heartbeat = MeshEvent::Heartbeat {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    if let Err(e) = send_event(&mut socket, heartbeat).await {
                        warn!("Failed to send heartbeat: {}", e);
                        break;
                    }

                    // If counts changed, send full snapshot
                    if peer_count != last_peer_count || slot_count != last_slot_count {
                        drop(mesh);
                        let snapshot = create_snapshot(&mesh_state.as_ref().unwrap()).await;
                        if let Err(e) = send_event(&mut socket, snapshot).await {
                            warn!("Failed to send snapshot update: {}", e);
                            break;
                        }
                        last_peer_count = peer_count;
                        last_slot_count = slot_count;
                    }
                }
            }
        }
    }
}

/// Shorten peer ID for display (matches REST API)
/// Strips "b3b3/" prefix and takes first 12 chars of the hash
fn short_peer_id(full_id: &str) -> String {
    let hash = full_id.strip_prefix("b3b3/").unwrap_or(full_id);
    hash.chars().take(12).collect()
}

/// Create a snapshot of the current mesh state
/// Output format MUST match REST API /api/v1/map for Flagship compatibility
async fn create_snapshot(mesh_state: &Arc<RwLock<MeshState>>) -> MeshEvent {
    use citadel_topology::{HexCoord, Neighbors};
    use std::collections::{HashMap, HashSet};

    let mesh = mesh_state.read().await;

    let short_self_id = short_peer_id(&mesh.self_id);

    // Build self node first (matches REST API structure)
    let self_slot = if let Some(ref claim) = mesh.self_slot {
        HexSlot {
            index: Some(claim.index),
            q: claim.coord.q,
            r: claim.coord.r,
            z: claim.coord.z,
        }
    } else {
        HexSlot { index: None, q: 0, r: 0, z: 0 }
    };

    let self_peer = PeerInfo {
        id: short_self_id.clone(),
        label: short_self_id.clone(),
        slot: self_slot,
        peer_type: "server".to_string(),
        last_heartbeat: 0, // We ARE ourselves - always fresh
        capabilities: vec!["storage".to_string(), "relay".to_string(), "api".to_string()],
        online: true,
    };

    // Build peers list from claimed_slots (authoritative source, like REST API)
    let mut peers = vec![self_peer];
    let mut coord_to_peer: HashMap<HexCoord, String> = HashMap::new();

    // Add self to coord map if we have a slot
    if let Some(ref claim) = mesh.self_slot {
        coord_to_peer.insert(claim.coord, short_self_id.clone());
    }

    // Build peers from claimed_slots (the authoritative source)
    for claim in mesh.claimed_slots.values() {
        let short_id = short_peer_id(&claim.peer_id);

        // Skip self (already added)
        if short_id == short_self_id {
            continue;
        }

        // Check if peer is online (look up in peers map)
        let (online, last_heartbeat) = if let Some(peer) = mesh.peers.get(&claim.peer_id) {
            let elapsed = peer.last_seen.elapsed().as_secs();
            (elapsed < 30, elapsed)
        } else {
            (false, 999)
        };

        coord_to_peer.insert(claim.coord, short_id.clone());

        peers.push(PeerInfo {
            id: short_id.clone(),
            label: short_id.clone(),
            slot: HexSlot {
                index: Some(claim.index),
                q: claim.coord.q,
                r: claim.coord.r,
                z: claim.coord.z,
            },
            peer_type: "server".to_string(),
            last_heartbeat,
            capabilities: vec!["storage".to_string(), "relay".to_string()],
            online,
        });
    }

    // Build slots list
    let slots: Vec<SlotInfo> = mesh
        .claimed_slots
        .values()
        .map(|s| SlotInfo {
            index: s.index,
            peer_id: short_peer_id(&s.peer_id),
            coord: [s.coord.q, s.coord.r, s.coord.z],
            confirmations: s.confirmations,
        })
        .collect();

    // Compute edges based on SPIRAL hex neighbor topology
    // Include latency data from mesh.latency_history for PoL visualization
    let mut edges = Vec::new();
    let mut seen_edges: HashSet<(String, String)> = HashSet::new();

    for (coord, peer_id) in &coord_to_peer {
        let neighbor_coords = Neighbors::of(*coord);
        for neighbor_coord in neighbor_coords {
            if let Some(neighbor_id) = coord_to_peer.get(&neighbor_coord) {
                // Canonical ordering to avoid duplicates
                let (from, to) = if peer_id < neighbor_id {
                    (peer_id.clone(), neighbor_id.clone())
                } else {
                    (neighbor_id.clone(), peer_id.clone())
                };

                if !seen_edges.contains(&(from.clone(), to.clone())) {
                    seen_edges.insert((from.clone(), to.clone()));

                    // Look up latency stats from mesh state (PoL measurements)
                    let latency_stats = mesh.latency_history
                        .get(peer_id)
                        .and_then(|h| h.get(neighbor_id))
                        .map(|h| {
                            let stats = h.compute_stats();
                            LatencyStatsWs {
                                last_1s_ms: stats.last_1s_ms,
                                last_60s_ms: stats.last_60s_ms,
                                last_1h_ms: stats.last_1h_ms,
                                samples_1s: stats.samples_1s,
                                samples_60s: stats.samples_60s,
                                samples_1h: stats.samples_1h,
                            }
                        })
                        .unwrap_or_default();

                    let latency_ms = latency_stats.last_1s_ms.map(|v| v as u32);

                    edges.push(EdgeInfo {
                        from,
                        to,
                        connection_type: "neighbor".to_string(),
                        latency_ms,
                        latency_stats,
                        bidirectional: true,
                    });
                }
            }
        }
    }

    MeshEvent::Snapshot {
        self_id: short_self_id,
        peers,
        slots,
        edges,
    }
}

/// Send a mesh event over WebSocket
async fn send_event(socket: &mut WebSocket, event: MeshEvent) -> Result<(), axum::Error> {
    let json = serde_json::to_string(&event).map_err(|e| {
        axum::Error::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    socket
        .send(Message::Text(json))
        .await
        .map_err(|e| axum::Error::new(e))
}

/// Convert FloodMessage to MeshEvent
pub fn flood_to_event(msg: FloodMessage) -> Option<MeshEvent> {
    match msg {
        FloodMessage::Peers(_peers) => {
            // Could emit individual PeerJoined events
            // For now, we rely on the snapshot
            None
        }
        FloodMessage::Admins(admins) => Some(MeshEvent::AdminsChanged { admins }),
        FloodMessage::SlotClaim {
            index,
            peer_id,
            coord,
            ..  // public_key not needed for WS event
        } => Some(MeshEvent::SlotClaimed {
            index,
            peer_id,
            coord: [coord.0, coord.1, coord.2],
        }),
        FloodMessage::SlotValidation {
            index,
            peer_id,
            validator_id,
            accepted,
        } => Some(MeshEvent::SlotValidated {
            index,
            peer_id,
            validator_id,
            accepted,
        }),
        FloodMessage::SporeHaveList { peer_id, slots } => Some(MeshEvent::SporeSync {
            peer_id,
            have_count: slots.len(),
            want_count: 0, // Not tracked in current message
        }),
        FloodMessage::VdfChain { links } => Some(MeshEvent::VdfChainUpdate {
            height: links.last().map(|l| l.height).unwrap_or(0),
            link_count: links.len(),
        }),
        FloodMessage::VdfSlotClaim { claim } => Some(MeshEvent::VdfSlotClaimed {
            slot: claim.slot,
            vdf_height: claim.vdf_height,
            claimer: hex::encode(claim.claimer),
        }),
        // PoL messages are internal protocol - not exposed to WebSocket clients
        FloodMessage::PoLPing { .. } => None,
        FloodMessage::PoLPong { .. } => None,
        FloodMessage::PoLSwapProposal { .. } => None,
        FloodMessage::PoLSwapResponse { .. } => None,
        // CVDF messages
        FloodMessage::CvdfAttestation { .. } => None, // Internal coordination
        FloodMessage::CvdfNewRound { round, spore_proof } => Some(MeshEvent::CvdfNewRound {
            round: round.round,
            weight: round.weight() as u64,
            attestation_count: round.attestations.len(),
            spore_ranges: spore_proof.range_count(),  // 0 at convergence
        }),
        FloodMessage::CvdfSyncRequest { .. } => None, // Internal coordination
        FloodMessage::CvdfSyncResponse { rounds, .. } => {
            let total_weight: u64 = rounds.iter().map(|r| r.weight() as u64).sum();
            Some(MeshEvent::CvdfChainUpdate {
                height: rounds.last().map(|r| r.round).unwrap_or(0),
                weight: total_weight,
            })
        }
        // SPORE content sync messages - internal, not exposed to WebSocket
        FloodMessage::ContentHaveList { .. } => None,
        FloodMessage::Release { .. } => None,
        FloodMessage::DoNotWantList { .. } => None,
        FloodMessage::ErasureConfirmation { .. } => None,
        // BadBits - internal moderation, not exposed to WebSocket
        FloodMessage::BadBits { .. } => None,
        // SPORE range-based sync - internal protocol
        FloodMessage::SporeSync { .. } => None,
        FloodMessage::SporeDelta { .. } => None,
        // Featured releases sync - internal, admin-curated content
        FloodMessage::FeaturedSync { .. } => None,
    }
}
