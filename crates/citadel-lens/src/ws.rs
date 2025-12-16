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
    /// CVDF new round produced
    CvdfNewRound {
        round: u64,
        weight: u64,
        attestation_count: usize,
    },
}

/// Peer information for snapshots
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    pub id: String,
    pub addr: String,
    pub slot: Option<SlotInfo>,
    pub online: bool,
}

/// Slot information
#[derive(Debug, Clone, Serialize)]
pub struct SlotInfo {
    pub index: u64,
    pub peer_id: String,
    pub coord: [i64; 3],
    pub confirmations: u32,
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

/// Create a snapshot of the current mesh state
async fn create_snapshot(mesh_state: &Arc<RwLock<MeshState>>) -> MeshEvent {
    let mesh = mesh_state.read().await;

    let peers: Vec<PeerInfo> = mesh
        .peers
        .iter()
        .map(|(id, peer)| PeerInfo {
            id: id.clone(),
            addr: peer.addr.to_string(),
            slot: peer.slot.as_ref().map(|s| SlotInfo {
                index: s.index,
                peer_id: s.peer_id.clone(),
                coord: [s.coord.q, s.coord.r, s.coord.z],
                confirmations: s.confirmations,
            }),
            online: peer.last_seen.elapsed().as_secs() < 30,
        })
        .collect();

    let slots: Vec<SlotInfo> = mesh
        .claimed_slots
        .values()
        .map(|s| SlotInfo {
            index: s.index,
            peer_id: s.peer_id.clone(),
            coord: [s.coord.q, s.coord.r, s.coord.z],
            confirmations: s.confirmations,
        })
        .collect();

    MeshEvent::Snapshot {
        self_id: mesh.self_id.clone(),
        peers,
        slots,
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
        FloodMessage::CvdfNewRound { round } => Some(MeshEvent::CvdfNewRound {
            round: round.round,
            weight: round.weight() as u64,
            attestation_count: round.attestations.len(),
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
    }
}
