//! Admin WebSocket for Real-time Moderation Updates
//!
//! Provides authenticated WebSocket endpoint for admins to receive
//! real-time moderation events:
//!
//! - New release submissions (pending)
//! - Release approvals
//! - Release rejections
//! - Moderation statistics updates
//!
//! # Authentication
//!
//! Clients must provide admin credentials via query parameters:
//! `/api/v1/ws/admin?pubkey=ed25519p/...`
//!
//! The public key must be in the admin list.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::models::{Release, ReleaseStatus};
use crate::node::LensState;

/// Query parameters for admin WebSocket authentication
#[derive(Debug, Deserialize)]
pub struct AdminWsQuery {
    /// Admin public key (ed25519p/... format)
    pubkey: String,
}

/// Admin WebSocket event types
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminEvent {
    /// Connection authenticated successfully
    Connected { admin_pubkey: String },
    /// Initial moderation state snapshot
    Snapshot {
        pending_count: usize,
        approved_count: usize,
        rejected_count: usize,
        pending_releases: Vec<ReleaseInfo>,
    },
    /// New release submitted for moderation
    ReleaseSubmitted { release: ReleaseInfo },
    /// Release was approved
    ReleaseApproved {
        release_id: String,
        moderator: String,
        timestamp: String,
    },
    /// Release was rejected
    ReleaseRejected {
        release_id: String,
        moderator: String,
        reason: Option<String>,
        timestamp: String,
    },
    /// Moderation stats updated
    StatsUpdated {
        pending: usize,
        approved: usize,
        rejected: usize,
    },
    /// Heartbeat to keep connection alive
    Heartbeat { timestamp: u64 },
    /// Error message
    Error { message: String },
}

/// Simplified release info for WebSocket events
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseInfo {
    pub id: String,
    pub name: String,
    pub category_id: String,
    pub creator: Option<String>,
    pub thumbnail_cid: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
}

impl From<&Release> for ReleaseInfo {
    fn from(r: &Release) -> Self {
        ReleaseInfo {
            id: r.id.clone(),
            name: r.title.clone(),
            category_id: r.category_id.clone(),
            creator: r.creator.clone(),
            thumbnail_cid: r.thumbnail_cid.clone(),
            status: r.status.to_string(),
            created_at: r.created_at.clone(),
        }
    }
}

/// Broadcast channel for admin events
pub type AdminEventSender = broadcast::Sender<AdminEvent>;
pub type AdminEventReceiver = broadcast::Receiver<AdminEvent>;

/// Create a new admin event broadcast channel
pub fn create_admin_channel() -> (AdminEventSender, AdminEventReceiver) {
    broadcast::channel(256)
}

/// WebSocket handler for admin moderation updates
pub async fn ws_admin_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<AdminWsQuery>,
    State(state): State<Arc<RwLock<LensState>>>,
) -> Result<impl IntoResponse, StatusCode> {
    // Verify admin status before upgrading
    {
        let state = state.read().await;
        if !state.storage.is_admin(&query.pubkey).unwrap_or(false) {
            warn!(
                "Unauthorized admin WebSocket attempt from: {}",
                query.pubkey
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    info!("Admin WebSocket connection from: {}", query.pubkey);
    Ok(ws.on_upgrade(move |socket| handle_admin_socket(socket, state, query.pubkey)))
}

/// Handle an authenticated admin WebSocket connection
async fn handle_admin_socket(
    mut socket: WebSocket,
    state: Arc<RwLock<LensState>>,
    admin_pubkey: String,
) {
    info!("Admin {} connected via WebSocket", admin_pubkey);

    // Send connection confirmation
    let connected = AdminEvent::Connected {
        admin_pubkey: admin_pubkey.clone(),
    };
    if let Err(e) = send_admin_event(&mut socket, connected).await {
        warn!("Failed to send connected event: {}", e);
        return;
    }

    // Send initial snapshot
    let snapshot = create_admin_snapshot(&state).await;
    if let Err(e) = send_admin_event(&mut socket, snapshot).await {
        warn!("Failed to send snapshot: {}", e);
        return;
    }

    // Get admin event receiver if available
    let mut event_rx = {
        let state = state.read().await;
        state.admin_event_tx.as_ref().map(|tx| tx.subscribe())
    };

    // Handle WebSocket connection
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    let mut last_pending_count = 0usize;

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Admin {} sent: {}", admin_pubkey, text);
                        // Could handle client requests (e.g., force refresh)
                        if text == "refresh" {
                            let snapshot = create_admin_snapshot(&state).await;
                            if let Err(e) = send_admin_event(&mut socket, snapshot).await {
                                warn!("Failed to send refresh snapshot: {}", e);
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("Admin {} disconnected", admin_pubkey);
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if let Err(e) = socket.send(Message::Pong(data)).await {
                            warn!("Failed to send pong: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        warn!("Admin WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            // Handle broadcast events
            event = async {
                if let Some(ref mut rx) = event_rx {
                    rx.recv().await.ok()
                } else {
                    // No event channel, wait forever
                    std::future::pending::<Option<AdminEvent>>().await
                }
            } => {
                if let Some(event) = event {
                    if let Err(e) = send_admin_event(&mut socket, event).await {
                        warn!("Failed to send admin event: {}", e);
                        break;
                    }
                }
            }
            // Send periodic heartbeat and check for changes
            _ = heartbeat_interval.tick() => {
                // Check for pending count changes (fallback if no event channel)
                let current_pending = {
                    use crate::models::{Release, ReleaseStatus};
                    let state = state.read().await;

                    let doc_store = state.doc_store.read().await;
                    doc_store.list::<Release>()
                        .unwrap_or_default()
                        .iter()
                        .filter(|r| r.status == ReleaseStatus::Pending)
                        .count()
                };

                if current_pending != last_pending_count {
                    let snapshot = create_admin_snapshot(&state).await;
                    if let Err(e) = send_admin_event(&mut socket, snapshot).await {
                        warn!("Failed to send stats update: {}", e);
                        break;
                    }
                    last_pending_count = current_pending;
                } else {
                    // Just send heartbeat
                    let heartbeat = AdminEvent::Heartbeat {
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };
                    if let Err(e) = send_admin_event(&mut socket, heartbeat).await {
                        warn!("Failed to send heartbeat: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

/// Create a snapshot of current moderation state
async fn create_admin_snapshot(state: &Arc<RwLock<LensState>>) -> AdminEvent {
    use crate::models::{Release, ReleaseStatus};

    let state = state.read().await;

    // Count releases by status from DocumentStore
    let (pending_count, approved_count, rejected_count, pending_releases) = {
        let doc_store = state.doc_store.read().await;
        let all_releases: Vec<Release> = doc_store.list().unwrap_or_default();

        let mut pending = 0usize;
        let mut approved = 0usize;
        let mut rejected = 0usize;
        let mut pending_list = Vec::new();

        for release in all_releases {
            match release.status {
                ReleaseStatus::Pending => {
                    pending += 1;
                    pending_list.push(ReleaseInfo::from(&release));
                }
                ReleaseStatus::Approved => approved += 1,
                ReleaseStatus::Rejected => rejected += 1,
                ReleaseStatus::Deleted => {}
            }
        }

        (pending, approved, rejected, pending_list)
    };

    AdminEvent::Snapshot {
        pending_count,
        approved_count,
        rejected_count,
        pending_releases,
    }
}

/// Send an admin event over WebSocket
async fn send_admin_event(socket: &mut WebSocket, event: AdminEvent) -> Result<(), axum::Error> {
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

/// Broadcast a moderation event to all connected admins
pub fn broadcast_admin_event(tx: &AdminEventSender, event: AdminEvent) {
    // Ignore send errors (no receivers)
    let _ = tx.send(event);
}

/// Helper to broadcast a release submission event
pub fn broadcast_release_submitted(tx: &AdminEventSender, release: &Release) {
    broadcast_admin_event(
        tx,
        AdminEvent::ReleaseSubmitted {
            release: ReleaseInfo::from(release),
        },
    );
}

/// Helper to broadcast a release approval event
pub fn broadcast_release_approved(tx: &AdminEventSender, release_id: &str, moderator: &str) {
    broadcast_admin_event(
        tx,
        AdminEvent::ReleaseApproved {
            release_id: release_id.to_string(),
            moderator: moderator.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    );
}

/// Helper to broadcast a release rejection event
pub fn broadcast_release_rejected(
    tx: &AdminEventSender,
    release_id: &str,
    moderator: &str,
    reason: Option<String>,
) {
    broadcast_admin_event(
        tx,
        AdminEvent::ReleaseRejected {
            release_id: release_id.to_string(),
            moderator: moderator.to_string(),
            reason,
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    );
}

/// Helper to broadcast stats update
pub fn broadcast_stats_updated(
    tx: &AdminEventSender,
    pending: usize,
    approved: usize,
    rejected: usize,
) {
    broadcast_admin_event(
        tx,
        AdminEvent::StatsUpdated {
            pending,
            approved,
            rejected,
        },
    );
}
