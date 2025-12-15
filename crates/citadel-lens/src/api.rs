//! HTTP API for Lens.

use crate::models::{Category, Release};
use crate::node::LensState;
use crate::ws::ws_mesh_handler;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

type AppState = Arc<RwLock<LensState>>;

/// Build the API router.
pub fn build_router(state: AppState) -> Router {
    // CORS layer for browser access
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health (at root and under /api/v1 for compatibility)
        .route("/health", get(health))
        .route("/api/v1/health", get(health))
        .route("/ready", get(ready))
        .nest("/api/v1",
            // Releases
            .route("/releases", get(list_releases))
            .route("/releases", post(create_release))
            .route("/releases/:id", get(get_release))
            .route("/releases/:id", delete(delete_release))
            // Categories
            .route("/content-categories", get(list_categories))
            // Featured releases (for flagship home page)
            .route("/featured-releases", get(list_featured_releases))
            // Account (identity management)
            .route("/account/:public_key", get(get_account))
            // Network mesh topology map
            .route("/map", get(get_network_map))
            // Mesh state (slots, peers, TGP sessions)
            .route("/mesh/state", get(get_mesh_state))
            // WebSocket for real-time mesh updates
            .route("/ws/mesh", get(ws_mesh_handler))
        )
        .layer(cors)
        .with_state(state)
}

// --- Health endpoints ---

async fn health() -> &'static str {
    "OK"
}

async fn ready() -> &'static str {
    "OK"
}

// --- Release endpoints ---

async fn list_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<Release>>, StatusCode> {
    let state = state.read().await;
    let releases = state
        .storage
        .list_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(releases))
}

// Ben Review: Premature optimisation possible: instead of String, some sort of optimised string
// such as a Cow.
#[derive(Debug, Deserialize)]
struct CreateReleaseRequest {
    title: String,
    category_id: String,
    creator: Option<String>,
    year: Option<u32>,
    description: Option<String>,
    tags: Option<Vec<String>>,
}

async fn create_release(
    State(state): State<AppState>,
    Json(req): Json<CreateReleaseRequest>,
) -> Result<(StatusCode, Json<Release>), StatusCode> {
    // Generate ID from title + timestamp
    let content = format!("{}:{}", req.title, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());
    let id = Release::generate_id(content.as_bytes());

    let mut release = Release::new(id, req.title, req.category_id);
    release.creator = req.creator;
    release.year = req.year;
    release.description = req.description;
    release.tags = req.tags.unwrap_or_default();

    let state = state.read().await;
    state
        .storage
        .put_release(&release)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(release)))
}

async fn get_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Release>, StatusCode> {
    let state = state.read().await;
    match state.storage.get_release(&id) {
        Ok(Some(release)) => Ok(Json(release)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn delete_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    let state = state.read().await;
    match state.storage.delete_release(&id) {
        Ok(()) => StatusCode::NO_CONTENT,
        // BenPH review: log the actual error
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// --- Category endpoints ---

async fn list_categories(
    State(state): State<AppState>,
) -> Result<Json<Vec<Category>>, StatusCode> {
    let state = state.read().await;
    let categories = state
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(categories))
}

// --- Featured releases endpoints ---

async fn list_featured_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<Release>>, StatusCode> {
    let state = state.read().await;
    // For now, featured releases are just the most recent releases
    let releases = state
        .storage
        .list_releases()
        // BenPH review: log the actual error
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(releases))
}

// --- Account endpoints ---

/// Account status response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountStatus {
    public_key: String,
    is_admin: bool,
    roles: Vec<String>,
    permissions: Vec<String>,
}

async fn get_account(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> Result<Json<AccountStatus>, StatusCode> {
    let state = state.read().await;

    // Check if this public key is an admin (managed via lens-admin CLI)
    let is_admin = state.storage.is_admin(&public_key).unwrap_or(false);

    let (roles, permissions) = if is_admin {
        (
            vec!["admin".to_string()],
            vec![
                "upload".to_string(),
                "delete".to_string(),
                "moderate".to_string(),
                "admin".to_string(),
            ],
        )
    } else {
        // Regular user - check if they have upload permission
        let has_upload = state.storage.has_permission(&public_key, "upload").unwrap_or(false);
        let permissions = if has_upload {
            vec!["upload".to_string()]
        } else {
            vec![]
        };
        (vec!["user".to_string()], permissions)
    };

    Ok(Json(AccountStatus {
        public_key,
        is_admin,
        roles,
        permissions,
    }))
}

// --- Network Map endpoints ---

/// Network map showing actual mesh state (emergent topology, no predefined dimensions)
#[derive(Debug, Serialize)]
struct NetworkMap {
    /// This node's view of the mesh
    self_node: PeerNode,
    /// All known nodes in the mesh
    nodes: Vec<PeerNode>,
    /// Active connections between nodes
    edges: Vec<PeerEdge>,
    /// Live mesh statistics
    stats: NetworkStats,
}

#[derive(Debug, Clone, Serialize)]
struct PeerNode {
    id: String,
    label: String,
    /// Hex coordinates in the mesh (emergent from node ID hash)
    slot: HexSlot,
    peer_type: String,
    last_heartbeat: u64,
    capabilities: Vec<String>,
    online: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HexSlot {
    /// SPIRAL index (slot number in enumeration order)
    index: Option<u64>,
    /// Hex axial coordinate q
    q: i64,
    /// Hex axial coordinate r
    r: i64,
    /// Vertical layer z (2.5D)
    z: i64,
}

#[derive(Debug, Serialize)]
struct PeerEdge {
    from: String,
    to: String,
    connection_type: String,  // "neighbor" or "relay"
    // BenPH review: consider using us with u64
    latency_ms: Option<u32>,
    bidirectional: bool,
}

#[derive(Debug, Serialize)]
struct NetworkStats {
    total_nodes: u32,
    server_nodes: u32,
    browser_nodes: u32,
    total_edges: u32,
    // BenPH review: consider using us with u64
    avg_latency_ms: Option<f64>,
}

// BenPH review: This is a particularly long function. consider refactoring
async fn get_network_map(
    State(state): State<AppState>,
) -> Json<NetworkMap> {
    let state = state.read().await;
    let config = &state.config;

    // Get our actual PeerID and SPIRAL slot from mesh state
    let (self_id, self_slot_opt) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        (mesh.self_id.clone(), mesh.self_slot.clone())
    } else {
        (format!("lens-{}", config.p2p_addr.port()), None)
    };

    // Pure SPIRAL slot - only use actual claimed slot
    let slot = if let Some(ref claim) = self_slot_opt {
        HexSlot {
            index: Some(claim.index),
            q: claim.coord.q,
            r: claim.coord.r,
            z: claim.coord.z,
        }
    } else {
        // BenPH review: consider use of Derive(default)
        //  - the `self_slot_opt` can be initialised with `unwrap_or_default()`
        // No slot claimed yet - position at origin until claimed
        HexSlot { index: None, q: 0, r: 0, z: 0 }
    };

    let short_self_id = short_peer_id(&self_id);
    let self_node = PeerNode {
        id: short_self_id.clone(),
        label: short_self_id.clone(),  // Use peer ID as label, not IP
        slot: slot.clone(),
        peer_type: "server".to_string(),
        last_heartbeat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        capabilities: vec!["storage".to_string(), "relay".to_string(), "api".to_string()],
        online: true,
    };

    // Query actual mesh state from mesh service
    let mut nodes = vec![self_node.clone()];
    let mut edges = Vec::new();

    if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;

        // BenPH review: use an iterator, map and collect, or declare nodes and edges with an
        // expected capacity. Should already be handled via optimiser, but clearly stating intent
        // can help
        // Add all connected peers as nodes
        // Use peer_id (hashmap key) as authoritative ID - gets updated from hello
        for (peer_id, peer) in &mesh.peers {
            let short_id = short_peer_id(peer_id);

            // Pure SPIRAL - only use actual claimed slots from mesh state
            let peer_slot = if let Some(ref claim) = peer.slot {
                HexSlot {
                    index: Some(claim.index),
                    q: claim.coord.q,
                    r: claim.coord.r,
                    z: claim.coord.z,
                }
            } else if let Some(claim) = mesh.claimed_slots.values().find(|c| c.peer_id == *peer_id) {
                // Check global claims for this peer
                HexSlot {
                    index: Some(claim.index),
                    q: claim.coord.q,
                    r: claim.coord.r,
                    z: claim.coord.z,
                }
            } else {
                // No slot claimed yet
                HexSlot { index: None, q: 0, r: 0, z: 0 }
            };

            nodes.push(PeerNode {
                id: short_id.clone(),
                label: short_id.clone(),  // Use peer ID as label, not IP
                slot: peer_slot,
                peer_type: "server".to_string(),
                last_heartbeat: peer.last_seen.elapsed().as_secs(),
                capabilities: vec!["storage".to_string(), "relay".to_string()],
                online: true,
            });

            // Add edge from self to peer
            // Note: latency_ms is None until we implement actual RTT measurement
            // (last_seen.elapsed() is time since last message, NOT network latency)
            edges.push(PeerEdge {
                from: short_self_id.clone(),
                to: short_id,
                connection_type: if peer.coordinated { "neighbor" } else { "bootstrap" }.to_string(),
                latency_ms: None,
                bidirectional: true,
            });
        }

        // Also add nodes from claimed_slots that we've learned about via SPORE flooding
        // but aren't directly connected to (these are known but indirect peers)
        let known_ids: std::collections::HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
        for (slot_index, claim) in &mesh.claimed_slots {
            let short_id = short_peer_id(&claim.peer_id);
            if !known_ids.contains(&short_id) {
                // Add this node we've heard about through flooding
                nodes.push(PeerNode {
                    id: short_id.clone(),
                    label: short_id.clone(),
                    slot: HexSlot {
                        index: Some(*slot_index),
                        q: claim.coord.q,
                        r: claim.coord.r,
                        z: claim.coord.z,
                    },
                    peer_type: "server".to_string(),
                    last_heartbeat: 0,  // Unknown - not directly connected
                    capabilities: vec!["storage".to_string(), "relay".to_string()],
                    online: true,  // Assume online since we received their claim
                });
            }
        }
    }

    let stats = NetworkStats {
        total_nodes: nodes.len() as u32,
        server_nodes: nodes.iter().filter(|n| n.peer_type == "server").count() as u32,
        browser_nodes: nodes.iter().filter(|n| n.peer_type == "browser").count() as u32,
        total_edges: edges.len() as u32,
        avg_latency_ms: if edges.is_empty() {
            None
        } else {
            let total: u32 = edges.iter().filter_map(|e| e.latency_ms).sum();
            Some(total as f64 / edges.len() as f64)
        },
    };

    Json(NetworkMap {
        self_node,
        nodes,
        edges,
        stats,
    })
}

// BenPH review: this can likely return an &str based on the input id
/// Extract short ID from peer ID (strips "b3b3/" prefix, shows first 12 chars)
fn short_peer_id(id: &str) -> String {
    let hash = id.strip_prefix("b3b3/").unwrap_or(id);
    hash.chars().take(12).collect()
}

// --- Mesh State endpoint ---

#[derive(Debug, Serialize)]
struct MeshStateResponse {
    /// Our peer ID
    self_id: String,
    /// Our claimed slot (if any)
    our_slot: Option<SlotInfo>,
    /// Number of connected peers
    peer_count: usize,
    /// All claimed slots in the mesh
    slot_claims: Vec<SlotInfo>,
    /// Connected peers
    peers: Vec<PeerSummary>,
    /// Active TGP sessions count
    tgp_sessions: usize,
}

#[derive(Debug, Serialize)]
struct SlotInfo {
    index: u64,
    peer_id: String,
    coord: CoordInfo,
}

#[derive(Debug, Serialize)]
struct CoordInfo {
    q: i64,
    r: i64,
    z: i64,
}

#[derive(Debug, Serialize)]
struct PeerSummary {
    id: String,
    addr: String,
    slot: Option<u64>,
    coordinated: bool,
    last_seen_ms: u64,
}

// BenPH review: state could probably be bassed in as a `RwLockReadGuard<AppState>`
async fn get_mesh_state(
    State(state): State<AppState>,
) -> Json<MeshStateResponse> {
    let state = state.read().await;

    let (self_id, our_slot, peer_count, slot_claims, peers) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;

        let our_slot = mesh.self_slot.as_ref().map(|s| SlotInfo {
            index: s.index,
            peer_id: short_peer_id(&mesh.self_id),
            coord: CoordInfo { q: s.coord.q, r: s.coord.r, z: s.coord.z },
        });

        let slot_claims: Vec<SlotInfo> = mesh.claimed_slots.iter()
            .map(|(idx, claim)| SlotInfo {
                index: *idx,
                peer_id: short_peer_id(&claim.peer_id),
                coord: CoordInfo { q: claim.coord.q, r: claim.coord.r, z: claim.coord.z },
            })
            .collect();

        let peers: Vec<PeerSummary> = mesh.peers.iter()
            .map(|(id, peer)| PeerSummary {
                id: short_peer_id(id),
                addr: peer.addr.to_string(),
                slot: peer.slot.as_ref().map(|s| s.index),
                coordinated: peer.coordinated,
                last_seen_ms: peer.last_seen.elapsed().as_millis() as u64,
            })
            .collect();

        (mesh.self_id.clone(), our_slot, mesh.peers.len(), slot_claims, peers)
    } else {
        (String::new(), None, 0, Vec::new(), Vec::new())
    };

    Json(MeshStateResponse {
        self_id: short_peer_id(&self_id),
        our_slot,
        peer_count,
        slot_claims,
        peers,
        tgp_sessions: 0, // TODO: expose TGP session count
    })
}

