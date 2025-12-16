//! HTTP API for Lens.

use crate::mesh::FloodMessage;
use crate::models::{Category, Release};
use crate::node::LensState;
use crate::ws::ws_mesh_handler;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
        .route("/api/v1/ready", get(ready))
        // Releases
        .route("/api/v1/releases", get(list_releases))
        .route("/api/v1/releases", post(create_release))
        .route("/api/v1/releases/:id", get(get_release))
        .route("/api/v1/releases/:id", delete(delete_release))
        // Categories
        .route("/api/v1/content-categories", get(list_categories))
        .route("/api/v1/content-categories", post(create_category))
        .route("/api/v1/content-categories/:id", get(get_category))
        .route("/api/v1/content-categories/:id", put(update_category))
        .route("/api/v1/content-categories/:id", delete(delete_category))
        // Featured releases (for flagship home page)
        .route("/api/v1/featured-releases", get(list_featured_releases))
        // Account (identity management)
        .route("/api/v1/account/:public_key", get(get_account))
        // Network mesh topology map
        .route("/api/v1/map", get(get_network_map))
        // Mesh state (slots, peers, TGP sessions)
        .route("/api/v1/mesh/state", get(get_mesh_state))
        // WebSocket for real-time mesh updates
        .route("/api/v1/ws/mesh", get(ws_mesh_handler))
        // Import/Export
        .route("/api/v1/import", post(import_releases))
        .route("/api/v1/export", get(export_releases))
        .route("/api/v1/admin/releases", delete(delete_all_releases))
        .layer(cors)
        .with_state(state)
}

// --- Health endpoints ---

async fn health() -> &'static str {
    "OK"
}

/// Ready check response with sync status details
#[derive(Debug, Serialize)]
struct ReadyResponse {
    ready: bool,
    synced_peers: usize,
    total_peers: usize,
    message: String,
}

/// GET /ready, /api/v1/ready - Check if node is synced and ready to serve traffic
/// Returns 200 OK when all peers are content-synced (HaveList XOR = 0)
/// Returns 503 Service Unavailable when still syncing
async fn ready(
    State(state): State<AppState>,
) -> Result<Json<ReadyResponse>, (StatusCode, Json<ReadyResponse>)> {
    let state = state.read().await;

    // Check mesh state for sync status
    let (synced, total, is_ready) = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        let (synced, total) = mesh.sync_status();
        let ready = mesh.is_content_ready();
        (synced, total, ready)
    } else {
        // No mesh state = standalone mode, trivially ready
        (0, 0, true)
    };

    let response = ReadyResponse {
        ready: is_ready,
        synced_peers: synced,
        total_peers: total,
        message: if is_ready {
            "Content ready (WantList=∅ from all peers)".to_string()
        } else {
            format!("Syncing: have all content from {}/{} peers", synced, total)
        },
    };

    if is_ready {
        Ok(Json(response))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(response)))
    }
}

// --- Release endpoints ---

async fn list_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<Release>>, StatusCode> {
    let state = state.read().await;
    let releases = state
        .storage
        .list_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(|r| r.with_defaults())
        .collect();
    Ok(Json(releases))
}

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

    // SPORE: Flood the release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding new release {}", release.id);
        }

        // SPORE: Broadcast our updated ContentHaveList so peers know our new state
        if let Ok(all_releases) = state.storage.list_releases() {
            let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
            let _ = flood_tx.send(FloodMessage::ContentHaveList {
                peer_id: "api-create".to_string(),
                release_ids,
            });
        }
    }

    Ok((StatusCode::CREATED, Json(release)))
}

async fn get_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Release>, StatusCode> {
    let state = state.read().await;
    match state.storage.get_release(&id) {
        Ok(Some(release)) => Ok(Json(release.with_defaults())),
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

async fn get_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Category>, StatusCode> {
    let state = state.read().await;
    let categories = state
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    categories
        .into_iter()
        .find(|c| c.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCategoryRequest {
    /// Public key for authentication
    public_key: String,
    id: Option<String>,
    category_id: Option<String>,
    name: Option<String>,
    display_name: Option<String>,
    slug: Option<String>,
    metadata_schema: Option<serde_json::Value>,
    featured: Option<bool>,
}

async fn create_category(
    State(state): State<AppState>,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state_read = state.read().await;

    // Check if requester is admin
    if !state_read.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to create categories"
        })));
    }
    drop(state_read);

    // Use categoryId or id
    let id = match req.category_id.or(req.id) {
        Some(id) => id,
        None => return Ok(Json(serde_json::json!({
            "error": "Category ID is required"
        }))),
    };
    // Use displayName or name
    let name = match req.display_name.or(req.name) {
        Some(name) => name,
        None => return Ok(Json(serde_json::json!({
            "error": "Category name is required"
        }))),
    };

    let category = Category::with_schema(
        id,
        name,
        req.featured.unwrap_or(false),
        req.metadata_schema,
    );

    let state = state.write().await;
    state
        .storage
        .save_category(&category)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::to_value(&category).unwrap()))
}

async fn update_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state_write = state.write().await;

    // Check if requester is admin
    if !state_write.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to update categories"
        })));
    }

    // Get existing category
    let categories = state_write
        .storage
        .list_categories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let existing = match categories.into_iter().find(|c| c.id == id) {
        Some(cat) => cat,
        None => return Ok(Json(serde_json::json!({
            "error": "Category not found"
        }))),
    };

    // Update fields
    let name = req.display_name.or(req.name).unwrap_or(existing.name);
    let category = Category::with_schema(
        id,
        name,
        req.featured.unwrap_or(existing.featured),
        req.metadata_schema.or(existing.metadata_schema),
    );

    state_write
        .storage
        .save_category(&category)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::to_value(&category).unwrap()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteCategoryRequest {
    /// Public key for authentication
    public_key: String,
}

async fn delete_category(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DeleteCategoryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.write().await;

    // Check if requester is admin
    if !state.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to delete categories"
        })));
    }

    state
        .storage
        .delete_category(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "deleted": id
    })))
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
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(|r| r.with_defaults())
        .collect();
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

/// Latency statistics over multiple time windows
#[derive(Debug, Serialize, Clone, Default)]
pub struct LatencyStats {
    /// Average latency over last 1 second
    pub last_1s_ms: Option<f64>,
    /// Average latency over last 60 seconds
    pub last_60s_ms: Option<f64>,
    /// Average latency over last hour
    pub last_1h_ms: Option<f64>,
    /// Sample count in each window
    pub samples_1s: u32,
    pub samples_60s: u32,
    pub samples_1h: u32,
}

#[derive(Debug, Serialize)]
struct PeerEdge {
    from: String,
    to: String,
    connection_type: String,  // "neighbor" or "relay"
    latency_ms: Option<u32>,  // Most recent measurement
    latency_stats: LatencyStats,  // Multi-window averages for hover display
    bidirectional: bool,
}

#[derive(Debug, Serialize)]
struct NetworkStats {
    total_nodes: u32,
    server_nodes: u32,
    browser_nodes: u32,
    total_edges: u32,
    avg_latency_ms: Option<f64>,
}

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

        // Build a map of coordinates to node IDs for SPIRAL edge computation
        use citadel_topology::{HexCoord, Neighbors};
        let mut coord_to_node: HashMap<HexCoord, String> = HashMap::new();

        // Add self to coord map if we have a slot
        if let Some(ref claim) = self_slot_opt {
            coord_to_node.insert(claim.coord, short_self_id.clone());
        }

        // First pass: collect all nodes from claimed_slots (the authoritative source)
        for (slot_index, claim) in &mesh.claimed_slots {
            let short_id = short_peer_id(&claim.peer_id);

            // Skip self (already added)
            if short_id == short_self_id {
                continue;
            }

            // Check if we're directly connected to this peer
            let (online, last_heartbeat) = if let Some(peer) = mesh.peers.get(&claim.peer_id) {
                (true, peer.last_seen.elapsed().as_secs())
            } else {
                // Check by short ID prefix match
                let connected = mesh.peers.keys().any(|k| short_peer_id(k) == short_id);
                (connected, 0)
            };

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
                last_heartbeat,
                capabilities: vec!["storage".to_string(), "relay".to_string()],
                online,
            });

            coord_to_node.insert(claim.coord, short_id);
        }

        // Second pass: compute SPIRAL edges based on actual hex neighbor topology
        // For each node, check which of its 20 theoretical neighbors exist in the mesh
        let mut seen_edges: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

        for (coord, node_id) in &coord_to_node {
            let neighbor_coords = Neighbors::of(*coord);

            for neighbor_coord in neighbor_coords {
                if let Some(neighbor_id) = coord_to_node.get(&neighbor_coord) {
                    // Create canonical edge (smaller ID first to avoid duplicates)
                    let (from, to) = if node_id < neighbor_id {
                        (node_id.clone(), neighbor_id.clone())
                    } else {
                        (neighbor_id.clone(), node_id.clone())
                    };

                    if !seen_edges.contains(&(from.clone(), to.clone())) {
                        seen_edges.insert((from.clone(), to.clone()));

                        // Look up latency stats from accountability tracker if available
                        let latency_stats = mesh.latency_history
                            .get(node_id)
                            .and_then(|history| history.get(neighbor_id))
                            .map(|h| h.compute_stats())
                            .unwrap_or_default();

                        let latency_ms = latency_stats.last_1s_ms.map(|v| v as u32);

                        edges.push(PeerEdge {
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

/// Shorten a peer ID for display (first 12 chars of hash)
pub fn short_peer_id(id: &str) -> String {
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

// --- Import/Export endpoints ---

/// Legacy Lens SDK v1 export format
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyExport {
    version: String,
    export_date: String,
    releases: Vec<LegacyRelease>,
}

/// Legacy release format from Lens SDK v1
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyRelease {
    id: String,
    posted_by: Option<LegacyPublicKey>,
    site_address: Option<String>,
    name: String,
    category_id: String,
    category_slug: Option<String>,
    #[serde(alias = "contentCID")]
    content_cid: Option<String>,
    #[serde(alias = "thumbnailCID")]
    thumbnail_cid: Option<String>,
    metadata: Option<serde_json::Value>,
}

/// Legacy public key format (byte array object)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPublicKey {
    public_key: Option<HashMap<String, u8>>,
}

/// Convert legacy public key bytes to ed25519 format
fn convert_legacy_public_key(legacy_key: &Option<LegacyPublicKey>) -> Option<String> {
    legacy_key.as_ref().and_then(|lpk| {
        lpk.public_key.as_ref().map(|key_map| {
            let mut bytes = Vec::new();
            for i in 0..32 {
                if let Some(&byte) = key_map.get(&i.to_string()) {
                    bytes.push(byte);
                }
            }
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            format!("ed25519p/{}", hex)
        })
    })
}

/// Export data format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportData {
    version: String,
    export_date: String,
    releases: Vec<Release>,
}

/// Import request with public key for authentication
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportRequest {
    public_key: String,
    data: serde_json::Value,
}

/// Import response
#[derive(Debug, Serialize)]
struct ImportResponse {
    success: bool,
    imported: usize,
    skipped: usize,
    errors: Vec<String>,
}

/// POST /api/v1/import - Import releases from legacy format
async fn import_releases(
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, StatusCode> {
    let state = state.read().await;

    // Check if requester is admin
    if !state.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(ImportResponse {
            success: false,
            imported: 0,
            skipped: 0,
            errors: vec!["Admin permission required for import".to_string()],
        }));
    }

    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    // Try to parse as legacy format
    match serde_json::from_value::<LegacyExport>(req.data.clone()) {
        Ok(legacy_export) => {
            tracing::info!(
                "Importing {} releases from legacy format v{}",
                legacy_export.releases.len(),
                legacy_export.version
            );

            for legacy_release in legacy_export.releases {
                // Check if release already exists
                if state.storage.get_release(&legacy_release.id).ok().flatten().is_some() {
                    tracing::debug!("Skipping existing release: {}", legacy_release.id);
                    skipped += 1;
                    continue;
                }

                // Convert to new format
                let creator = convert_legacy_public_key(&legacy_release.posted_by);

                let mut release = Release::new(
                    legacy_release.id.clone(),
                    legacy_release.name,
                    legacy_release.category_slug.unwrap_or(legacy_release.category_id),
                );
                release.creator = creator;
                release.thumbnail_cid = legacy_release.thumbnail_cid;
                release.content_cid = legacy_release.content_cid;
                release.site_address = legacy_release.site_address;
                // Store raw metadata for Flagship compatibility
                release.metadata = legacy_release.metadata.clone();

                // Extract metadata fields if available
                if let Some(metadata) = &legacy_release.metadata {
                    if let Some(year) = metadata.get("year").and_then(|y| y.as_u64()) {
                        release.year = Some(year as u32);
                    }
                    if let Some(desc) = metadata.get("description").and_then(|d| d.as_str()) {
                        release.description = Some(desc.to_string());
                    }
                }

                // Save release
                if let Err(e) = state.storage.put_release(&release) {
                    errors.push(format!("Failed to save release {}: {}", legacy_release.id, e));
                    continue;
                }

                // SPORE: Flood the release to propagate across mesh
                if let Some(ref flood_tx) = state.flood_tx {
                    if let Ok(json) = serde_json::to_string(&release) {
                        let _ = flood_tx.send(FloodMessage::Release { release_json: json });
                        tracing::debug!("SPORE: Flooding imported release {}", release.id);
                    }
                }

                imported += 1;
            }

            tracing::info!("Import complete: {} imported, {} skipped", imported, skipped);

            // SPORE: Broadcast our updated ContentHaveList so peers know our complete state
            if imported > 0 {
                if let Some(ref flood_tx) = state.flood_tx {
                    if let Ok(all_releases) = state.storage.list_releases() {
                        let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
                        let _ = flood_tx.send(FloodMessage::ContentHaveList {
                            peer_id: "api-import".to_string(), // API doesn't have mesh identity
                            release_ids,
                        });
                        tracing::info!("SPORE: Broadcast ContentHaveList with {} releases after import", all_releases.len());
                    }
                }
            }
        }
        Err(e) => {
            let error_msg = format!("Failed to parse import data: {}", e);
            tracing::error!("{}", error_msg);
            errors.push(error_msg);
        }
    }

    Ok(Json(ImportResponse {
        success: errors.is_empty(),
        imported,
        skipped,
        errors,
    }))
}

/// GET /api/v1/export - Export all releases
async fn export_releases(
    State(state): State<AppState>,
) -> Result<Json<ExportData>, StatusCode> {
    let state = state.read().await;

    let releases = state.storage
        .list_releases()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Exporting {} releases", releases.len());

    Ok(Json(ExportData {
        version: "2.0".to_string(),
        export_date: chrono::Utc::now().to_rfc3339(),
        releases,
    }))
}

/// Delete all releases request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteAllRequest {
    public_key: String,
}

/// DELETE /api/v1/admin/releases - Delete ALL releases
async fn delete_all_releases(
    State(state): State<AppState>,
    Json(req): Json<DeleteAllRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = state.read().await;

    // Check if requester is admin
    if !state.storage.is_admin(&req.public_key).unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Admin permission required"
        })));
    }

    match state.storage.delete_all_releases() {
        Ok(count) => {
            tracing::warn!("Deleted {} releases by admin {}", count, req.public_key);
            Ok(Json(serde_json::json!({
                "success": true,
                "deleted": count
            })))
        }
        Err(e) => {
            tracing::error!("Failed to delete releases: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

