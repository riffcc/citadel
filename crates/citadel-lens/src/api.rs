//! HTTP API for Lens.

use crate::admin_socket;
use crate::mesh::{double_hash_id, FloodMessage};
use crate::models::{
    Category, FeaturedRelease, Release, ReleaseQuality, ReleaseStatus, RendererMode, SiteManifest,
};
use crate::node::LensState;
use crate::ws::ws_mesh_handler;
use crate::ws_admin;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post, put},
    Json, Router,
};
use citadel_crdt::ContentId;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

// ============================================================================
// SIGNED REQUEST AUTHENTICATION
// ============================================================================
// All write endpoints require:
// 1. A valid ed25519 public key (in "ed25519p/{hex}" format)
// 2. A signature over the message (format: "{timestamp}:{body}" or "{timestamp}:{method}:{path}")
// 3. The public key must be in the admin list
//
// For POST/PUT: signature is over "{timestamp}:{json_body}"
// For DELETE: signature is over "{timestamp}:DELETE:{path}"
// The timestamp header (X-Timestamp) must be provided to reconstruct the signed message.
// ============================================================================

/// Verify an ed25519 signature over a message.
///
/// # Arguments
/// * `public_key` - The public key in "ed25519p/{hex}" format
/// * `message` - The message that was signed (the request body)
/// * `signature_hex` - The signature in hex format
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(String)` with an error message if verification fails
fn verify_signature(public_key: &str, message: &[u8], signature_hex: &str) -> Result<(), String> {
    // Parse public key (format: "ed25519p/{hex}")
    let key_hex = public_key
        .strip_prefix("ed25519p/")
        .ok_or_else(|| "Invalid public key format: must start with 'ed25519p/'")?;

    let key_bytes = hex::decode(key_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!(
            "Invalid public key length: expected 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "Failed to convert public key to array")?;

    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|e| format!("Invalid public key: {}", e))?;

    // Parse signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "Invalid signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Failed to convert signature to array")?;

    let signature = Signature::from_bytes(&sig_array);

    // Verify
    verifying_key
        .verify(message, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

/// Helper to check if a request is properly signed by an admin.
///
/// This is the main authentication function for write endpoints.
/// It verifies:
/// 1. The signature is valid for the given public key and message
/// 2. The public key is in the admin list
///
/// # Arguments
/// * `storage` - The storage backend to check admin status
/// * `public_key` - The public key claiming to sign the request
/// * `signature` - The hex-encoded signature
/// * `timestamp` - The timestamp from X-Timestamp header
/// * `body` - The request body bytes (for POST/PUT)
///
/// # Returns
/// * `Ok(())` if authenticated as admin
/// * `Err(String)` with error message if not
fn require_admin_signature(
    storage: &crate::storage::Storage,
    public_key: &str,
    signature: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<(), String> {
    // Reconstruct the signed message: "{timestamp}:{body}"
    // This matches what Flagship signs
    let body_str =
        std::str::from_utf8(body).map_err(|e| format!("Invalid UTF-8 in request body: {}", e))?;
    let message = format!("{}:{}", timestamp, body_str);

    // Verify the signature
    verify_signature(public_key, message.as_bytes(), signature)?;

    // Then check if the key is an admin
    if !storage.is_admin(public_key).unwrap_or(false) {
        return Err(format!("Public key {} is not an admin", public_key));
    }

    Ok(())
}

/// Helper to check if a DELETE request is properly signed by an admin.
///
/// For DELETE requests, the message format is "{timestamp}:DELETE:{path}"
fn require_admin_signature_delete(
    storage: &crate::storage::Storage,
    public_key: &str,
    signature: &str,
    timestamp: &str,
    path: &str,
) -> Result<(), String> {
    // Reconstruct the signed message: "{timestamp}:DELETE:{path}"
    let message = format!("{}:DELETE:{}", timestamp, path);

    // Verify the signature
    verify_signature(public_key, message.as_bytes(), signature)?;

    // Then check if the key is an admin
    if !storage.is_admin(public_key).unwrap_or(false) {
        return Err(format!("Public key {} is not an admin", public_key));
    }

    Ok(())
}

fn node_id_from_public_key(public_key: &str) -> Option<[u8; 8]> {
    let key_hex = public_key.strip_prefix("ed25519p/").unwrap_or(public_key);

    let key_bytes = hex::decode(key_hex).ok()?;
    if key_bytes.is_empty() {
        return None;
    }

    let hash = blake3::hash(&key_bytes);
    let mut node_id = [0u8; 8];
    node_id.copy_from_slice(&hash.as_bytes()[..8]);
    Some(node_id)
}

fn node_public_key(storage: &crate::storage::Storage) -> Result<String, String> {
    let signing_key = storage
        .get_or_create_node_key()
        .map_err(|e| format!("Failed to read node identity: {}", e))?;
    Ok(format!(
        "ed25519p/{}",
        hex::encode(signing_key.verifying_key().as_bytes())
    ))
}

fn signed_headers(
    headers: &HeaderMap,
) -> Result<(&str, &str, &str), (StatusCode, Json<serde_json::Value>)> {
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing X-Public-Key header" })),
            )
        })?;
    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing X-Signature header" })),
            )
        })?;
    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Missing X-Timestamp header" })),
            )
        })?;
    Ok((public_key, signature, timestamp))
}

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
        .route("/api/v1/releases/:id", put(update_release))
        .route("/api/v1/releases/:id", delete(delete_release))
        // Moderation endpoints (admin only)
        .route("/api/v1/releases/pending", get(list_pending_releases))
        .route("/api/v1/releases/:id/approve", post(approve_release))
        .route("/api/v1/releases/:id/reject", post(reject_release))
        .route("/api/v1/moderation/stats", get(moderation_stats))
        // Categories
        .route("/api/v1/content-categories", get(list_categories))
        .route("/api/v1/content-categories", post(create_category))
        .route("/api/v1/content-categories/:id", get(get_category))
        .route("/api/v1/content-categories/:id", put(update_category))
        .route("/api/v1/content-categories/:id", delete(delete_category))
        // Site manifest
        .route("/api/v1/site", get(get_site))
        .route("/api/v1/site", put(update_site))
        // Compatibility: Flagship still queries structures even when the current
        // Citadel deployment has no structure backend enabled yet.
        .route("/api/v1/structures", get(list_structures))
        // Featured releases (for flagship home page)
        .route("/api/v1/featured-releases", get(list_featured_releases))
        // Admin: Featured releases management
        .route(
            "/api/v1/admin/featured-releases",
            post(create_featured_release),
        )
        .route(
            "/api/v1/admin/featured-releases/:id",
            get(get_featured_release),
        )
        .route(
            "/api/v1/admin/featured-releases/:id",
            put(update_featured_release),
        )
        .route(
            "/api/v1/admin/featured-releases/:id",
            delete(delete_featured_release),
        )
        // Account (identity management)
        .route("/api/v1/account/:public_key", get(get_account))
        // Upload permission validation (for nginx auth_request)
        .route("/api/v1/validate-upload", get(validate_upload))
        // Network mesh topology map
        .route("/api/v1/map", get(get_network_map))
        // Mesh state (slots and live peers)
        .route("/api/v1/mesh/state", get(get_mesh_state))
        // WebSocket for real-time mesh updates
        .route("/api/v1/ws/mesh", get(ws_mesh_handler))
        // WebSocket for real-time admin moderation updates
        .route("/api/v1/ws/admin", get(ws_admin::ws_admin_handler))
        // Import/Export
        .route("/api/v1/import", post(import_releases))
        .route("/api/v1/export", get(export_releases))
        .route("/api/v1/admin/releases", delete(delete_all_releases))
        // Admin API (for lens-admin CLI with --url)
        .route("/api/admin/ping", post(admin_ping))
        .route("/api/admin/add-admin", post(admin_add_admin))
        .route("/api/admin/remove-admin", post(admin_remove_admin))
        .route("/api/admin/grant-upload", post(admin_grant_upload))
        .route("/api/admin/revoke-upload", post(admin_revoke_upload))
        .route("/api/admin/list-admins", post(admin_list_admins))
        .route("/api/admin/is-admin", post(admin_is_admin))
        .route("/api/admin/start-profiling", post(admin_start_profiling))
        .route("/api/admin/stop-profiling", post(admin_stop_profiling))
        .route("/api/admin/cpu-profile", post(admin_cpu_profile))
        .route("/api/admin/mem-profile", post(admin_mem_profile))
        .route("/api/admin/mesh-stats", post(admin_mesh_stats))
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

/// Query parameters for listing releases
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListReleasesQuery {
    /// If true, include all releases (pending, approved, rejected) - admin only
    #[serde(default)]
    include_all: bool,
    /// Filter by specific status
    status: Option<String>,
}

async fn list_releases(
    State(state): State<AppState>,
    Query(params): Query<ListReleasesQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<Release>>, StatusCode> {
    let state = state.read().await;

    // Check if caller is admin (for include_all)
    let is_admin = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .map(|pk| state.storage.is_admin(pk).unwrap_or(false))
        .unwrap_or(false);

    // Use DocumentStore for CRDT-based sync
    let releases = {
        let doc_store = state.doc_store.read().await;
        doc_store.list::<Release>().map_err(|e| {
            tracing::error!("DocumentStore list failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    // Filter releases based on params
    let filtered: Vec<Release> = if params.include_all && is_admin {
        // Admin requested all releases
        releases
    } else if let Some(status_str) = params.status {
        // Filter by specific status
        let target_status = match status_str.to_lowercase().as_str() {
            "pending" => ReleaseStatus::Pending,
            "approved" => ReleaseStatus::Approved,
            "rejected" => ReleaseStatus::Rejected,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        releases
            .into_iter()
            .filter(|r| r.status == target_status)
            .collect()
    } else {
        // Default: return only approved releases (public catalog)
        releases
            .into_iter()
            .filter(|r| r.status == ReleaseStatus::Approved)
            .collect()
    };

    Ok(Json(
        filtered.into_iter().map(|r| r.with_defaults()).collect(),
    ))
}

async fn list_structures() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

/// Request for creating a release.
/// Accepts both camelCase (Flagship) and snake_case field names.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateReleaseRequest {
    /// Title/name of the release
    #[serde(alias = "title")]
    name: String,
    /// Category ID
    #[serde(alias = "category_id")]
    category_id: String,
    /// Creator/artist (optional)
    #[serde(alias = "postedBy")]
    creator: Option<String>,
    /// Release year (optional)
    year: Option<u32>,
    /// Description (optional)
    description: Option<String>,
    /// Tags (optional)
    tags: Option<Vec<String>>,
    /// Content CID (optional)
    #[serde(alias = "content_cid", alias = "contentCID")]
    content_cid: Option<String>,
    /// Optional named quality variants for this release
    qualities: Option<Vec<ReleaseQuality>>,
    /// Thumbnail CID (optional)
    #[serde(alias = "thumbnail_cid", alias = "thumbnailCID")]
    thumbnail_cid: Option<String>,
    /// Arbitrary metadata (optional) - for artist type, series, etc.
    metadata: Option<serde_json::Value>,
    /// Initial status (optional) - admins can create as "pending" for moderation
    /// Defaults to "approved" for backward compatibility
    #[serde(default)]
    status: Option<String>,
}

async fn create_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Release>), (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            tracing::warn!("Auth failed for create_release: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    // Parse the request body
    let req: CreateReleaseRequest = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })),
        )
    })?;

    // Generate ID from name + timestamp
    let content = format!(
        "{}:{}",
        req.name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let id = Release::generate_id(content.as_bytes());

    // BadBits: Check if this release is on the permanent blocklist
    // (DMCA, abuse material, illegal content - prevents re-upload)
    {
        let state = state.read().await;
        if let Some(ref mesh_state) = state.mesh_state {
            let mesh = mesh_state.read().await;
            let release_hash = double_hash_id(&id);
            if mesh.bad_bits.contains(&release_hash) {
                tracing::warn!(
                    "BadBits: Rejected upload of blocked content (hash matches blocklist)"
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "Content is on blocklist"
                    })),
                ));
            }
        }
    }

    let mut release = Release::new(id, req.name, req.category_id);
    release.creator = req.creator;
    release.year = req.year;
    release.description = req.description;
    release.tags = req.tags.unwrap_or_default();
    release.content_cid = req.content_cid;
    release.qualities = req.qualities.unwrap_or_default();
    release.thumbnail_cid = req.thumbnail_cid;
    release.metadata = req.metadata;
    release.ensure_primary_content_cid();

    // Set status if provided (admin can create as pending for moderation queue)
    if let Some(status_str) = req.status {
        release.status = match status_str.to_lowercase().as_str() {
            "pending" => ReleaseStatus::Pending,
            "rejected" => ReleaseStatus::Rejected,
            _ => ReleaseStatus::Approved, // Default to approved
        };
    }

    if let Some(node_id) = node_id_from_public_key(public_key) {
        release.init_version(node_id);
    }

    let state = state.read().await;

    // Save to DocumentStore (CRDT path with automatic merge)
    {
        let mut doc_store = state.doc_store.write().await;
        let (_, _changed) = doc_store.put(&release).map_err(|e| {
            tracing::error!("DocumentStore put failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to save release"
                })),
            )
        })?;
        tracing::info!("Created release {} in DocumentStore", release.id);
    }

    // SPORE: Flood the release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding new release {}", release.id);
        }

        // SPORE: Broadcast our updated ContentHaveList so peers know our new state
        {
            let doc_store = state.doc_store.read().await;
            if let Ok(all_releases) = doc_store.list::<Release>() {
                let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
                let _ = flood_tx.send(FloodMessage::ContentHaveList {
                    peer_id: "api-create".to_string(),
                    release_ids,
                });
            }
        }
    }

    // Broadcast to admin WebSocket subscribers if release is pending moderation
    if release.status == ReleaseStatus::Pending {
        if let Some(ref admin_tx) = state.admin_event_tx {
            ws_admin::broadcast_release_submitted(admin_tx, &release);
        }
    }

    Ok((StatusCode::CREATED, Json(release)))
}

async fn get_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Release>, StatusCode> {
    let state = state.read().await;

    let doc_store = state.doc_store.read().await;
    let content_id = citadel_crdt::ContentId::hash(id.as_bytes());
    match doc_store.get::<Release>(&content_id) {
        Ok(Some(release)) => Ok(Json(release.with_defaults())),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Request for updating a release (same fields as create, all optional except what's changing)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateReleaseRequest {
    /// Title/name of the release
    #[serde(alias = "title")]
    name: Option<String>,
    /// Category ID (frontend sends categoryId)
    #[serde(alias = "categoryId")]
    category_id: Option<String>,
    /// Creator/artist (optional) - frontend may send postedBy
    #[serde(alias = "postedBy")]
    creator: Option<String>,
    /// Release year (optional)
    year: Option<u32>,
    /// Description (optional)
    description: Option<String>,
    /// Tags (optional)
    tags: Option<Vec<String>>,
    /// Content CID (frontend sends contentCID)
    #[serde(alias = "contentCID")]
    content_cid: Option<String>,
    /// Optional named quality variants for this release
    qualities: Option<Vec<ReleaseQuality>>,
    /// Thumbnail CID (frontend sends thumbnailCID)
    #[serde(alias = "thumbnailCID")]
    thumbnail_cid: Option<String>,
    /// Site address (frontend sends siteAddress)
    #[serde(alias = "siteAddress")]
    site_address: Option<String>,
    /// Arbitrary metadata (optional)
    metadata: Option<serde_json::Value>,
}

async fn update_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Release>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            tracing::warn!("Auth failed for update_release: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    // Parse the request body
    let req: UpdateReleaseRequest = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })),
        )
    })?;

    let state = state.read().await;

    // Get existing release from doc_store
    let mut release = {
        let doc_store = state.doc_store.read().await;
        let content_id = citadel_crdt::ContentId::hash(id.as_bytes());
        match doc_store.get::<Release>(&content_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "Release not found"
                    })),
                ))
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to get release"
                    })),
                ))
            }
        }
    };

    // Update fields if provided
    if let Some(name) = req.name {
        release.title = name;
    }
    if let Some(category_id) = req.category_id {
        release.category_id = category_id.clone();
        release.category_slug = Some(category_id);
    }
    if let Some(creator) = req.creator {
        release.creator = Some(creator);
    }
    if let Some(year) = req.year {
        release.year = Some(year);
    }
    if let Some(description) = req.description {
        release.description = Some(description);
    }
    if let Some(tags) = req.tags {
        release.tags = tags;
    }
    if let Some(content_cid) = req.content_cid {
        release.content_cid = Some(content_cid);
    }
    if let Some(qualities) = req.qualities {
        release.qualities = qualities;
    }
    if let Some(thumbnail_cid) = req.thumbnail_cid {
        release.thumbnail_cid = Some(thumbnail_cid);
    }
    if let Some(site_address) = req.site_address {
        release.site_address = Some(site_address);
    }
    if let Some(new_metadata) = req.metadata {
        // Merge new metadata with existing metadata instead of replacing
        if let Some(existing) = release.metadata.as_mut() {
            if let (Some(existing_obj), Some(new_obj)) =
                (existing.as_object_mut(), new_metadata.as_object())
            {
                for (key, value) in new_obj {
                    existing_obj.insert(key.clone(), value.clone());
                }
            } else {
                // If not both objects, just replace
                release.metadata = Some(new_metadata);
            }
        } else {
            release.metadata = Some(new_metadata);
        }
    }
    release.ensure_primary_content_cid();

    // Update modified_at for LWW merge semantics
    release.modified_at = chrono::Utc::now().to_rfc3339();

    if let Some(node_id) = node_id_from_public_key(public_key) {
        release.update_version(node_id);
    }

    // Save updated release to DocumentStore (CRDT merge)
    {
        let mut doc_store = state.doc_store.write().await;
        let (_, _changed) = doc_store.put(&release).map_err(|e| {
            tracing::error!("DocumentStore put failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to save release"
                })),
            )
        })?;
        tracing::debug!("Updated release {} in DocumentStore", release.id);
    }

    // SPORE: Flood the updated release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding updated release {}", release.id);
        }
    }

    Ok(Json(release.with_defaults()))
}

async fn delete_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // For DELETE, signature is over "{timestamp}:DELETE:/releases/{id}"
    let path = format!("/releases/{}", id);

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature_delete(&state.storage, public_key, signature, timestamp, &path)
        {
            tracing::warn!("Auth failed for delete_release: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    let state = state.read().await;

    // Delete from DocumentStore
    {
        let content_id = citadel_crdt::ContentId::hash(id.as_bytes());
        let mut doc_store = state.doc_store.write().await;
        if let Err(e) = doc_store.delete::<Release>(&content_id) {
            tracing::warn!("Failed to delete release from DocumentStore: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to delete release"
                })),
            ));
        }
        tracing::debug!("Deleted release {} from DocumentStore", id);
    }

    // SPORE⁻¹: Compute double-hash tombstone and add to DoNotWantList
    let tombstone = double_hash_id(&id);

    // Add to mesh state's do_not_want set using SPORE⁻¹
    if let Some(ref mesh_state) = state.mesh_state {
        let mut mesh = mesh_state.write().await;
        let is_new = mesh.add_tombstone(tombstone);
        let self_id = mesh.self_id.clone();
        let do_not_want = mesh.do_not_want_spore().clone();
        drop(mesh); // Release lock before flooding

        // Flood the do_not_want Spore to propagate deletion through mesh
        if is_new {
            if let Some(ref flood_tx) = state.flood_tx {
                let _ = flood_tx.send(FloodMessage::DoNotWantList {
                    peer_id: self_id,
                    do_not_want,
                });
                tracing::info!("SPORE⁻¹: Flooding tombstone for deleted release {}", id);
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

// --- Moderation endpoints ---

/// GET /api/v1/releases/pending - List all pending releases (admin only)
async fn list_pending_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Release>>, (StatusCode, Json<serde_json::Value>)> {
    // Extract and verify admin
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let state = state.read().await;

    if !state.storage.is_admin(public_key).unwrap_or(false) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Admin permission required"
            })),
        ));
    }

    // List pending releases from DocumentStore (CRDT path)
    let releases: Vec<Release> = {
        let doc_store = state.doc_store.read().await;
        doc_store
            .list::<Release>()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.status == ReleaseStatus::Pending)
            .map(|r| r.with_defaults())
            .collect()
    };

    Ok(Json(releases))
}

/// Request body for approving a release
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproveReleaseRequest {
    // Empty for now, but allows for future fields like notes
}

/// POST /api/v1/releases/:id/approve - Approve a pending release (admin only)
async fn approve_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Release>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            tracing::warn!("Auth failed for approve_release: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    let state = state.read().await;

    // Get release from doc_store
    let mut release = {
        let doc_store = state.doc_store.read().await;
        let content_id = citadel_crdt::ContentId::hash(id.as_bytes());
        match doc_store.get::<Release>(&content_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "Release not found"
                    })),
                ))
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to get release"
                    })),
                ))
            }
        }
    };

    // Approve the release
    release.approve(public_key);
    release.modified_at = chrono::Utc::now().to_rfc3339();

    // Save to doc_store
    {
        let mut doc_store = state.doc_store.write().await;
        match doc_store.put(&release) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to save approved release to DocumentStore: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to approve release"
                    })),
                ));
            }
        }
    }

    tracing::info!("Release {} approved by {}", id, public_key);

    // SPORE: Flood the approved release to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding approved release {}", release.id);
        }
    }

    // Broadcast to admin WebSocket subscribers
    if let Some(ref admin_tx) = state.admin_event_tx {
        ws_admin::broadcast_release_approved(admin_tx, &id, public_key);
    }

    Ok(Json(release.with_defaults()))
}

/// Request body for rejecting a release
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectReleaseRequest {
    /// Optional reason for rejection
    reason: Option<String>,
}

/// POST /api/v1/releases/:id/reject - Reject a pending release (admin only)
async fn reject_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Release>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            tracing::warn!("Auth failed for reject_release: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    // Parse the request body for rejection reason
    let req: RejectReleaseRequest =
        serde_json::from_slice(&body).unwrap_or(RejectReleaseRequest { reason: None });

    let state = state.read().await;

    // Get release from doc_store
    let mut release = {
        let doc_store = state.doc_store.read().await;
        let content_id = citadel_crdt::ContentId::hash(id.as_bytes());
        match doc_store.get::<Release>(&content_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "Release not found"
                    })),
                ))
            }
            Err(_) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to get release"
                    })),
                ))
            }
        }
    };

    // Reject the release
    release.reject(public_key, req.reason.clone());
    release.modified_at = chrono::Utc::now().to_rfc3339();

    // Save to doc_store
    {
        let mut doc_store = state.doc_store.write().await;
        match doc_store.put(&release) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to save rejected release to DocumentStore: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to reject release"
                    })),
                ));
            }
        }
    }

    tracing::info!(
        "Release {} rejected by {} (reason: {:?})",
        id,
        public_key,
        req.reason
    );

    // SPORE: Flood the updated release status to propagate across mesh
    if let Some(ref flood_tx) = state.flood_tx {
        if let Ok(json) = serde_json::to_string(&release) {
            let _ = flood_tx.send(FloodMessage::Release { release_json: json });
            tracing::debug!("SPORE: Flooding rejected release {}", release.id);
        }
    }

    // Broadcast to admin WebSocket subscribers
    if let Some(ref admin_tx) = state.admin_event_tx {
        ws_admin::broadcast_release_rejected(admin_tx, &id, public_key, req.reason.clone());
    }

    Ok(Json(release.with_defaults()))
}

/// Moderation statistics response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModerationStatsResponse {
    pending: usize,
    approved: usize,
    rejected: usize,
    total: usize,
}

/// GET /api/v1/moderation/stats - Get release counts by status (admin only)
async fn moderation_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ModerationStatsResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract and verify admin
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let state = state.read().await;

    if !state.storage.is_admin(public_key).unwrap_or(false) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Admin permission required"
            })),
        ));
    }

    // Count releases by status from DocumentStore
    let (pending, approved, rejected) = {
        let doc_store = state.doc_store.read().await;
        let releases = doc_store.list::<Release>().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get moderation stats"
                })),
            )
        })?;
        let mut pending = 0usize;
        let mut approved = 0usize;
        let mut rejected = 0usize;
        for r in &releases {
            match r.status {
                ReleaseStatus::Pending => pending += 1,
                ReleaseStatus::Approved => approved += 1,
                ReleaseStatus::Rejected => rejected += 1,
                _ => {} // Deleted etc.
            }
        }
        (pending, approved, rejected)
    };

    Ok(Json(ModerationStatsResponse {
        pending,
        approved,
        rejected,
        total: pending + approved + rejected,
    }))
}

// --- Category endpoints ---

async fn list_categories(State(state): State<AppState>) -> Result<Json<Vec<Category>>, StatusCode> {
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
    if !state_read
        .storage
        .is_admin(&req.public_key)
        .unwrap_or(false)
    {
        return Ok(Json(serde_json::json!({
            "error": "Admin permission required to create categories"
        })));
    }
    drop(state_read);

    // Use categoryId or id
    let id = match req.category_id.or(req.id) {
        Some(id) => id,
        None => {
            return Ok(Json(serde_json::json!({
                "error": "Category ID is required"
            })))
        }
    };
    // Use displayName or name
    let name = match req.display_name.or(req.name) {
        Some(name) => name,
        None => {
            return Ok(Json(serde_json::json!({
                "error": "Category name is required"
            })))
        }
    };

    let category =
        Category::with_schema(id, name, req.featured.unwrap_or(false), req.metadata_schema);

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
    if !state_write
        .storage
        .is_admin(&req.public_key)
        .unwrap_or(false)
    {
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
        None => {
            return Ok(Json(serde_json::json!({
                "error": "Category not found"
            })))
        }
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

/// List all featured releases (returns all, client filters by time)
async fn list_featured_releases(
    State(state): State<AppState>,
) -> Result<Json<Vec<FeaturedRelease>>, StatusCode> {
    let state = state.read().await;

    // List featured releases from DocumentStore (CRDT-based sync)
    let doc_store = state.doc_store.read().await;
    let featured = doc_store.list::<FeaturedRelease>().map_err(|e| {
        tracing::error!("DocumentStore list failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tracing::debug!(
        "Listed {} featured releases from DocumentStore",
        featured.len()
    );
    Ok(Json(featured))
}

/// Get a single featured release by ID
async fn get_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FeaturedRelease>, StatusCode> {
    let state = state.read().await;

    let doc_store = state.doc_store.read().await;
    // ContentId is computed from the string ID (same as FeaturedRelease::content_id)
    let content_id = ContentId::hash(id.as_bytes());
    doc_store
        .get::<FeaturedRelease>(&content_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Request body for creating/updating a featured release
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FeaturedReleaseRequest {
    release_id: String,
    start_time: String,
    end_time: String,
    #[serde(default)]
    promoted: bool,
    #[serde(default = "default_priority")]
    priority: u32,
    #[serde(default)]
    order: u32,
    custom_title: Option<String>,
    custom_description: Option<String>,
    custom_thumbnail: Option<String>,
    #[serde(default)]
    regions: Vec<String>,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    variant: Option<String>,
    metadata: Option<serde_json::Value>,
}

fn default_priority() -> u32 {
    500
}

/// Create a new featured release (admin only)
async fn create_featured_release(
    State(state): State<AppState>,
    Json(req): Json<FeaturedReleaseRequest>,
) -> Result<(StatusCode, Json<FeaturedRelease>), StatusCode> {
    // Verify the release exists
    {
        let state = state.read().await;
        let doc_store = state.doc_store.read().await;
        let content_id = citadel_crdt::ContentId::hash(req.release_id.as_bytes());
        let release_exists = doc_store
            .get::<Release>(&content_id)
            .ok()
            .flatten()
            .is_some();
        if !release_exists {
            return Err(StatusCode::BAD_REQUEST); // Release doesn't exist
        }
    }

    let id = FeaturedRelease::generate_id();
    let mut featured = FeaturedRelease::new(id, req.release_id, req.start_time, req.end_time);

    // Apply optional fields
    featured.promoted = req.promoted;
    featured.priority = req.priority;
    featured.order = req.order;
    featured.custom_title = req.custom_title;
    featured.custom_description = req.custom_description;
    featured.custom_thumbnail = req.custom_thumbnail;
    featured.regions = req.regions;
    featured.languages = req.languages;
    featured.tags = req.tags;
    featured.variant = req.variant;
    featured.metadata = req.metadata;

    let state = state.read().await;

    // Save to DocumentStore (CRDT-based sync with rich semantic merges)
    tracing::info!("Creating featured release in DocumentStore");
    {
        let mut doc_store = state.doc_store.write().await;
        doc_store.put(&featured).map_err(|e| {
            tracing::error!("DocumentStore put failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }
    tracing::info!("Featured release created successfully: {}", featured.id);

    // SPORE: Flood featured releases so they propagate across the mesh
    if let Some(ref flood_tx) = state.flood_tx {
        let doc_store = state.doc_store.read().await;
        if let Ok(all_featured) = doc_store.list::<FeaturedRelease>() {
            let featured_json: Vec<String> = all_featured
                .iter()
                .filter_map(|f| serde_json::to_string(f).ok())
                .collect();
            let _ = flood_tx.send(FloodMessage::FeaturedSync {
                peer_id: "api".to_string(),
                featured: featured_json,
            });
            tracing::debug!("SPORE: Broadcast FeaturedSync after creating featured release");
        }
    }

    Ok((StatusCode::CREATED, Json(featured)))
}

/// Update an existing featured release (admin only)
///
/// With DocumentStore (CRDT), updates are merged using rich semantic merges:
/// - Counters: max(old, new)
/// - Sets (regions, languages, tags): union(old, new)
/// - Booleans (promoted): or(old, new)
/// - Time windows: (min(start), max(end))
async fn update_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FeaturedReleaseRequest>,
) -> Result<Json<FeaturedRelease>, StatusCode> {
    let state = state.read().await;
    let content_id = ContentId::hash(id.as_bytes());

    // Get existing to verify it exists
    {
        let doc_store = state.doc_store.read().await;
        if doc_store
            .get::<FeaturedRelease>(&content_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .is_none()
        {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    // Verify the release exists
    {
        let doc_store = state.doc_store.read().await;
        let release_content_id = citadel_crdt::ContentId::hash(req.release_id.as_bytes());
        let release_exists = doc_store
            .get::<Release>(&release_content_id)
            .ok()
            .flatten()
            .is_some();
        if !release_exists {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Create updated featured release with the same ID
    let mut featured =
        FeaturedRelease::new(id.clone(), req.release_id, req.start_time, req.end_time);
    featured.promoted = req.promoted;
    featured.priority = req.priority;
    featured.order = req.order;
    featured.custom_title = req.custom_title;
    featured.custom_description = req.custom_description;
    featured.custom_thumbnail = req.custom_thumbnail;
    featured.regions = req.regions;
    featured.languages = req.languages;
    featured.tags = req.tags;
    featured.variant = req.variant;
    featured.metadata = req.metadata;

    // Put will automatically merge with existing using TotalMerge
    let merged = {
        let mut doc_store = state.doc_store.write().await;
        doc_store
            .put(&featured)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Return the merged result
        doc_store
            .get::<FeaturedRelease>(&content_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    };

    // SPORE: Flood featured releases so they propagate across the mesh
    if let Some(ref flood_tx) = state.flood_tx {
        let doc_store = state.doc_store.read().await;
        if let Ok(all_featured) = doc_store.list::<FeaturedRelease>() {
            let featured_json: Vec<String> = all_featured
                .iter()
                .filter_map(|f| serde_json::to_string(f).ok())
                .collect();
            let _ = flood_tx.send(FloodMessage::FeaturedSync {
                peer_id: "api".to_string(),
                featured: featured_json,
            });
            tracing::debug!("SPORE: Broadcast FeaturedSync after updating featured release");
        }
    }

    Ok(Json(merged))
}

/// Delete a featured release (admin only)
///
/// Note: In CRDT context, deletion creates a tombstone for sync.
async fn delete_featured_release(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    let state = state.read().await;
    let content_id = ContentId::hash(id.as_bytes());

    // Check if exists, then delete from DocumentStore
    {
        let doc_store_read = state.doc_store.read().await;
        match doc_store_read.get::<FeaturedRelease>(&content_id) {
            Ok(Some(_)) => {
                drop(doc_store_read); // Release read lock before write
                let mut doc_store_write = state.doc_store.write().await;
                if doc_store_write
                    .delete::<FeaturedRelease>(&content_id)
                    .is_ok()
                {
                    // SPORE: Flood updated featured releases so deletion propagates
                    if let Some(ref flood_tx) = state.flood_tx {
                        if let Ok(all_featured) = doc_store_write.list::<FeaturedRelease>() {
                            let featured_json: Vec<String> = all_featured
                                .iter()
                                .filter_map(|f| serde_json::to_string(f).ok())
                                .collect();
                            let _ = flood_tx.send(FloodMessage::FeaturedSync {
                                peer_id: "api".to_string(),
                                featured: featured_json,
                            });
                            tracing::debug!(
                                "SPORE: Broadcast FeaturedSync after deleting featured release"
                            );
                        }
                    }
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
            Ok(None) => StatusCode::NOT_FOUND,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSiteRequest {
    name: Option<String>,
    description: Option<String>,
    logo: Option<String>,
    url: Option<String>,
    renderer_mode: Option<RendererMode>,
    live_preview_url: Option<String>,
    theme: Option<serde_json::Value>,
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
        let has_upload = state
            .storage
            .has_permission(&public_key, "upload")
            .unwrap_or(false);
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

async fn get_site(State(state): State<AppState>) -> Result<Json<SiteManifest>, StatusCode> {
    let state = state.read().await;
    let address = node_public_key(&state.storage).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let manifest = state
        .storage
        .ensure_site_manifest(&address)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(manifest))
}

async fn update_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SiteManifest>, (StatusCode, Json<serde_json::Value>)> {
    let (public_key, signature, timestamp) = signed_headers(&headers)?;

    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": e })),
            ));
        }
    }

    let req: UpdateSiteRequest = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })),
        )
    })?;

    let state = state.read().await;
    let address = node_public_key(&state.storage).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
    })?;
    let mut manifest = state.storage.ensure_site_manifest(&address).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to load site manifest: {}", e)
            })),
        )
    })?;

    if let Some(name) = req.name {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Site name cannot be empty" })),
            ));
        }
        manifest.name = trimmed.to_string();
    }

    if let Some(description) = req.description {
        let trimmed = description.trim();
        manifest.description = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(logo) = req.logo {
        let trimmed = logo.trim();
        manifest.logo = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(url) = req.url {
        let trimmed = url.trim();
        manifest.url = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if let Some(renderer_mode) = req.renderer_mode {
        manifest.renderer_mode = renderer_mode;
    }

    if let Some(live_preview_url) = req.live_preview_url {
        let trimmed = live_preview_url.trim();
        manifest.live_preview_url = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    if manifest.renderer_mode == RendererMode::Live && manifest.live_preview_url.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "livePreviewUrl is required when rendererMode is Live"
            })),
        ));
    }

    if let Some(theme) = req.theme {
        manifest.theme = Some(theme);
    }

    manifest.address = address.clone();
    manifest.id = address;
    manifest.touch();

    state.storage.put_site_manifest(&manifest).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to save site manifest: {}", e)
            })),
        )
    })?;

    Ok(Json(manifest))
}

/// Validate upload permission for nginx auth_request.
/// Returns 200 OK if signature is valid and pubkey has upload permission.
/// Returns 403 Forbidden otherwise.
///
/// Required headers (passed by nginx from original request):
/// - X-Pubkey: Public key in "ed25519p/{hex}" format
/// - X-Signature: Hex-encoded ed25519 signature over "{timestamp}:UPLOAD"
/// - X-Timestamp: Unix timestamp (seconds) when signature was created
///
/// The signature must be recent (within 5 minutes) to prevent replay attacks.
async fn validate_upload(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    // Get required headers
    let public_key = match headers.get("X-Pubkey").and_then(|v| v.to_str().ok()) {
        Some(key) => key,
        None => {
            tracing::debug!("validate_upload: Missing X-Pubkey header");
            return StatusCode::FORBIDDEN;
        }
    };

    let signature = match headers.get("X-Signature").and_then(|v| v.to_str().ok()) {
        Some(sig) => sig,
        None => {
            tracing::debug!("validate_upload: Missing X-Signature header");
            return StatusCode::FORBIDDEN;
        }
    };

    let timestamp = match headers.get("X-Timestamp").and_then(|v| v.to_str().ok()) {
        Some(ts) => ts,
        None => {
            tracing::debug!("validate_upload: Missing X-Timestamp header");
            return StatusCode::FORBIDDEN;
        }
    };

    // Verify timestamp is recent (within 24 hours) to prevent replay attacks
    // We use a longer window because jobs may be queued before execution
    let ts_secs: i64 = match timestamp.parse() {
        Ok(ts) => ts,
        Err(_) => {
            tracing::debug!("validate_upload: Invalid timestamp format");
            return StatusCode::FORBIDDEN;
        }
    };

    let now = chrono::Utc::now().timestamp();
    let age = (now - ts_secs).abs();
    if age > 86400 {
        // 24 hours - allows for queued jobs
        tracing::debug!(
            "validate_upload: Timestamp too old/future: {} (now: {}, age: {}s)",
            ts_secs,
            now,
            age
        );
        return StatusCode::FORBIDDEN;
    }

    // Verify signature over "{timestamp}:UPLOAD"
    let message = format!("{}:UPLOAD", timestamp);
    if let Err(e) = verify_signature(public_key, message.as_bytes(), signature) {
        tracing::debug!("validate_upload: Signature verification failed: {}", e);
        return StatusCode::FORBIDDEN;
    }

    let state = state.read().await;

    // Check if admin
    if state.storage.is_admin(public_key).unwrap_or(false) {
        tracing::debug!("validate_upload: {} is admin, allowed", public_key);
        return StatusCode::OK;
    }

    // Check if has upload permission
    if state
        .storage
        .has_permission(public_key, "upload")
        .unwrap_or(false)
    {
        tracing::debug!(
            "validate_upload: {} has upload permission, allowed",
            public_key
        );
        return StatusCode::OK;
    }

    tracing::debug!(
        "validate_upload: {} denied - no upload permission",
        public_key
    );
    StatusCode::FORBIDDEN
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
    connection_type: String,     // "neighbor" or "relay"
    latency_ms: Option<u32>,     // Most recent measurement
    latency_stats: LatencyStats, // Multi-window averages for hover display
    bidirectional: bool,
}

#[derive(Debug, Serialize)]
struct NetworkStats {
    total_peers: u32,
    server_nodes: u32,
    browser_peers: u32,
    mesh_edges: u32,
    available_slots: u32,
    filled_slots: u32,
    mesh_density: f64,
    relay_connections: u32,
    avg_latency_ms: Option<f64>,
}

async fn get_network_map(State(state): State<AppState>) -> Json<NetworkMap> {
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
        HexSlot {
            index: None,
            q: 0,
            r: 0,
            z: 0,
        }
    };

    let short_self_id = short_peer_id(&self_id);
    let self_node = PeerNode {
        id: short_self_id.clone(),
        label: short_self_id.clone(), // Use peer ID as label, not IP
        slot: slot.clone(),
        peer_type: "server".to_string(),
        last_heartbeat: 0, // We ARE ourselves - always fresh
        capabilities: vec![
            "storage".to_string(),
            "relay".to_string(),
            "api".to_string(),
        ],
        online: true,
    };

    // Query actual mesh state from mesh service
    let mut nodes = vec![self_node.clone()];
    let mut edges = Vec::new();

    const LIVE_TOPOLOGY_WINDOW_SECS: u64 = 60;

    if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;

        // Build a map of coordinates to node IDs for SPIRAL edge computation
        use citadel_topology::{HexCoord, Neighbors};
        let mut coord_to_node: HashMap<HexCoord, String> = HashMap::new();
        let mut full_to_short: HashMap<String, String> = HashMap::new();
        full_to_short.insert(mesh.self_id.clone(), short_self_id.clone());

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
                let elapsed = peer.last_seen.elapsed().as_secs();
                (elapsed <= LIVE_TOPOLOGY_WINDOW_SECS, elapsed)
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

            full_to_short.insert(claim.peer_id.clone(), short_id.clone());
            coord_to_node.insert(claim.coord, short_id);
        }

        // Second pass: include live peers that have not claimed a slot yet.
        for (peer_id, peer) in &mesh.peers {
            let elapsed = peer.last_seen.elapsed().as_secs();
            if elapsed > LIVE_TOPOLOGY_WINDOW_SECS {
                continue;
            }

            let short_id = short_peer_id(peer_id);

            if short_id == short_self_id || nodes.iter().any(|node| node.id == short_id) {
                continue;
            }

            nodes.push(PeerNode {
                id: short_id.clone(),
                label: short_id.clone(),
                slot: HexSlot {
                    index: None,
                    q: 0,
                    r: 0,
                    z: 0,
                },
                peer_type: "server".to_string(),
                last_heartbeat: elapsed,
                capabilities: vec!["storage".to_string(), "relay".to_string()],
                online: true,
            });

            full_to_short.insert(peer_id.clone(), short_id);
        }

        // Third pass: draw live transport edges for peers we are actively talking to,
        // even before SPIRAL slot occupancy settles.
        let mut seen_edges: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for (peer_id, peer) in &mesh.peers {
            let elapsed = peer.last_seen.elapsed().as_secs();
            if elapsed > LIVE_TOPOLOGY_WINDOW_SECS {
                continue;
            }

            let Some(peer_short_id) = full_to_short.get(peer_id).cloned() else {
                continue;
            };

            let (from, to) = if short_self_id < peer_short_id {
                (short_self_id.clone(), peer_short_id.clone())
            } else {
                (peer_short_id.clone(), short_self_id.clone())
            };

            if seen_edges.contains(&(from.clone(), to.clone())) {
                continue;
            }
            seen_edges.insert((from.clone(), to.clone()));

            let latency_stats = mesh
                .latency_history
                .get(&mesh.self_id)
                .and_then(|history| history.get(peer_id))
                .map(|h| h.compute_stats())
                .unwrap_or_default();
            let latency_ms = latency_stats.last_1s_ms.map(|v| v as u32);

            edges.push(PeerEdge {
                from,
                to,
                connection_type: "transport".to_string(),
                latency_ms,
                latency_stats,
                bidirectional: true,
            });
        }

        // Fourth pass: compute SPIRAL edges based on actual hex neighbor topology
        // For each node, check which of its 20 theoretical neighbors exist in the mesh
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
                        let latency_stats = mesh
                            .latency_history
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

    let available_slots = if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        mesh.available_slot_count() as u32
    } else {
        0
    };
    let filled_slots = nodes
        .iter()
        .filter(|node| node.slot.index.is_some())
        .count() as u32;
    let stats = NetworkStats {
        total_peers: nodes.len() as u32,
        server_nodes: nodes.iter().filter(|n| n.peer_type == "server").count() as u32,
        browser_peers: nodes.iter().filter(|n| n.peer_type == "browser").count() as u32,
        mesh_edges: edges.len() as u32,
        available_slots,
        filled_slots,
        mesh_density: if available_slots == 0 {
            0.0
        } else {
            (filled_slots as f64 / available_slots as f64) * 100.0
        },
        relay_connections: edges
            .iter()
            .filter(|edge| edge.connection_type == "relay")
            .count() as u32,
        avg_latency_ms: if edges.is_empty() {
            None
        } else {
            let latencies: Vec<u32> = edges.iter().filter_map(|e| e.latency_ms).collect();
            if latencies.is_empty() {
                None
            } else {
                Some(latencies.iter().sum::<u32>() as f64 / latencies.len() as f64)
            }
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
    connected: bool,
    transport: &'static str,
    coordinated: bool,
    last_seen_ms: u64,
}

async fn get_mesh_state(State(state): State<AppState>) -> Json<MeshStateResponse> {
    let state = state.read().await;
    const LIVE_PEER_WINDOW_MS: u64 = 60_000;

    let (self_id, our_slot, peer_count, slot_claims, peers) =
        if let Some(ref mesh_state) = state.mesh_state {
            let mesh = mesh_state.read().await;

            let our_slot = mesh.self_slot.as_ref().map(|s| SlotInfo {
                index: s.index,
                peer_id: short_peer_id(&mesh.self_id),
                coord: CoordInfo {
                    q: s.coord.q,
                    r: s.coord.r,
                    z: s.coord.z,
                },
            });

            let slot_claims: Vec<SlotInfo> = mesh
                .claimed_slots
                .iter()
                .map(|(idx, claim)| SlotInfo {
                    index: *idx,
                    peer_id: short_peer_id(&claim.peer_id),
                    coord: CoordInfo {
                        q: claim.coord.q,
                        r: claim.coord.r,
                        z: claim.coord.z,
                    },
                })
                .collect();

            let peers: Vec<PeerSummary> = mesh
                .peers
                .iter()
                .map(|(id, peer)| {
                    let last_seen_ms = peer.last_seen.elapsed().as_millis() as u64;
                    let connected = last_seen_ms <= LIVE_PEER_WINDOW_MS;
                    let transport = if peer.yggdrasil_addr.is_some()
                        || peer
                            .ygg_peer_uri
                            .as_deref()
                            .is_some_and(|uri| uri.starts_with("tls://["))
                    {
                        "ygg"
                    } else {
                        "tcp"
                    };

                    PeerSummary {
                        id: short_peer_id(id),
                        addr: peer.addr.to_string(),
                        slot: peer.slot.as_ref().map(|s| s.index),
                        connected,
                        transport,
                        // Back-compat for current /p2p UI: treat live mesh presence as connected.
                        coordinated: connected,
                        last_seen_ms,
                    }
                })
                .collect();

            let peer_count = peers.iter().filter(|peer| peer.connected).count();

            (
                mesh.self_id.clone(),
                our_slot,
                peer_count,
                slot_claims,
                peers,
            )
        } else {
            (String::new(), None, 0, Vec::new(), Vec::new())
        };

    Json(MeshStateResponse {
        self_id: short_peer_id(&self_id),
        our_slot,
        peer_count,
        slot_claims,
        peers,
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
    /// Featured releases (optional for backwards compatibility)
    #[serde(default)]
    featured_releases: Vec<FeaturedRelease>,
}

/// Legacy release format from Lens SDK v1
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyRelease {
    id: String,
    /// Can be either a string ("ed25519p/...") or legacy byte array object
    #[serde(deserialize_with = "deserialize_posted_by")]
    posted_by: Option<String>,
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

/// Custom deserializer for posted_by that handles both string and legacy object formats
fn deserialize_posted_by<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;

    match value {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            // Already a string like "ed25519p/..."
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        Some(serde_json::Value::Object(obj)) => {
            // Legacy format: { "publicKey": { "0": 123, "1": 45, ... } }
            if let Some(public_key_val) = obj.get("publicKey").or(obj.get("public_key")) {
                if let Some(key_map) = public_key_val.as_object() {
                    let mut bytes = Vec::new();
                    for i in 0..32 {
                        if let Some(byte_val) = key_map.get(&i.to_string()) {
                            if let Some(byte) = byte_val.as_u64() {
                                bytes.push(byte as u8);
                            }
                        }
                    }
                    if bytes.len() == 32 {
                        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        return Ok(Some(format!("ed25519p/{}", hex)));
                    }
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Export data format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportData {
    version: String,
    export_date: String,
    releases: Vec<Release>,
    featured_releases: Vec<FeaturedRelease>,
}

/// Import response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResponse {
    success: bool,
    imported: usize,
    skipped: usize,
    featured_imported: usize,
    featured_skipped: usize,
    errors: Vec<String>,
}

/// POST /api/v1/import - Import releases from legacy format
/// Requires admin signature authentication via X-Public-Key, X-Signature, X-Timestamp headers
async fn import_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ImportResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract authentication headers
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Public-Key header"
                })),
            )
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Signature header"
                })),
            )
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "Missing X-Timestamp header"
                })),
            )
        })?;

    // Verify signature and admin status
    {
        let state = state.read().await;
        if let Err(e) =
            require_admin_signature(&state.storage, public_key, signature, timestamp, &body)
        {
            tracing::warn!("Auth failed for import_releases: {}", e);
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": e
                })),
            ));
        }
    }

    // Parse the import data (body is the legacy export JSON directly)
    let legacy_export: LegacyExport = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Failed to parse import data: {}", e)
            })),
        )
    })?;

    let state = state.read().await;

    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    tracing::info!(
        "Importing {} releases from legacy format v{}",
        legacy_export.releases.len(),
        legacy_export.version
    );

    let doc_store = &state.doc_store;

    for legacy_release in legacy_export.releases {
        // Check if release already exists in doc_store
        let content_id = citadel_crdt::ContentId::hash(legacy_release.id.as_bytes());
        {
            let doc_store_read = doc_store.read().await;
            if doc_store_read
                .get::<Release>(&content_id)
                .ok()
                .flatten()
                .is_some()
            {
                tracing::debug!("Skipping existing release: {}", legacy_release.id);
                skipped += 1;
                continue;
            }
        }

        // Use posted_by directly (already converted by deserializer)
        let creator = legacy_release.posted_by.clone();

        let mut release = Release::new(
            legacy_release.id.clone(),
            legacy_release.name,
            legacy_release
                .category_slug
                .unwrap_or(legacy_release.category_id),
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

        // Save release to doc_store
        {
            let mut doc_store_write = doc_store.write().await;
            if let Err(e) = doc_store_write.put(&release) {
                errors.push(format!(
                    "Failed to save release {}: {:?}",
                    legacy_release.id, e
                ));
                continue;
            }
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

    tracing::info!(
        "Releases import complete: {} imported, {} skipped",
        imported,
        skipped
    );

    // Import featured releases if present
    let mut featured_imported = 0;
    let mut featured_skipped = 0;
    for featured in legacy_export.featured_releases {
        // Check if featured release already exists in doc_store
        let content_id = citadel_crdt::ContentId::hash(featured.id.as_bytes());
        {
            let doc_store_read = doc_store.read().await;
            if doc_store_read
                .get::<FeaturedRelease>(&content_id)
                .ok()
                .flatten()
                .is_some()
            {
                tracing::debug!("Skipping existing featured release: {}", featured.id);
                featured_skipped += 1;
                continue;
            }
        }

        // Save featured release to doc_store
        {
            let mut doc_store_write = doc_store.write().await;
            if let Err(e) = doc_store_write.put(&featured) {
                errors.push(format!(
                    "Failed to save featured release {}: {:?}",
                    featured.id, e
                ));
                continue;
            }
        }

        featured_imported += 1;
    }

    if featured_imported > 0 || featured_skipped > 0 {
        tracing::info!(
            "Featured releases import: {} imported, {} skipped",
            featured_imported,
            featured_skipped
        );
    }

    // SPORE: Flood imported featured releases so they propagate across mesh
    if featured_imported > 0 {
        if let Some(ref flood_tx) = state.flood_tx {
            let doc_store_read = doc_store.read().await;
            if let Ok(all_featured) = doc_store_read.list::<FeaturedRelease>() {
                let featured_json: Vec<String> = all_featured
                    .iter()
                    .filter_map(|f| serde_json::to_string(f).ok())
                    .collect();
                let _ = flood_tx.send(FloodMessage::FeaturedSync {
                    peer_id: "api-import".to_string(),
                    featured: featured_json,
                });
                tracing::info!(
                    "SPORE: Flooding {} featured releases after import",
                    all_featured.len()
                );
            }
        }
    }

    // SPORE: Broadcast our updated ContentHaveList so peers know our complete state
    if imported > 0 {
        if let Some(ref flood_tx) = state.flood_tx {
            let doc_store_read = doc_store.read().await;
            if let Ok(all_releases) = doc_store_read.list::<Release>() {
                let release_ids: Vec<String> = all_releases.iter().map(|r| r.id.clone()).collect();
                let _ = flood_tx.send(FloodMessage::ContentHaveList {
                    peer_id: "api-import".to_string(), // API doesn't have mesh identity
                    release_ids,
                });
                tracing::info!(
                    "SPORE: Broadcast ContentHaveList with {} releases after import",
                    all_releases.len()
                );
            }
        }
    }

    Ok(Json(ImportResponse {
        success: errors.is_empty(),
        imported,
        skipped,
        featured_imported,
        featured_skipped,
        errors,
    }))
}

/// GET /api/v1/export - Export all releases and featured releases
async fn export_releases(State(state): State<AppState>) -> Result<Json<ExportData>, StatusCode> {
    let state = state.read().await;

    let doc_store = state.doc_store.read().await;
    let releases = doc_store
        .list::<Release>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let featured_releases = doc_store
        .list::<FeaturedRelease>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        "Exporting {} releases and {} featured releases",
        releases.len(),
        featured_releases.len()
    );

    Ok(Json(ExportData {
        version: "2.0".to_string(),
        export_date: chrono::Utc::now().to_rfc3339(),
        releases,
        featured_releases,
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

    // Delete all releases from DocumentStore
    let mut doc_store = state.doc_store.write().await;
    let releases = match doc_store.list::<Release>() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to list releases for deletion: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let count = releases.len();
    for release in &releases {
        let content_id = citadel_crdt::ContentId::hash(release.id.as_bytes());
        if let Err(e) = doc_store.delete::<Release>(&content_id) {
            tracing::warn!("Failed to delete release {}: {:?}", release.id, e);
        }
    }
    tracing::warn!("Deleted {} releases by admin {}", count, req.public_key);
    Ok(Json(serde_json::json!({
        "success": true,
        "deleted": count
    })))
}

// ============================================================================
// ADMIN HTTP API (for lens-admin CLI with --url)
// ============================================================================

/// Admin API response format (matches socket responses)
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum AdminApiResponse {
    Ok { message: String },
    Error { error: String },
    List { items: Vec<String> },
    Bool { value: bool },
    Pong,
    Profile { data: serde_json::Value },
}

/// Request body for add/remove admin
#[derive(Debug, Deserialize)]
struct AdminKeyRequest {
    public_key: String,
}

/// Helper to verify admin auth from headers
fn verify_admin_auth(
    headers: &HeaderMap,
    storage: &crate::storage::Storage,
) -> Result<String, AdminApiResponse> {
    let pubkey = headers
        .get("X-Pubkey")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AdminApiResponse::Error {
            error: "Missing X-Pubkey header".to_string(),
        })?;

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AdminApiResponse::Error {
            error: "Missing X-Timestamp header".to_string(),
        })?;

    let signature = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AdminApiResponse::Error {
            error: "Missing X-Signature header".to_string(),
        })?;

    // Verify signature (CLI signs "{timestamp}:UPLOAD" for admin commands)
    let message = format!("{}:UPLOAD", timestamp);
    verify_signature(pubkey, message.as_bytes(), signature)
        .map_err(|e| AdminApiResponse::Error { error: e })?;

    // Check admin status
    if !storage.is_admin(pubkey).unwrap_or(false) {
        return Err(AdminApiResponse::Error {
            error: format!("Public key {} is not an admin", pubkey),
        });
    }

    Ok(pubkey.to_string())
}

/// POST /api/admin/ping
async fn admin_ping(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;
    Ok(Json(AdminApiResponse::Pong))
}

/// POST /api/admin/add-admin
async fn admin_add_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminKeyRequest>,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.set_admin(&req.public_key, true) {
        Ok(()) => {
            tracing::info!("Added admin: {}", req.public_key);
            Ok(Json(AdminApiResponse::Ok {
                message: format!("Added admin: {}", req.public_key),
            }))
        }
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/remove-admin
async fn admin_remove_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminKeyRequest>,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.set_admin(&req.public_key, false) {
        Ok(()) => {
            tracing::info!("Removed admin: {}", req.public_key);
            Ok(Json(AdminApiResponse::Ok {
                message: format!("Removed admin: {}", req.public_key),
            }))
        }
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/grant-upload
async fn admin_grant_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminKeyRequest>,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.grant_permission(&req.public_key, "upload") {
        Ok(()) => {
            tracing::info!("Granted upload to: {}", req.public_key);
            Ok(Json(AdminApiResponse::Ok {
                message: format!("Granted upload permission to: {}", req.public_key),
            }))
        }
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/revoke-upload
async fn admin_revoke_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminKeyRequest>,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.revoke_permission(&req.public_key, "upload") {
        Ok(()) => {
            tracing::info!("Revoked upload from: {}", req.public_key);
            Ok(Json(AdminApiResponse::Ok {
                message: format!("Revoked upload permission from: {}", req.public_key),
            }))
        }
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/list-admins
async fn admin_list_admins(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.list_admins() {
        Ok(admins) => Ok(Json(AdminApiResponse::List { items: admins })),
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/is-admin
async fn admin_is_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminKeyRequest>,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    match state.storage.is_admin(&req.public_key) {
        Ok(is_admin) => Ok(Json(AdminApiResponse::Bool { value: is_admin })),
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/start-profiling
async fn admin_start_profiling(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    tracing::info!("Profiling mode enabled via HTTP");
    Ok(Json(AdminApiResponse::Ok {
        message: "Profiling enabled. cpu-profile will auto-collect when called.".to_string(),
    }))
}

/// POST /api/admin/stop-profiling
async fn admin_stop_profiling(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    tracing::info!("Profiling stopped via HTTP");
    Ok(Json(AdminApiResponse::Ok {
        message: "Profiling stopped.".to_string(),
    }))
}

/// POST /api/admin/cpu-profile
async fn admin_cpu_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    tracing::info!("CPU profiling: collecting for 5 seconds via HTTP...");

    // Run profiling in a blocking task since it uses std::thread::sleep
    let profile_result = tokio::task::spawn_blocking(|| admin_socket::collect_cpu_profile(5))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AdminApiResponse::Error {
                    error: format!("Task join error: {}", e),
                }),
            )
        })?;

    match profile_result {
        Ok(data) => Ok(Json(AdminApiResponse::Profile { data })),
        Err(e) => Ok(Json(AdminApiResponse::Error {
            error: e.to_string(),
        })),
    }
}

/// POST /api/admin/mem-profile
async fn admin_mem_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    let mem_data = admin_socket::get_memory_stats();
    Ok(Json(AdminApiResponse::Profile { data: mem_data }))
}

/// POST /api/admin/mesh-stats
async fn admin_mesh_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminApiResponse>, (StatusCode, Json<AdminApiResponse>)> {
    let state = state.read().await;
    verify_admin_auth(&headers, &state.storage).map_err(|e| (StatusCode::UNAUTHORIZED, Json(e)))?;

    // Get mesh state if available
    if let Some(ref mesh_state) = state.mesh_state {
        let mesh = mesh_state.read().await;
        let (synced, total) = mesh.sync_status();
        let ready = mesh.is_content_ready();

        let stats = serde_json::json!({
            "synced_peers": synced,
            "total_peers": total,
            "content_ready": ready,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        Ok(Json(AdminApiResponse::Profile { data: stats }))
    } else {
        Ok(Json(AdminApiResponse::Error {
            error: "Mesh state not available (standalone mode)".to_string(),
        }))
    }
}
